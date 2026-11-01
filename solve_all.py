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
FPM85_LAB = ROOT / "lab"
FPM83_LAB = ROOT / "profiles" / "fpm83"
FPM84_LAB = ROOT / "profiles" / "fpm84"
APACHE_LAB = ROOT / "lab" / "apache"
FPM85_SOLVER = ROOT / "solve.py"
FPM83_SOLVER = ROOT / "profiles" / "fpm83" / "solve.py"
FPM84_SOLVER = ROOT / "profiles" / "fpm84" / "solve.py"
APACHE_SOLVER = ROOT / "apache" / "solve.py"
INSTALLER = ROOT / "lab" / "install.py"

FPM83_FLAG = "hitcon{local_fpm83_instance_do_not_submit}"
FPM84_FLAG = "hitcon{local_fpm84_instance_do_not_submit}"
FPM85_FLAG = "hitcon{local_fpm85_instance_do_not_submit}"
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


def windows_environment(env, *names):
    inherited = [item for item in env.get("WSLENV", "").split(":") if item]
    for name in names:
        if name not in inherited:
            inherited.append(name)
    env["WSLENV"] = ":".join(inherited)
    return env


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
    return windows_environment(
        env,
        "LAB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "DB_ROOT_PASSWORD",
        "LOCAL_FLAG",
    )


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
    return windows_environment(
        env,
        "APACHE_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "DB_ROOT_PASSWORD",
        "LOCAL_FLAG",
    )


def run_fpm_profile(docker, docker_text, profile, port, root, keep_lab):
    name = profile["name"]
    project = f"php2shell-{name}"
    env = fpm_environment(port, profile["flag"])
    attempts = profile.get("attempts", 1)

    for attempt in range(1, attempts + 1):
        output = root / name / f"attempt-{attempt:02d}"
        down(docker, project, profile["lab"], env)
        try:
            info(f"building {name} on port {port} for attempt {attempt}")
            compose(docker, project, profile["lab"], env, "up", "-d", "--build")
            run([
                sys.executable,
                INSTALLER,
                "--port", str(port),
                "--title", profile["title"],
            ], timeout=180)

            command = [
                sys.executable,
                profile["solver"],
                "--execute",
                "--restart-at-start",
                "--port", str(port),
                "--container", profile["container"],
                "--docker-command", docker_text,
                "--sid", fresh_sid(profile["sid_prefix"]),
                "--output-dir", output,
                "--expected-marker", profile["flag"],
                *profile.get("extra_solver_args", []),
            ]
            completed = run(command, timeout=1200, check=False)
            result_path = output / "result.json"
            if completed.returncode or not result_path.is_file():
                info(f"{name} attempt {attempt} missed")
                continue

            result = json.loads(result_path.read_text())
            responses = list(output.glob(profile["response_pattern"]))
            if not result.get("success") or len(responses) != 1:
                info(f"{name} attempt {attempt} left no unique GET proof")
                continue
            response = responses[0].read_bytes()
            if profile["flag"].encode() not in response:
                info(f"{name} attempt {attempt} response missed its dummy flag")
                continue

            good(f"{name}: {profile['flag']}")
            profile_result = {
                "profile": name,
                "stack": profile["stack"],
                "port": port,
                "attempt": attempt,
                "flag": profile["flag"],
                "B": result["B"],
                "r2a_p_offset": result["r2a_p_offset"],
                "r2b_p_offset": result["r2b_p_offset"],
                "r3_q_offset": result["r3_q_offset"],
                "fingerprint": result.get("fingerprint"),
                "result": str(result_path.resolve()),
            }
            for key in (
                "r2a_big_value_offset",
                "r2b_big_value_offset",
                "r3_big_value_offset",
            ):
                if key in result:
                    profile_result[key] = result[key]
            return profile_result
        finally:
            if not keep_lab:
                down(docker, project, profile["lab"], env)

    raise RuntimeError(f"{name} failed after {attempts} clean attempts")


def run_apache_instance(docker, port, flag, root, attempts, workers, keep_lab):
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

    down(docker, project, APACHE_LAB, env)
    try:
        info(f"building apache-wordpress on port {port}")
        compose(docker, project, APACHE_LAB, env, "up", "-d", "--build")


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
        if not keep_lab:
            down(docker, project, APACHE_LAB, env)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--docker-command", default=os.environ.get("PHP2SHELL_DOCKER_CMD", "docker")
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--fpm83-port", type=int, default=18234)
    parser.add_argument("--fpm84-port", type=int, default=18235)
    parser.add_argument("--fpm85-port", type=int, default=18233)
    parser.add_argument("--fpm83-attempts", type=int, default=3)
    parser.add_argument("--fpm84-attempts", type=int, default=3)
    parser.add_argument("--apache-port", type=int, default=18322)
    parser.add_argument("--apache-attempts", type=int, default=3)
    parser.add_argument("--apache-workers", type=int, default=150)
    parser.add_argument("--keep-labs", action="store_true")
    args = parser.parse_args()

    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("empty Docker command")
    if not 10_000 <= args.fpm83_port <= 65_535:
        parser.error("the FPM83 profile requires a five-digit loopback port")
    if args.fpm84_port != 18235:
        parser.error("the packaged FPM84 heap geometry is calibrated for port 18235")
    if args.fpm85_port != 18233:
        parser.error("the packaged FPM85 heap geometry is calibrated for port 18233")
    ports = [args.fpm83_port, args.fpm84_port, args.fpm85_port, args.apache_port]
    if (
        any(port < 1 or port > 65_535 for port in ports)
        or len(set(ports)) != len(ports)
    ):
        parser.error("all loopback ports must be valid and distinct")
    if args.fpm83_attempts < 1 or args.fpm83_attempts > 5:
        parser.error("FPM83 attempts must be between 1 and 5")
    if args.fpm84_attempts < 1 or args.fpm84_attempts > 5:
        parser.error("FPM84 attempts must be between 1 and 5")
    if args.apache_attempts < 1 or args.apache_attempts > 5:
        parser.error("Apache attempts must be between 1 and 5")
    if args.apache_workers < 1 or args.apache_workers > 150:
        parser.error("Apache workers must be between 1 and 150")

    fpm83 = {
        "name": "fpm83",
        "lab": FPM83_LAB,
        "solver": FPM83_SOLVER,
        "container": "php2shell-fpm83",
        "title": "HITCON-LAB-FPM83",
        "stack": "Nginx + PHP-FPM 8.3.35 + WordPress 7.1.3",
        "flag": FPM83_FLAG,
        "sid_prefix": "f83",
        "response_pattern": "r3.get.bin",
        "extra_solver_args": ["--accept-fixed-geometry"],
        "attempts": args.fpm83_attempts,
    }
    fpm84 = {
        "name": "fpm84",
        "lab": FPM84_LAB,
        "solver": FPM84_SOLVER,
        "container": "php2shell-fpm84",
        "title": "HITCON-LAB-FPM84",
        "stack": "Nginx + PHP-FPM 8.4.26 + WordPress 6.9.10",
        "flag": FPM84_FLAG,
        "sid_prefix": "f84",
        "response_pattern": "r3-*.get.bin",
        "extra_solver_args": ["--accept-fixed-geometry"],
        "attempts": args.fpm84_attempts,
    }
    fpm85 = {
        "name": "fpm85",
        "lab": FPM85_LAB,
        "solver": FPM85_SOLVER,
        "container": "php2shell-fpm85",
        "title": "HITCON-LAB-FPM85",
        "stack": "Nginx + PHP-FPM 8.5.11 + WordPress 6.9.10",
        "flag": FPM85_FLAG,
        "sid_prefix": "f85",
        "response_pattern": "r3-*.get.bin",
    }

    output = (args.output_dir or ROOT / "runs" / ("full-local-" + secrets.token_hex(4))).resolve()
    plan = {
        "mode": "full_local_challenge",
        "acceptance": "one clean flag read from each pinned FPM profile and one clean Apache flag copy",
        "profiles": [
            {
                "name": "fpm83",
                "port": args.fpm83_port,
                "flag": FPM83_FLAG,
                "attempts": args.fpm83_attempts,
            },
            {
                "name": "fpm84",
                "port": args.fpm84_port,
                "flag": FPM84_FLAG,
                "attempts": args.fpm84_attempts,
            },
            {"name": "fpm85", "port": args.fpm85_port, "flag": FPM85_FLAG},
            {"name": "apache-wordpress", "port": args.apache_port, "flag": APACHE_FLAG},
        ],
        "authentic_hitcon_artifacts": False,
        "live_requests": 0 if not args.execute else "bounded loopback only",
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
        first = run_fpm_profile(
            docker, args.docker_command, fpm83, args.fpm83_port, output, args.keep_labs
        )
        summary["profiles"].append(first)
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

        second = run_fpm_profile(
            docker, args.docker_command, fpm84, args.fpm84_port, output, args.keep_labs
        )
        summary["profiles"].append(second)
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

        third = run_fpm_profile(
            docker, args.docker_command, fpm85, args.fpm85_port, output, args.keep_labs
        )
        summary["profiles"].append(third)
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

        apache = run_apache_instance(
            docker, args.apache_port, APACHE_FLAG, output,
            args.apache_attempts, args.apache_workers, args.keep_labs,
        )
        summary["profiles"].append(apache)
        summary["success"] = True
        summary["flags"] = [profile["flag"] for profile in summary["profiles"]]
        summary["score"] = "4/4 local dummy flags across four pinned profiles"
        (output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    except Exception as error:
        summary["error"] = f"{type(error).__name__}: {error}"
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
