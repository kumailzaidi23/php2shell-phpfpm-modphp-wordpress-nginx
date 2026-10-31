#!/usr/bin/env python3

import argparse
import asyncio
import json
import shlex
import subprocess


def container_ip(name, docker):
    raw = subprocess.check_output(
        [*docker, "inspect", "--format", "{{json .NetworkSettings.Networks}}", name],
        text=True,
    )
    networks = json.loads(raw)
    addresses = [item.get("IPAddress", "") for item in networks.values()]
    addresses = [address for address in addresses if address]
    if len(addresses) != 1:
        raise RuntimeError(f"expected one Docker address for {name}, found {addresses}")
    return addresses[0]


async def copy(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        if writer.can_write_eof():
            try:
                writer.write_eof()
            except ConnectionError:
                pass


async def client(reader, writer, remote_ip, remote_port):
    try:
        remote_reader, remote_writer = await asyncio.open_connection(remote_ip, remote_port)
        await asyncio.gather(copy(reader, remote_writer), copy(remote_reader, writer))
        remote_writer.close()
        try:
            await remote_writer.wait_closed()
        except ConnectionError:
            pass
    except OSError:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default="php2shell-apache")
    parser.add_argument("--listen-port", type=int, default=18322)
    parser.add_argument("--docker-command", default="docker")
    args = parser.parse_args()

    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("empty Docker command")
    remote_ip = container_ip(args.container, docker)
    server = await asyncio.start_server(
        lambda reader, writer: client(reader, writer, remote_ip, 80),
        "127.0.0.1",
        args.listen_port,
        backlog=256,
    )
    print(f"127.0.0.1:{args.listen_port} -> {remote_ip}:80", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
