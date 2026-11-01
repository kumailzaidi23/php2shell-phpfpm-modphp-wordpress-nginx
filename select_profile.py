#!/usr/bin/env python3
"""Fingerprint a local challenge container and select exact exploit geometry."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from dataclasses import asdict
from typing import cast

from profile_registry import Fingerprint, Sapi, UnsupportedProfile, select_profile

ARCHES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


def checked(docker: list[str], *args: str) -> str:
    result = subprocess.run(
        [*docker, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        text=True,
    )
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join([*docker, *args])} failed: {message[:500]}")
    return result.stdout.strip()


def fingerprint_local(docker: list[str], container: str, sapi: str) -> Fingerprint:
    php = checked(docker, "exec", container, "php", "-r", "echo PHP_VERSION;")
    wordpress = checked(
        docker,
        "exec",
        container,
        "php",
        "-r",
        "include '/var/www/html/wp-includes/version.php'; echo $wp_version;",
    )
    ini = checked(
        docker,
        "exec",
        container,
        "php",
        "-r",
        "echo ini_get('memory_limit'),'|',ini_get('session.upload_progress.enabled'),'|',ini_get('session.save_path');",
    )
    machine = checked(docker, "exec", container, "uname", "-m").lower()
    arch = ARCHES.get(machine)
    if arch is None:
        raise RuntimeError(f"unsupported architecture fingerprint: {machine!r}")
    return Fingerprint(sapi=cast(Sapi, sapi), php=php, wordpress=wordpress, ini=ini, arch=arch)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--sapi", choices=("fpm", "apache2handler"), required=True)
    parser.add_argument("--docker-command", default="docker")
    parser.add_argument(
        "--include-calibrating",
        action="store_true",
        help="return a matching unverified profile instead of failing closed",
    )
    args = parser.parse_args()

    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("empty Docker command")

    fingerprint = fingerprint_local(docker, args.container, args.sapi)
    try:
        profile = select_profile(
            fingerprint,
            require_verified=not args.include_calibrating,
        )
    except UnsupportedProfile as error:
        print(
            json.dumps(
                {
                    "supported": False,
                    "fingerprint": asdict(fingerprint),
                    "error": str(error),
                },
                indent=2,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "supported": profile.verified,
                "profile": profile.name,
                "fingerprint": asdict(fingerprint),
                "solver": None if profile.solver is None else str(profile.solver),
                "support": profile.support,
                "blocker": profile.blocker,
            },
            indent=2,
        )
    )
    return 0 if profile.verified else 2


if __name__ == "__main__":
    raise SystemExit(main())
