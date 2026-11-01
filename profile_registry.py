#!/usr/bin/env python3
"""Exact build profiles for the local PHP2Shell challenge recreations.

Selection is deliberately fail-closed. Heap geometry is tied to an exact PHP,
WordPress, SAPI, and INI fingerprint; a same-branch or nearest-version fallback
would turn a fingerprint mismatch into memory corruption against an unknown
layout.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent
Support = Literal["verified", "calibrating"]
Sapi = Literal["fpm", "apache2handler"]

CHALLENGE_RANDOMIZATION = {
    "reported_php_families": ["7.x", "8.x"],
    "exact_build_list_published": False,
    "source": "https://x.com/brokenpacifist/status/2114361269369385145",
    "policy": (
        "an affected version range is not an exploit profile; execution requires "
        "one exact verified SAPI/PHP/WordPress/INI/architecture fingerprint"
    ),
}

VULNERABLE_PHP_RANGES = (
    {"branch": "7.0-7.3", "vulnerable": "all releases", "fixed": "none"},
    {"branch": "7.4", "vulnerable": "all releases", "fixed": "source backport only"},
    {"branch": "8.0", "vulnerable": "all releases", "fixed": "source backport only"},
    {"branch": "8.1", "vulnerable": "all releases", "fixed": "source backport only"},
    {"branch": "8.2", "vulnerable": "8.2.0-8.2.34", "fixed": "8.2.35"},
    {"branch": "8.3", "vulnerable": "8.3.0-8.3.35", "fixed": "8.3.36"},
    {"branch": "8.4", "vulnerable": "8.4.0-8.4.26", "fixed": "8.4.27"},
    {"branch": "8.5", "vulnerable": "8.5.0-8.5.11", "fixed": "8.5.12"},
)


@dataclass(frozen=True)
class Fingerprint:
    sapi: Sapi
    php: str
    wordpress: str
    ini: str
    arch: str = "amd64"


@dataclass(frozen=True)
class Profile:
    name: str
    fingerprint: Fingerprint
    support: Support
    stack: str
    lab: Path
    solver: Path | None
    container: str
    default_port: int
    title: str
    flag: str
    sid_prefix: str | None = None
    response_pattern: str | None = None
    attempts: int = 1
    extra_solver_args: tuple[str, ...] = ()
    blocker: str | None = None
    workers: int = 1

    @property
    def verified(self) -> bool:
        return self.support == "verified"

    def runner_dict(self, *, attempts: int | None = None) -> dict[str, object]:
        if not self.verified or self.solver is None:
            detail = f": {self.blocker}" if self.blocker else ""
            raise UnsupportedProfile(f"profile {self.name!r} is not executable{detail}")
        result: dict[str, object] = {
            "name": self.name,
            "lab": self.lab,
            "solver": self.solver,
            "container": self.container,
            "title": self.title,
            "stack": self.stack,
            "flag": self.flag,
            "extra_solver_args": list(self.extra_solver_args),
            "attempts": self.attempts if attempts is None else attempts,
            "sapi": self.fingerprint.sapi,
            "workers": self.workers,
        }
        if self.fingerprint.sapi == "fpm":
            result.update(
                sid_prefix=self.sid_prefix,
                response_pattern=self.response_pattern,
            )
        return result


class UnsupportedProfile(RuntimeError):
    """The observed target has no exact, verified exploit geometry."""


PROFILES: tuple[Profile, ...] = (
    Profile(
        name="fpm82",
        fingerprint=Fingerprint("fpm", "8.2.34", "7.1.3", "128M|1|/tmp"),
        support="calibrating",
        stack="Nginx + PHP-FPM 8.2.34 + WordPress 7.1.3",
        lab=ROOT / "profiles" / "fpm82",
        solver=None,
        container="php2shell-fpm82",
        default_port=18232,
        title="HITCON-LAB-FPM82",
        flag="hitcon{local_fpm82_instance_do_not_submit}",
        blocker=(
            "the exact PHP 8.2 heap lineage keeps the next decoder store at "
            "BG.data+0x1598 while the reflected search buffers remain outside "
            "the reclaimed struct; bounded route, depth, field-count, pad, and "
            "allocation-size sweeps produced either an unchanged value or a worker crash"
        ),
    ),
    Profile(
        name="fpm83",
        fingerprint=Fingerprint("fpm", "8.3.35", "7.1.3", "128M|1|/tmp"),
        support="verified",
        stack="Nginx + PHP-FPM 8.3.35 + WordPress 7.1.3",
        lab=ROOT / "profiles" / "fpm83",
        solver=ROOT / "profiles" / "fpm83" / "solve.py",
        container="php2shell-fpm83",
        default_port=18234,
        title="HITCON-LAB-FPM83",
        flag="hitcon{local_fpm83_instance_do_not_submit}",
        sid_prefix="f83",
        response_pattern="r3.get.bin",
        attempts=3,
        extra_solver_args=("--accept-fixed-geometry",),
    ),
    Profile(
        name="fpm84",
        fingerprint=Fingerprint("fpm", "8.4.26", "6.9.10", "128M|1|/tmp"),
        support="verified",
        stack="Nginx + PHP-FPM 8.4.26 + WordPress 6.9.10",
        lab=ROOT / "profiles" / "fpm84",
        solver=ROOT / "profiles" / "fpm84" / "solve.py",
        container="php2shell-fpm84",
        default_port=18235,
        title="HITCON-LAB-FPM84",
        flag="hitcon{local_fpm84_instance_do_not_submit}",
        sid_prefix="f84",
        response_pattern="r3-*.get.bin",
        attempts=3,
        extra_solver_args=("--accept-fixed-geometry",),
    ),
    Profile(
        name="fpm85",
        fingerprint=Fingerprint("fpm", "8.5.11", "6.9.10", "128M|1|/tmp"),
        support="verified",
        stack="Nginx + PHP-FPM 8.5.11 + WordPress 6.9.10",
        lab=ROOT / "lab",
        solver=ROOT / "solve.py",
        container="php2shell-fpm85",
        default_port=18233,
        title="HITCON-LAB-FPM85",
        flag="hitcon{local_fpm85_instance_do_not_submit}",
        sid_prefix="f85",
        response_pattern="r3-*.get.bin",
        attempts=5,
    ),
    Profile(
        name="apache83",
        fingerprint=Fingerprint("apache2handler", "8.3.35", "7.1.3", "128M|1|"),
        support="verified",
        stack="Apache 2 prefork + mod_php 8.3.35 + WordPress 7.1.3",
        lab=ROOT / "profiles" / "apache83",
        solver=ROOT / "apache" / "solve.py",
        container="php2shell-apache83",
        default_port=18323,
        title="HITCON-LAB-APACHE83",
        flag="hitcon{local_apache83_instance_do_not_submit}",
        extra_solver_args=("--profile", "apache83"),
    ),
    Profile(
        name="apache84",
        fingerprint=Fingerprint("apache2handler", "8.4.26", "7.0.7", "128M|1|"),
        support="verified",
        stack="Apache 2 prefork + mod_php 8.4.26 + WordPress 7.0.7",
        lab=ROOT / "lab" / "apache",
        solver=ROOT / "apache" / "solve.py",
        container="php2shell-apache84",
        default_port=18322,
        title="HITCON-LAB-APACHE84",
        flag="hitcon{local_apache_instance_do_not_submit}",
        extra_solver_args=("--profile", "apache84"),
        attempts=3,
        workers=150,
    ),
    Profile(
        name="apache85",
        fingerprint=Fingerprint("apache2handler", "8.5.11", "7.1.3", "128M|1|"),
        support="verified",
        stack="Apache 2 prefork + mod_php 8.5.11 + WordPress 7.1.3",
        lab=ROOT / "profiles" / "apache85",
        solver=ROOT / "apache" / "solve.py",
        container="php2shell-apache85",
        default_port=18325,
        title="HITCON-LAB-APACHE85",
        flag="hitcon{local_apache85_instance_do_not_submit}",
        extra_solver_args=("--profile", "apache85"),
    ),
)


def profile_by_name(name: str, *, require_verified: bool = True) -> Profile:
    matches = [profile for profile in PROFILES if profile.name == name]
    if not matches:
        raise UnsupportedProfile(
            f"unknown profile {name!r}; known profiles: "
            + ", ".join(profile.name for profile in PROFILES)
        )
    profile = matches[0]
    if require_verified and not profile.verified:
        detail = f": {profile.blocker}" if profile.blocker else ""
        raise UnsupportedProfile(f"profile {name!r} is not verified{detail}")
    return profile


def select_profile(fingerprint: Fingerprint, *, require_verified: bool = True) -> Profile:
    matches = [profile for profile in PROFILES if profile.fingerprint == fingerprint]
    if len(matches) != 1:
        supported = ", ".join(
            f"{profile.name}={profile.fingerprint.php}/{profile.fingerprint.wordpress}/"
            f"{profile.fingerprint.sapi}/{profile.fingerprint.arch}"
            for profile in PROFILES
        )
        raise UnsupportedProfile(
            f"unsupported exact fingerprint {fingerprint}; supported fingerprints: {supported}"
        )
    profile = matches[0]
    if require_verified and not profile.verified:
        detail = f": {profile.blocker}" if profile.blocker else ""
        raise UnsupportedProfile(
            f"fingerprint matches {profile.name!r}, but that profile is not verified{detail}"
        )
    return profile


def support_matrix() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for profile in PROFILES:
        row = asdict(profile)
        row["lab"] = str(profile.lab.relative_to(ROOT))
        row["solver"] = None if profile.solver is None else str(profile.solver.relative_to(ROOT))
        row["extra_solver_args"] = list(profile.extra_solver_args)
        rows.append(row)
    return rows


def support_contract() -> dict[str, object]:
    verified = [profile.name for profile in PROFILES if profile.verified]
    calibrating = [profile.name for profile in PROFILES if not profile.verified]
    return {
        "challenge_randomization": CHALLENGE_RANDOMIZATION,
        "vulnerable_php_ranges": list(VULNERABLE_PHP_RANGES),
        "verified_profiles": verified,
        "calibrating_profiles": calibrating,
        "profiles": support_matrix(),
    }


def main() -> None:
    print(json.dumps(support_contract(), indent=2))


if __name__ == "__main__":
    main()
