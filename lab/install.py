#!/usr/bin/env python3

import argparse
import secrets
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def fetch(url, data=None):
    method = "POST" if data is not None else "GET"
    req = Request(url, data=data, method=method)
    with urlopen(req, timeout=20) as response:
        return response.status, response.read(1000000), response.geturl()


def wait_for_wordpress(origin):
    last_error = None
    for _ in range(60):
        try:
            return fetch(origin + "/wp-admin/install.php")
        except (HTTPError, URLError, TimeoutError, ConnectionError) as error:
            last_error = error
            time.sleep(1)
    raise RuntimeError(f"WordPress did not start: {last_error}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18233)
    parser.add_argument("--title", default="HITCON-LAB-FPM85")
    args = parser.parse_args()
    if not args.title or len(args.title) > 80:
        parser.error("title must be 1-80 characters")
    if not 1 <= args.port <= 65535:
        parser.error("bad port")

    origin = f"http://127.0.0.1:{args.port}"
    _, body, final_url = wait_for_wordpress(origin)
    installed = "wp-login.php" in final_url or b"Already Installed" in body

    if not installed:
        password = secrets.token_urlsafe(24)
        fields = {
            "weblog_title": args.title,
            "user_name": "lab_admin",
            "admin_password": password,
            "admin_password2": password,
            "admin_email": "lab@example.invalid",
            "blog_public": "0",
            "Submit": "Install WordPress",
            "language": "",
        }
        status, result, _ = fetch(
            origin + "/wp-admin/install.php?step=2",
            urlencode(fields).encode(),
        )
        if status != 200 or b"Success!" not in result:
            raise RuntimeError("WordPress install failed")
        print("[+] WordPress installed")
        print("[+] user: lab_admin")
        print(f"[+] disposable password: {password}")
    else:
        print("[*] WordPress is already installed")

    # These requests are part of the heap setup used by solve.py.
    for path in ("/", "/?rest_route=/wp/v2/block-patterns/patterns", "/"):
        try:
            status, response, final = fetch(origin + path)
            print(f"[*] prime {path}: {status}, {len(response)} bytes, {final}")
        except HTTPError as error:
            print(f"[*] prime {path}: HTTP {error.code}")


if __name__ == "__main__":
    main()
