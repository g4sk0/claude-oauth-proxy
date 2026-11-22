#!/usr/bin/env python3
"""End-to-end check that touches no network at all.

Starts the proxy in a background thread on a free loopback port, writes a
fake token record to a throwaway file, and verifies the parts that are easy
to get wrong: /healthz without a token, a login being picked up while the
proxy is already running, and test_request.py refusing to send anything
when there is no token.

Run:  python -I tests/offline_check.py
"""

from __future__ import annotations

import http.client
import json
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import claude_login as login  # noqa: E402
import claude_oauth_proxy as proxy  # noqa: E402
import test_request  # noqa: E402

results: list[tuple[str, bool]] = []


def check(name: str, ok: object, detail: str = "") -> None:
    results.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark}  {name}{('  -- ' + detail) if detail else ''}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get(base: str, path: str) -> tuple[int, dict]:
    with urllib.request.urlopen(f"{base}{path}", timeout=10) as response:  # noqa: S310
        return response.status, json.loads(response.read() or b"{}")


def raw(port: int, method: str, path: str,
        headers: dict | None = None, body: bytes | None = None) -> tuple[int, bytes]:
    """One request with headers exactly as given, Host included."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()[:400]
    finally:
        connection.close()


def main() -> int:
    check("proxy selftest", proxy.selftest() == 0)
    check("login selftest", login.selftest() == 0)

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    auth = Path(tempfile.mkdtemp()) / "auth.json"
    auth.write_text("{}", encoding="utf-8")

    proxy.Handler.store = proxy.TokenStore(auth)
    proxy.Handler.client_key = ""
    server = proxy.Server(("127.0.0.1", port), proxy.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.4)

    try:
        status, body = get(base, "/healthz")
        check("healthz answers 200 with no token", status == 200)
        check("token reported missing", body.get("token") == "missing", json.dumps(body))
        check("auth file path echoed", body.get("auth_file") == str(auth))
        check("version reported", bool(body.get("version")), str(body.get("version")))

        # Someone logs in while the proxy is already running: the token store
        # re-reads per request, so it must be picked up without a restart.
        auth.write_text(
            json.dumps({
                "openai": {"type": "oauth", "access": "other-provider-untouched"},
                "anthropic": {
                    "type": "oauth",
                    "provider": "anthropic",
                    "access": "fake-access-not-a-real-token",
                    "refresh": "fake-refresh-not-a-real-token",
                    "expires_at": time.time() + 3600,
                },
            }, indent=2),
            encoding="utf-8",
        )
        status, body = get(base, "/healthz")
        check("login is picked up without a restart", body.get("token") == "present", json.dumps(body))
        left = body.get("expires_in") or 0
        check("expiry reported", 3400 < left <= 3600, f"expires_in={left}")

        status, body = get(base, "/healthz")
        check("other providers in the file are left alone", body.get("token") == "present")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
        check("probes ran without an error", False, str(exc))

    # No token -> nothing can leave the machine even if a guard were wrong.
    auth.write_text("{}", encoding="utf-8")

    # Browser / DNS-rebinding guards, which only apply while no client key is
    # set (that is the mode where anyone on the machine is trusted).
    try:
        evil = {"Host": "attacker.example.com", "Accept": "application/json"}
        status, _ = raw(port, "GET", "/healthz", evil)
        check("rebinding Host refused on /healthz", status == 403, f"status={status}")
        status, _ = raw(port, "POST", "/v1/messages", dict(evil, **{
            "Content-Type": "application/json"}), b"{}")
        check("rebinding Host refused on /v1", status == 403, f"status={status}")

        good = f"127.0.0.1:{port}"
        status, _ = raw(port, "POST", "/v1/messages", {
            "Host": good, "Origin": "https://evil.example.com",
            "Content-Type": "application/json"}, b"{}")
        check("cross-site Origin refused", status == 403, f"status={status}")
        status, _ = raw(port, "POST", "/v1/messages", {
            "Host": good,
            "Content-Type": "application/x-www-form-urlencoded"}, b"{}")
        check("form-shaped POST refused", status == 403, f"status={status}")
        status, _ = raw(port, "POST", "/v1/messages", {
            "Host": good, "Content-Type": "application/json"}, b"{}")
        check("a plain JSON POST passes the guard", status == 401, f"status={status}")

        # With a key set, the guards step aside: the key is the gate.
        proxy.Handler.client_key = "test-client-key"
        status, body = raw(port, "GET", "/healthz", {"Host": "attacker.example.com"})
        check("keyed mode answers any Host", status == 200, f"status={status}")
        check("keyless status is not leaked", b"auth_file" not in body, body[:120].decode("utf-8", "replace"))
        status, body = raw(port, "GET", "/healthz", {
            "Host": good, "x-api-key": "test-client-key"})
        check("the key unlocks the full status", status == 200 and b"auth_file" in body)
        proxy.Handler.client_key = ""
    except OSError as exc:
        check("guard probes ran without an error", False, str(exc))

    check("test_request stops cleanly when no token", test_request.main(["--url", base]) == 1)
    check("test_request reports a closed proxy", test_request.main(["--url", "http://127.0.0.1:1"]) == 1)

    server.shutdown()
    server.server_close()

    failed = [name for name, ok in results if not ok]
    print()
    print(f"offline_check: {len(results) - len(failed)}/{len(results)} ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
