#!/usr/bin/env python3
"""Local proxy that puts a Claude Pro/Max subscription behind the Anthropic API.

Your tool talks to this proxy exactly as it would talk to api.anthropic.com
(any dummy ``x-api-key`` will do); the proxy drops that key, puts a fresh
``Authorization: Bearer <subscription token>`` and the ``oauth-2025-04-20``
beta in its place, guarantees the Claude Code identity as the first system
block, and streams api.anthropic.com's answer straight back. The client's own
transport, retries, streaming and token accounting stay untouched.

The token record is the one claude_login.py writes:

    ~/.claude-oauth/auth.json   ->   {"anthropic": {"type": "oauth", ...}}

Logging in stays its job. This proxy only reads that record and refreshes it
in place, through the same single-use refresh token, when the access token is
near expiry -- so every tool sharing that one file keeps working.

It listens on 127.0.0.1 only. Binding anywhere else needs a client key
(CLAUDE_OAUTH_CLIENT_KEY), because whoever reaches the port can spend the
subscription.

Run:  python3 -I claude_oauth_proxy.py [--port 8789] [--bind 127.0.0.1]
                                       [--auth ~/.claude-oauth/auth.json]
Self-test (no network, no token file):  python3 -I claude_oauth_proxy.py --selftest
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# ---- constants -------------------------------------------------------------

VERSION = "1.0.0"

PROVIDER = "anthropic"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"  # nosec B105
IDENTITY_SYSTEM_PROMPT = "You are Claude Code, Anthropic's official CLI for Claude."
BETA_FLAG = "oauth-2025-04-20"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"

# Headers the client manages and that must not go upstream.
DROP_HEADERS = frozenset({
    "x-api-key",
    "authorization",
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "anthropic-beta",
    "anthropic-version",
})
# Response headers whose framing is ours, not the upstream's.
DROP_RESPONSE_HEADERS = frozenset({
    "content-length",
    "connection",
    "transfer-encoding",
    "content-encoding",
})

TOKEN_TIMEOUT = 30.0
UPSTREAM_TIMEOUT = 600.0
EXPIRY_SKEW_S = 300.0
DEFAULT_TTL_S = 3600.0
CHUNK = 65536


class AuthError(Exception):
    """No usable token: the proxy answers 401 and names the step that failed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def log(message: str) -> None:
    print(f"[claude-oauth] {message}", file=sys.stderr, flush=True)


# ---- environment and paths -------------------------------------------------


def env_str(*names: str) -> str:
    """The first of these environment variables that is set and non-empty."""
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


LEGACY_AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"

# Host names a keyless proxy will answer, and the content types only a browser
# form sends. Both guard the loopback-only mode; see host_allowed() below.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", ""})
FORM_CONTENT_TYPES = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
})


def default_auth_path() -> Path:
    """Where the token lives: the env override, else ~/.claude-oauth/auth.json.

    A token file written by an earlier version of these scripts is used when
    the new one does not exist yet, so an earlier login keeps working.
    """
    env = env_str("CLAUDE_OAUTH_AUTH_FILE", "HARNESS_OAUTH_AUTH_FILE")
    if env:
        return Path(env)
    path = Path.home() / ".claude-oauth" / "auth.json"
    if not path.exists() and LEGACY_AUTH_PATH.exists():
        return LEGACY_AUTH_PATH
    return path


def bind_needs_key(bind: str, client_key: str, allow_anonymous: bool) -> bool:
    """True when this bind address would hand the subscription to the network."""
    if client_key or allow_anonymous:
        return False
    return bind.strip().lower() not in {"127.0.0.1", "localhost", "::1", "[::1]"}


def strip_port(host: str) -> str:
    """The host part of a Host header, lowercased, without the port."""
    host = (host or "").strip().lower()
    if host.startswith("["):  # [::1]:8789
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.split(":", 1)[0]


def host_allowed(host_header: str, client_key: str) -> bool:
    """Guard against DNS rebinding when the proxy has no client key.

    A page on the internet cannot read a response from 127.0.0.1, but it can
    make the browser *send* one: it serves a hostname that resolves to
    127.0.0.1 and posts to this port. Such a request arrives with that
    hostname in Host. Loopback mode therefore answers loopback names only.

    With a client key the key is the authentication and any Host is fine --
    that is how the container case (host.docker.internal) works.
    """
    if client_key:
        return True
    return strip_port(host_header) in LOOPBACK_HOSTS


def browser_shaped(origin: str, content_type: str) -> bool:
    """True for request shapes that only a web page sends.

    No API client sets Origin, and the three content types below are the ones
    a browser may send cross-origin with no preflight to answer -- exactly
    what an HTML form does. Refusing them costs a real client nothing and
    takes CSRF off the table.
    """
    if (origin or "").strip():
        return True
    kind = (content_type or "").split(";", 1)[0].strip().lower()
    return kind in FORM_CONTENT_TYPES


def write_private(path: Path, text: str) -> None:
    """Write a file only the owner can read, with no moment of wider access.

    The descriptor is created 0600 in place, so the token is never inside a
    file another account could open -- not even between the write and a
    chmod. On Windows the mode is largely advisory; the file still lands
    under the user's own profile.
    """
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        with contextlib.suppress(OSError, AttributeError):
            os.fchmod(handle.fileno(), 0o600)  # an existing file is tightened first
        handle.write(text)
        handle.flush()
        with contextlib.suppress(OSError):
            os.fsync(handle.fileno())


# ---- token store -----------------------------------------------------------


class TokenStore:
    """The shared subscription-auth.json, read per request, refreshed in place.

    Re-reading means a login done on the host while this runs is picked up
    without a restart. Writing keeps the file's other providers untouched and
    happens in place (no temp file + rename), because the file may be bind-mounted
    on its own (Docker) -- a rename would replace the mount, not the host's file.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.refreshes = 0
        self.last_error = ""

    def read_store(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))  # -sig: a BOM must not break it
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def read_record(self) -> dict[str, Any] | None:
        record = self.read_store().get(PROVIDER)
        if not isinstance(record, dict) or record.get("type") != "oauth":
            return None
        if not (record.get("access") and record.get("refresh")):
            return None
        return record

    def save_record(self, record: dict[str, Any]) -> None:
        data = self.read_store()
        data[PROVIDER] = record
        write_private(self.path, json.dumps(data, indent=2))

    def expires_in(self) -> float | None:
        record = self.read_record()
        if record is None:
            return None
        expires_at = record.get("expires_at")
        if not isinstance(expires_at, (int, float)):
            return 0.0
        return float(expires_at) - time.time()

    def token(self) -> str:
        """A usable access token, refreshed once under the lock when needed."""
        record = self.read_record()
        if record is None:
            raise AuthError("not_authenticated", f"no Claude record in {self.path}")
        if not near_expiry(record):
            return str(record["access"])
        with self._lock:
            # Another thread may have refreshed while this one waited.
            record = self.read_record()
            if record is None:
                raise AuthError("not_authenticated", f"no Claude record in {self.path}")
            if not near_expiry(record):
                return str(record["access"])
            try:
                refreshed = refresh_tokens(str(record["refresh"]))
            except AuthError as exc:
                # Another process sharing this file may have spent the refresh
                # token meanwhile and written a new one -- take that one.
                latest = self.read_record()
                if latest and latest["refresh"] != record["refresh"] and not near_expiry(latest):
                    return str(latest["access"])
                self.last_error = exc.message
                raise
            try:
                self.save_record(refreshed)
            except OSError as exc:
                # Persisting failed: this token works, but the next refresh
                # would reuse a spent refresh token. Say so loudly.
                self.last_error = f"token refreshed but not saved: {exc}"
                log(f"WARNING: {self.last_error}")
                log("  the token file must be writable, or you re-login every hour")
            self.refreshes += 1
            self.last_error = ""
            left = float(refreshed["expires_at"]) - time.time()
            log(f"access token refreshed, valid for {int(left)}s")
            return str(refreshed["access"])


def near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, (int, float)):
        return True
    return float(expires_at) - EXPIRY_SKEW_S <= time.time()


def post_json(payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(  # noqa: S310 -- constant https URL
        TOKEN_URL,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TOKEN_TIMEOUT) as response:  # noqa: S310
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        with contextlib.suppress(Exception):
            detail = exc.read().decode("utf-8", "replace")[:300]
        raise AuthError("token_http_error", f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AuthError("unavailable", str(exc)) from exc
    try:
        data = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise AuthError("bad_response", "token endpoint returned non-JSON") from exc
    if not isinstance(data, dict):
        raise AuthError("bad_response", "token endpoint returned a non-object")
    return data


def record_from_token_response(data: dict[str, Any], refresh_fallback: str | None = None) -> dict[str, Any]:
    access = data.get("access_token")
    refresh = data.get("refresh_token") or refresh_fallback
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access:
        raise AuthError("bad_response", "token response without access_token")
    if not isinstance(refresh, str) or not refresh:
        raise AuthError("bad_response", "token response without refresh_token")
    ttl = float(expires_in) if isinstance(expires_in, (int, float)) else DEFAULT_TTL_S
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "expires_at": time.time() + ttl,
    }


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    data = post_json({
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    })
    return record_from_token_response(data, refresh_fallback=refresh_token)


# ---- request rewriting -----------------------------------------------------


def prepend_identity_system(body: dict[str, Any]) -> dict[str, Any]:
    """Make the first system block exactly the Claude Code identity line.

    The block is byte-identical on every request, so a client's cached system
    prefix still hits -- the cache_control markers stay on their own blocks.
    """
    identity = {"type": "text", "text": IDENTITY_SYSTEM_PROMPT}
    system = body.get("system")
    if isinstance(system, str):
        blocks: list[Any] = [identity, {"type": "text", "text": system}]
    elif isinstance(system, list):
        blocks = [
            block
            for block in system
            if not (isinstance(block, dict) and block.get("text") == IDENTITY_SYSTEM_PROMPT)
        ]
        blocks = [identity, *blocks]
    else:
        blocks = [identity]
    body["system"] = blocks
    return body


def rewrite_headers(headers: dict[str, str], token: str) -> dict[str, str]:
    out = {k: v for k, v in headers.items() if k.lower() not in DROP_HEADERS}
    out["Authorization"] = f"Bearer {token}"
    out["anthropic-version"] = ANTHROPIC_VERSION
    existing = next((v for k, v in headers.items() if k.lower() == "anthropic-beta"), "")
    betas = [b.strip() for b in existing.split(",") if b.strip()]
    if BETA_FLAG not in betas:
        betas.append(BETA_FLAG)
    out["anthropic-beta"] = ", ".join(betas)
    return out


# ---- server ----------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    store: TokenStore
    client_key: str = ""
    server_version = f"claude-oauth-proxy/{VERSION}"
    sys_version = ""

    def log_message(self, *args: Any) -> None:  # the request log is ours
        pass

    # -- helpers

    def reply_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        with contextlib.suppress(OSError):
            self.wfile.write(raw)

    def reply_error(self, status: int, kind: str, message: str) -> None:
        # Anthropic's error shape, so the client shows the message instead of a blank.
        self.reply_json(status, {"type": "error", "error": {"type": kind, "message": message}})

    def refused_reason(self) -> str:
        """Why this request looks like a web page talking to us, or "" if it does not.

        Only the keyless loopback mode needs this: when a client key is set,
        a page cannot add that header cross-origin without a preflight we
        never answer.
        """
        if self.client_key:
            return ""
        host = self.headers.get("host") or ""
        if not host_allowed(host, self.client_key):
            return f"unexpected Host {host!r}: this proxy answers loopback names only"
        if (self.headers.get("origin") or "").strip():
            return "requests from a web page are refused; set CLAUDE_OAUTH_CLIENT_KEY to allow one"
        if browser_shaped("", self.headers.get("content-type") or ""):
            return "send content-type: application/json"
        return ""

    def refuse_if_browser(self) -> bool:
        reason = self.refused_reason()
        if not reason:
            return False
        log(f"{self.command} {self.path} -> 403 ({reason})")
        self.reply_error(403, "permission_error", reason)
        return True

    def authorized(self) -> bool:
        if not self.client_key:
            return True
        sent = self.headers.get("x-api-key") or ""
        if not sent:
            authorization = self.headers.get("authorization") or ""
            if authorization[:7].lower() == "bearer ":
                sent = authorization[7:].strip()
        return hmac.compare_digest(sent, self.client_key)

    def forward(self, payload: bytes | None) -> None:
        start = time.time()
        try:
            token = self.store.token()
        except AuthError as exc:
            log(f"{self.command} {self.path} -> 401 ({exc.code})")
            self.reply_error(
                401,
                "authentication_error",
                f"Claude subscription token unavailable ({exc.code}: {exc.message})",
            )
            return
        headers = rewrite_headers(dict(self.headers), token)
        request = urllib.request.Request(  # noqa: S310 -- host is the constant above
            ANTHROPIC_BASE_URL + self.path,
            data=payload,
            headers=headers,
            method=self.command,
        )
        try:
            upstream = urllib.request.urlopen(request, timeout=UPSTREAM_TIMEOUT)  # noqa: S310
            status, head = upstream.status, upstream.headers
        except urllib.error.HTTPError as exc:
            # 4xx/5xx is an answer, not a failure: relay it verbatim so the client's
            # own retry, failover and error reporting see the real thing.
            upstream, status, head = exc, exc.code, exc.headers
        except (urllib.error.URLError, OSError) as exc:
            log(f"{self.command} {self.path} -> 502 (upstream: {exc})")
            self.reply_error(502, "api_error", f"upstream request failed: {exc}")
            return
        sent = 0
        try:
            self.send_response(status)
            for key, value in head.items():
                if key.lower() in DROP_RESPONSE_HEADERS:
                    continue
                self.send_header(key, value)
            self.end_headers()
            while True:
                chunk = upstream.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                sent += len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            log(f"{self.command} {self.path} -> {status}, client left after {sent}B")
            return
        finally:
            with contextlib.suppress(Exception):
                upstream.close()
        log(f"{self.command} {self.path} -> {status}, {sent}B in {time.time() - start:.1f}s")

    # -- routes

    def do_POST(self) -> None:
        if not self.path.startswith("/v1/"):
            self.reply_error(404, "not_found_error", f"no route for {self.path}")
            return
        if self.refuse_if_browser():
            return
        if not self.authorized():
            self.reply_error(401, "authentication_error", "wrong x-api-key for this proxy (CLAUDE_OAUTH_CLIENT_KEY)")
            return
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("the request body is not a JSON object")
            payload = json.dumps(prepend_identity_system(body)).encode()
        except (json.JSONDecodeError, ValueError) as exc:
            self.reply_error(400, "invalid_request_error", f"could not read the request body: {exc}")
            return
        self.forward(payload)

    def do_GET(self) -> None:
        if self.refuse_if_browser():
            return
        if self.path.startswith("/healthz"):
            if self.client_key and not self.authorized():
                # Without the key, the version is all an outside caller gets:
                # the rest would describe the account and the filesystem.
                self.reply_json(200, {"version": VERSION, "detail": "send x-api-key for the full status"})
                return
            left = self.store.expires_in()
            self.reply_json(200, {
                "ok": left is not None,
                "version": VERSION,
                "token": "missing" if left is None else "present",
                "expires_in": None if left is None else int(left),
                "refreshes": self.store.refreshes,
                "auth_file": str(self.store.path),
                "last_error": self.store.last_error,
            })
            return
        if not self.path.startswith("/v1/"):
            self.reply_error(404, "not_found_error", f"no route for {self.path}")
            return
        if not self.authorized():
            self.reply_error(401, "authentication_error", "wrong x-api-key for this proxy (CLAUDE_OAUTH_CLIENT_KEY)")
            return
        self.forward(None)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # Workers would queue behind one another otherwise.
    request_queue_size = 64


# ---- self-test -------------------------------------------------------------


def selftest() -> int:
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        if condition:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name}")
            failures.append(name)

    identity = {"type": "text", "text": IDENTITY_SYSTEM_PROMPT}

    body = prepend_identity_system({"system": "be helpful", "model": "m"})
    check("a string system keeps its text behind the identity block",
          body["system"] == [identity, {"type": "text", "text": "be helpful"}])

    blocks = [
        {"type": "text", "text": "client static", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "client dynamic"},
    ]
    body = prepend_identity_system({"system": list(blocks)})
    check("a block list keeps its order and cache_control", body["system"] == [identity, *blocks])

    body = prepend_identity_system({"system": [identity, *blocks]})
    check("an identity block is not duplicated", body["system"] == [identity, *blocks])
    check("the identity block is first", body["system"][0]["text"] == IDENTITY_SYSTEM_PROMPT)

    body = prepend_identity_system({"model": "m"})
    check("a missing system becomes the identity block alone", body["system"] == [identity])

    sent = {"x-api-key": "dummy", "Host": "claude-oauth:8789", "anthropic-version": "2023-06-01",
            "content-type": "application/json", "content-length": "12", "accept": "text/event-stream"}
    out = rewrite_headers(sent, "tok")
    check("the client key never leaves the proxy", not any(k.lower() == "x-api-key" for k in out))
    check("hop-by-hop headers are dropped",
          not any(k.lower() in {"host", "content-length"} for k in out))
    check("the bearer token is set", out["Authorization"] == "Bearer tok")
    check("the oauth beta is set", out["anthropic-beta"] == BETA_FLAG)
    check("the api version is set", out["anthropic-version"] == ANTHROPIC_VERSION)
    check("other headers survive", out["accept"] == "text/event-stream")

    out = rewrite_headers({"anthropic-beta": "fine-grained-tool-streaming-2025-05-14"}, "tok")
    check("an existing beta is kept alongside ours",
          out["anthropic-beta"] == f"fine-grained-tool-streaming-2025-05-14, {BETA_FLAG}")

    now = time.time()
    check("a token expiring inside the skew is refreshed", near_expiry({"expires_at": now + 60}))
    check("a fresh token is not refreshed", not near_expiry({"expires_at": now + 1800}))
    check("a record without an expiry is refreshed", near_expiry({}))

    record = record_from_token_response({"access_token": "a", "expires_in": 120}, refresh_fallback="r")
    check("the old refresh token is kept when the response omits one", record["refresh"] == "r")
    check("the expiry comes from expires_in", 115 < record["expires_at"] - time.time() <= 120)

    os.environ.pop("CLAUDE_OAUTH_AUTH_FILE", None)
    os.environ["HARNESS_OAUTH_AUTH_FILE"] = "/tmp/legacy.json"
    check("a legacy env var is still honoured", default_auth_path() == Path("/tmp/legacy.json"))
    os.environ["CLAUDE_OAUTH_AUTH_FILE"] = "/tmp/new.json"
    check("the new env var wins over the legacy one", default_auth_path() == Path("/tmp/new.json"))
    os.environ.pop("CLAUDE_OAUTH_AUTH_FILE", None)
    os.environ.pop("HARNESS_OAUTH_AUTH_FILE", None)
    check("the default token path is a json file", default_auth_path().suffix == ".json")

    check("loopback without a client key is allowed", not bind_needs_key("127.0.0.1", "", False))
    check("a wildcard bind without a client key is refused", bind_needs_key("0.0.0.0", "", False))
    check("a wildcard bind with a client key is allowed", not bind_needs_key("0.0.0.0", "k", False))
    check("--allow-anonymous overrides the refusal", not bind_needs_key("0.0.0.0", "", True))

    check("a port is stripped from Host", strip_port("127.0.0.1:8789") == "127.0.0.1")
    check("an ipv6 Host keeps its brackets", strip_port("[::1]:8789") == "[::1]")
    check("a loopback Host is allowed", host_allowed("127.0.0.1:8789", ""))
    check("localhost is allowed", host_allowed("LocalHost:8789", ""))
    check("a missing Host is allowed", host_allowed("", ""))
    check("a rebinding Host is refused", not host_allowed("evil.example.com:8789", ""))
    check("any Host is allowed once a key is set", host_allowed("host.docker.internal:8789", "k"))
    check("an Origin marks a browser request", browser_shaped("https://evil.example.com", "application/json"))
    check("a form content type marks a browser request",
          browser_shaped("", "application/x-www-form-urlencoded"))
    check("text/plain marks a browser request", browser_shaped("", "text/plain; charset=utf-8"))
    check("a plain json client does not", not browser_shaped("", "application/json"))
    check("a missing content type does not", not browser_shaped("", ""))

    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        secret = Path(folder) / "sub" / "auth.json"
        write_private(secret, '{"a": 1}')
        check("the token file is written", json.loads(secret.read_text(encoding="utf-8")) == {"a": 1})
        write_private(secret, '{"a": 2}')
        check("the token file is rewritten in place",
              json.loads(secret.read_text(encoding="utf-8")) == {"a": 2})
        if os.name != "nt":  # Windows modes are advisory
            check("the token file is owner-only", secret.stat().st_mode & 0o077 == 0)
            check("the token folder is owner-only", secret.parent.stat().st_mode & 0o077 == 0)

    print("")
    if failures:
        print(f"{len(failures)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


# ---- main ------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Local Anthropic-API proxy backed by a Claude Pro/Max subscription",
    )
    parser.add_argument("--port", type=int, default=int(env_str("CLAUDE_OAUTH_PORT", "HARNESS_OAUTH_PORT") or 8789),
                        help="port to listen on (default 8789)")
    parser.add_argument("--bind", default=env_str("CLAUDE_OAUTH_BIND", "HARNESS_OAUTH_BIND") or "127.0.0.1",
                        help="address to listen on (default 127.0.0.1; anything else needs a client key)")
    parser.add_argument("--auth", default=None,
                        help="token file written by claude_login.py (default ~/.claude-oauth/auth.json)")
    parser.add_argument("--allow-anonymous", action="store_true",
                        help="allow a non-loopback bind without CLAUDE_OAUTH_CLIENT_KEY")
    parser.add_argument("--version", action="version", version=f"claude-oauth-proxy {VERSION}")
    parser.add_argument("--selftest", action="store_true", help="check the rewriting rules and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    auth_path = Path(args.auth) if args.auth else default_auth_path()
    store = TokenStore(auth_path)
    Handler.store = store
    Handler.client_key = env_str("CLAUDE_OAUTH_CLIENT_KEY", "HARNESS_OAUTH_CLIENT_KEY")

    if bind_needs_key(args.bind, Handler.client_key, args.allow_anonymous):
        log(f"refusing to listen on {args.bind} without a client key.")
        log("  Whoever reaches that address could spend your subscription.")
        log("  Set CLAUDE_OAUTH_CLIENT_KEY=<a long random string> and send it as x-api-key,")
        log("  or pass --allow-anonymous if you know the port is firewalled off.")
        return 2

    left = store.expires_in()
    if left is None:
        log(f"no token in {auth_path} -- run claude_login.py; it is picked up without a restart")
    elif left <= 0:
        log("the access token has expired; it is refreshed on the first request")
    else:
        log(f"the access token is valid for {int(left)}s")
    if not Handler.client_key:
        reach = "every program on this machine" if not bind_needs_key(args.bind, "", False) \
            else "anyone who can reach this port"
        log(f"no CLAUDE_OAUTH_CLIENT_KEY set: {reach} may use the subscription")

    server = Server((args.bind, args.port), Handler)
    log(f"claude-oauth-proxy {VERSION} listening on {args.bind}:{args.port}, upstream {ANTHROPIC_BASE_URL}")
    log(f"point your tool at http://{args.bind}:{args.port} (format: anthropic, any api key)")
    if args.bind in ("0.0.0.0", "::"):
        log(f"from a Docker container: http://host.docker.internal:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
