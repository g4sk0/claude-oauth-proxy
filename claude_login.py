#!/usr/bin/env python3
r"""Claude subscription login: OAuth 2.0 + PKCE, standard library only.

You approve the request in your browser, then paste the code it shows back
here. The token is written to the file below and is never printed:

    ~/.claude-oauth/auth.json
    (Windows: %USERPROFILE%\.claude-oauth\auth.json)

Usage:
    python -I claude_login.py            # log in
    python -I claude_login.py --status   # is there a token, how long is it valid
    python -I claude_login.py --logout   # delete the stored token
    python -I claude_login.py --selftest # check itself, no network


"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

VERSION = "1.0.0"

PROVIDER = "anthropic"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"  # nosec B105
REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
SCOPE = "org:create_api_key user:profile user:inference"

TOKEN_TIMEOUT = 30.0
DEFAULT_TTL_S = 3600.0


class LoginError(Exception):
    pass


# ---- environment and paths --------------------------------------------------


def env_str(*names: str) -> str:
    """The first of these environment variables that is set and non-empty."""
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


LEGACY_AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"


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


# ---- PKCE -------------------------------------------------------------------


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(64))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorize_url(challenge: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "code": "true",
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def parse_redirect_input(value: str) -> tuple[str | None, str | None]:
    """What you paste may be the whole URL, "code#state", or just the code."""
    value = (value or "").strip().strip('"').strip("'")
    if not value:
        return None, None
    with contextlib.suppress(ValueError):
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.query:
            query = urllib.parse.parse_qs(parsed.query)
            return _first(query, "code"), _first(query, "state")
    if "#" in value:
        code, _, state = value.partition("#")
        return code or None, state or None
    if "code=" in value:
        query = urllib.parse.parse_qs(value)
        return _first(query, "code"), _first(query, "state")
    return value, None


# ---- token endpoint ---------------------------------------------------------


def post_json(payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 -- constant https URL
        TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TOKEN_TIMEOUT) as response:  # noqa: S310
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        with contextlib.suppress(Exception):
            detail = exc.read()[:300].decode("utf-8", "replace")
        raise LoginError(f"the token endpoint answered HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise LoginError(f"could not connect: {exc.reason}") from exc
    try:
        data = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise LoginError("the token endpoint did not return JSON") from exc
    if not isinstance(data, dict):
        raise LoginError("the token endpoint returned an unexpected shape")
    return data


def record_from_token_response(
    data: dict[str, Any], refresh_fallback: str | None = None
) -> dict[str, Any]:
    access = data.get("access_token")
    refresh = data.get("refresh_token") or refresh_fallback
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access:
        raise LoginError("the response has no access_token")
    if not isinstance(refresh, str) or not refresh:
        raise LoginError("the response has no refresh_token")
    ttl = float(expires_in) if isinstance(expires_in, (int, float)) else DEFAULT_TTL_S
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "expires_at": time.time() + ttl,
    }


def exchange_code(code: str, verifier: str, state: str | None = None) -> dict[str, Any]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    }
    if state:
        payload["state"] = state
    return record_from_token_response(post_json(payload))


# ---- token file -------------------------------------------------------------


def read_store(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))  # -sig: a BOM must not break it
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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


def save_record(path: Path, record: dict[str, Any]) -> None:
    data = read_store(path)
    data[PROVIDER] = record
    write_private(path, json.dumps(data, indent=2))


def read_record(path: Path) -> dict[str, Any] | None:
    record = read_store(path).get(PROVIDER)
    if not isinstance(record, dict) or record.get("type") != "oauth":
        return None
    if not (record.get("access") and record.get("refresh")):
        return None
    return record


# ---- commands ---------------------------------------------------------------


def cmd_status(path: Path) -> int:
    record = read_record(path)
    print(f"Token file : {path}")
    if record is None:
        print("Status     : NOT LOGGED IN (run this script with no arguments)")
        return 1
    expires_at = record.get("expires_at")
    if isinstance(expires_at, (int, float)):
        minutes = (float(expires_at) - time.time()) / 60.0
        if minutes > 0:
            print(f"Status     : logged in, the access token is valid for {minutes:.0f} min")
        else:
            print("Status     : logged in, the access token has expired")
            print("             (the proxy refreshes it on the first request, nothing to do)")
    else:
        print("Status     : logged in (no expiry recorded)")
    return 0


def cmd_logout(path: Path) -> int:
    data = read_store(path)
    if PROVIDER not in data:
        print("There is nothing to delete.")
        return 0
    del data[PROVIDER]
    if data:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        with contextlib.suppress(OSError):
            path.unlink()
    print("The stored token was deleted.")
    return 0


def cmd_login(path: Path) -> int:
    verifier, challenge = generate_pkce()
    state = secrets.token_hex(16)
    url = build_authorize_url(challenge, state)

    print("Claude subscription login")
    print("-------------------------")
    print("1) The address below is opening in your browser. If it does not open,")
    print("   copy it and open it yourself:")
    print()
    print(url)
    print()
    print("2) Sign in with your Claude account and approve the request.")
    print("3) A code then appears on the page / in the address bar.")
    print("   Paste the whole thing here and press Enter ('code#state' works,")
    print("   so does the complete URL).")
    print()
    with contextlib.suppress(Exception):
        webbrowser.open(url)

    try:
        pasted = input("Code: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 1

    code, pasted_state = parse_redirect_input(pasted)
    if not code:
        print("ERROR: could not read a code. Please start over.")
        return 1
    if pasted_state and pasted_state != state:
        print("ERROR: the state does not match. This attempt is void, start over.")
        return 1

    print("Exchanging the code for a token...")
    try:
        record = exchange_code(code, verifier, pasted_state or state)
    except LoginError as exc:
        print(f"ERROR: {exc}")
        return 1

    try:
        save_record(path, record)
    except OSError as exc:
        print(f"ERROR: could not write the token file: {exc}")
        return 1

    print()
    print(f"Done. The token was written to: {path}")
    print("It was never printed; do not share that file with anyone.")
    print("Now start the proxy (2-START.bat on Windows, 2-start.sh elsewhere).")
    return 0


# ---- selftest ---------------------------------------------------------------


def selftest() -> int:
    import io
    import tempfile

    checks: list[tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, bool(ok)))
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")

    verifier, challenge = generate_pkce()
    check("the verifier is long enough", 80 <= len(verifier) <= 128)
    check("the verifier is base64url", all(c.isalnum() or c in "-_" for c in verifier))
    check(
        "the challenge is S256(verifier)",
        challenge == b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
    )

    url = build_authorize_url(challenge, "abc123")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    check("the authorize url points at the right host", url.startswith(AUTHORIZE_URL + "?"))
    check("client_id is sent", query.get("client_id") == [CLIENT_ID])
    check("code_challenge_method is S256", query.get("code_challenge_method") == ["S256"])
    check("the scope is sent", query.get("scope") == [SCOPE])
    check("the redirect uri is sent", query.get("redirect_uri") == [REDIRECT_URI])
    check("code=true is sent", query.get("code") == ["true"])
    check("the state is sent", query.get("state") == ["abc123"])

    check("'code#state' is parsed", parse_redirect_input(" CODE1#ST1 ") == ("CODE1", "ST1"))
    check(
        "a full redirect url is parsed",
        parse_redirect_input("https://console.anthropic.com/oauth/code/callback?code=K2&state=S2")
        == ("K2", "S2"),
    )
    check("a bare code is parsed", parse_redirect_input("K3") == ("K3", None))
    check("empty input is rejected", parse_redirect_input("   ") == (None, None))

    record = record_from_token_response({"access_token": "a", "refresh_token": "r", "expires_in": 60})
    check("the record has the right shape", record["type"] == "oauth" and record["provider"] == PROVIDER)
    check("expires_at is in the future", float(record["expires_at"]) > time.time())
    record2 = record_from_token_response({"access_token": "a", "expires_in": 60}, refresh_fallback="r0")
    check("the old refresh token is kept when the response omits one", record2["refresh"] == "r0")
    try:
        record_from_token_response({"refresh_token": "r"})
        check("a missing access_token is an error", False)
    except LoginError:
        check("a missing access_token is an error", True)

    os.environ.pop("CLAUDE_OAUTH_AUTH_FILE", None)
    os.environ["HARNESS_OAUTH_AUTH_FILE"] = "/tmp/legacy.json"
    check("a legacy env var is still honoured", default_auth_path() == Path("/tmp/legacy.json"))
    os.environ["CLAUDE_OAUTH_AUTH_FILE"] = "/tmp/new.json"
    check("the new env var wins over the legacy one", default_auth_path() == Path("/tmp/new.json"))
    os.environ.pop("CLAUDE_OAUTH_AUTH_FILE", None)
    os.environ.pop("HARNESS_OAUTH_AUTH_FILE", None)
    check("the default token path is a json file", default_auth_path().suffix == ".json")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sub" / "auth.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"openai": {"type": "oauth", "access": "x"}}), encoding="utf-8")
        save_record(path, record)
        store = read_store(path)
        check("another provider in the file is left alone", "openai" in store)
        check("the record reads back", read_record(path) is not None)
        with contextlib.redirect_stdout(io.StringIO()):
            cmd_logout(path)
        check("logout removed the record", read_record(path) is None)
        check("logout left the other provider", "openai" in read_store(path))

        secret = Path(tmp) / "fresh" / "auth.json"
        write_private(secret, '{"a": 1}')
        check("the token file is written", json.loads(secret.read_text(encoding="utf-8")) == {"a": 1})
        write_private(secret, '{"a": 2}')
        check("the token file is rewritten in place",
              json.loads(secret.read_text(encoding="utf-8")) == {"a": 2})
        if os.name != "nt":  # Windows modes are advisory
            check("the token file is owner-only", secret.stat().st_mode & 0o077 == 0)
            check("the token folder is owner-only", secret.parent.stat().st_mode & 0o077 == 0)

    failed = [name for name, ok in checks if not ok]
    print()
    print(f"selftest: {len(checks) - len(failed)}/{len(checks)} ok")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Claude subscription login (OAuth + PKCE)")
    parser.add_argument("--out", default=None, help="path of the token file")
    parser.add_argument("--status", action="store_true", help="is there a token, how long is it valid")
    parser.add_argument("--logout", action="store_true", help="delete the stored token")
    parser.add_argument("--selftest", action="store_true", help="check itself, no network")
    parser.add_argument("--version", action="version", version=f"claude-oauth-proxy {VERSION}")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    path = Path(args.out) if args.out else default_auth_path()
    if args.status:
        return cmd_status(path)
    if args.logout:
        return cmd_logout(path)
    return cmd_login(path)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
