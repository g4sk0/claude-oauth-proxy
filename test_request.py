#!/usr/bin/env python3
"""Check the proxy: /healthz first, then one tiny request per model.

Usage:  python -I test_request.py [--url http://127.0.0.1:8789] [--model NAME]

Each model gets a single 16-token request, so what it spends from the
subscription is negligible. Use it to see which model names work for you.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_MODELS = ["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"]
TIMEOUT = 120.0


def client_key() -> str:
    """The proxy's client key, if one is set; otherwise any value works."""
    for name in ("CLAUDE_OAUTH_CLIENT_KEY", "HARNESS_OAUTH_CLIENT_KEY"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return "local-test"


def get_json(url: str) -> tuple[int, dict]:
    request = urllib.request.Request(url, method="GET")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read()[:400].decode("utf-8", "replace")}
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        return 0, {"error": str(exc)}


def ask(url: str, model: str) -> tuple[int, str]:
    payload = {
        "model": model,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with OK and nothing else."}],
    }
    request = urllib.request.Request(  # noqa: S310
        f"{url}/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": client_key(),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            data = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()[:300].decode("utf-8", "replace")
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        return 0, str(exc)
    blocks = data.get("content") or []
    text = ""
    for block in blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            text += str(block.get("text") or "")
    usage = data.get("usage") or {}
    return 200, f"{text.strip()!r} (tokens: {usage.get('input_tokens')}/{usage.get('output_tokens')})"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="claude-oauth-proxy check")
    parser.add_argument("--url", default=os.environ.get("CLAUDE_OAUTH_URL") or "http://127.0.0.1:8789")
    parser.add_argument("--model", action="append", default=None,
                        help="model to try (repeatable); defaults to a few known names")
    args = parser.parse_args(argv)
    url = args.url.rstrip("/")

    print(f"1) Health check: {url}/healthz")
    status, health = get_json(f"{url}/healthz")
    if status != 200:
        print(f"   FAILED ({status}): {health.get('error', health)}")
        print("   Is the proxy running? The 2-START window has to stay open.")
        return 1
    print(f"   token      : {health.get('token')}")
    print(f"   expires in : {health.get('expires_in')} s")
    print(f"   token file : {health.get('auth_file')}")
    if health.get("token") != "present":
        print("   No token yet: log in first (1-LOGIN.bat / 1-login.sh).")
        return 1

    models = args.model or DEFAULT_MODELS
    print()
    print("2) Model check (one tiny request each):")
    ok_models = []
    for model in models:
        status, detail = ask(url, model)
        if status == 200:
            ok_models.append(model)
            print(f"   OK    {model}  ->  {detail}")
        else:
            print(f"   ERROR {model}  ->  {status}: {detail}")

    print()
    if ok_models:
        print("Working model(s): " + ", ".join(ok_models))
        print(f"Give your tool this base URL: {url}  (format: anthropic, any api key)")
        return 0
    print("No model worked. The errors above come from Anthropic, not from the")
    print("proxy: it is usually the model name or a subscription rate limit.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
