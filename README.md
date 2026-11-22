# claude-oauth-proxy

Use your **Claude Pro / Max subscription** in any tool that expects an Anthropic
API key. It runs a small local server on your own machine:

```
http://127.0.0.1:8789
```

That address speaks the Anthropic Messages API (`/v1/messages`). It takes your
tool's request, attaches your subscription's OAuth token, forwards it to
`api.anthropic.com`, and hands the answer back. Expired tokens are refreshed on
the fly.

- **No dependencies.** Pure Python standard library — nothing is installed, nothing is downloaded.
- **Three files you can read.** The proxy, the login, and a test script. No build step.
- **Loopback by default.** Only your own machine can reach it.
- **Streaming works.** SSE responses are passed through unbuffered.

> **Read this first.** Using a Claude subscription outside Anthropic's own
> products is not an officially supported path, and this project is not
> affiliated with or endorsed by Anthropic.

---

## Run

```sh
python -I claude_login.py
python -I claude_oauth_proxy.py --port 8789
python -I test_request.py
```

## What to put in your tool

| Setting | Value |
| --- | --- |
| Provider / format | `anthropic` |
| Base URL | `http://127.0.0.1:8789` |
| API key | anything at all (e.g. `local-test`) — no real key is needed |
| Model | whatever `3-TEST` reports as working, e.g. `claude-sonnet-5-5` |

Anything that can point at a custom Anthropic base URL works: Cline, Roo Code,
Aider, Continue, LibreChat, your own scripts, an agent harness you wrote
yourself. Tools that only speak the **OpenAI** API format do not — this proxy
exposes the Anthropic API, not `/v1/chat/completions`.

The login is stored once and reused, and several tools can share one running
proxy.

## Commands

```sh
python -I claude_login.py              # log in
python -I claude_login.py --status     # is there a token, how long is it valid
python -I claude_login.py --logout     # delete the stored record
python -I claude_login.py --selftest   # offline self-check

python -I claude_oauth_proxy.py --help
python -I claude_oauth_proxy.py --port 9000
python -I claude_oauth_proxy.py --selftest

python -I tests/offline_check.py       # end to end, still no network
```

`curl http://127.0.0.1:8789/healthz` returns the proxy's state as JSON (token
present or not, seconds left, refresh count, last error). It never contains the
token. Once a client key is set, the full status needs that key as well; without
it only the version comes back.

## Configuration

Flags win over environment variables, which win over the defaults.

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--port` | `CLAUDE_OAUTH_PORT` | `8789` |
| `--bind` | `CLAUDE_OAUTH_BIND` | `127.0.0.1` |
| `--auth` | `CLAUDE_OAUTH_AUTH_FILE` | `~/.claude-oauth/auth.json` |
| — | `CLAUDE_OAUTH_CLIENT_KEY` | empty (no key required) |
| `--allow-anonymous` | — | off |

The token file holds your access and refresh tokens. Treat it like a password.
It lives in your home directory and is never part of this repository.

### Docker, VMs, other machines

If your tool runs in a container, the proxy has to listen on more than loopback
— and then **anyone who can reach that port can spend your subscription.** So
set a key first:

```sh
export CLAUDE_OAUTH_CLIENT_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
python3 -I claude_oauth_proxy.py --bind 0.0.0.0 --port 8789
```

Give that value to the tool as its API key and point it at
`http://host.docker.internal:8789`. Requests with a wrong or missing key get a
401.

Without a key, a non-loopback bind is **refused** (exit code 2). If you are
certain the port is firewalled off, `--allow-anonymous` overrides the refusal —
at your own risk.

## How it works

1. `claude_login.py` runs the OAuth authorization-code flow with PKCE against
   Anthropic's public client. Your browser does the login; you paste the
   resulting code back into the terminal. The access and refresh tokens are
   written to the token file, and nothing is printed to the screen.
2. `claude_oauth_proxy.py` listens locally. For every `/v1/...` request it
   re-reads the token file (so a login while it is running is picked up without
   a restart), refreshes the token if it expires within the next few minutes,
   replaces the authorization headers, and streams the upstream response back
   byte for byte. Status codes from Anthropic — `429` included — are relayed
   unchanged: the proxy does not retry and does not queue.
3. Every request carries one small system block identifying the client, byte for
   byte identical each time so prompt caching still hits. Your own system prompt
   follows it untouched.

Anything that is not under `/v1/` gets a 404, except `/healthz`.

While no client key is set, every request on the machine is trusted, so requests
that look like they came from a web page are refused with a 403 instead: a
`Host` header that is not loopback (how a DNS-rebinding page would reach you), a
cross-site `Origin`, or a browser form content type. Once a key is set the key is
the gate and these checks step aside, which is what keeps the container case
(`host.docker.internal`) working.

## Troubleshooting

| Symptom | What it means |
| --- | --- |
| `Python was not found` | Not installed, or not on PATH. Reinstall and tick "Add python.exe to PATH". |
| `no token in …` | Run the login step first. |
| `401` from the test | Token invalid or revoked — log in again. Or the proxy has a client key set and your tool sent a different one. |
| `403` with `permission_error` | In keyless mode the request looked like it came from a web page: a non-loopback `Host`, a cross-site `Origin`, or a form content type. With `curl`, add `-H 'content-type: application/json'`. |
| `429` / rate limit | Your subscription's usage window is full. That comes from Anthropic, not from the proxy. Wait it out. |
| A model name errors | Run the test script to see which names your subscription accepts. |



## Security

- The token file is the whole account. Do not paste it anywhere, do not commit
  it, do not put it in a bug report. Neither `/healthz` nor the logs contain it.
  It is created owner-only (`0600`, in a `0700` folder) where the filesystem
  supports it.
- Keep the bind on `127.0.0.1` unless you have a reason not to, and set a client
  key the moment you leave loopback.
- The scripts are short on purpose. Read them before you run them — that is what
  being this small is for.

## Files

```
claude_login.py          OAuth + PKCE login            (stdlib only)
claude_oauth_proxy.py    the proxy                     (stdlib only)
test_request.py          health + model check
tests/offline_check.py   end-to-end check, no network
```

## License

MIT — see [LICENSE](LICENSE).
