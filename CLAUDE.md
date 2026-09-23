# CLAUDE.md

Guidance for Claude Code (or any agentic coding tool) working in this repository.

## What this is

`secondeye` (package name `second-eye`, installed via `pipx` from GitHub —
not published to PyPI, intentionally) is a scope-gated, passive HTTP/HTTPS
recording proxy for offensive security operators. **`SPEC.md` is the
authoritative technical specification** — read it before making any
non-trivial change. This file only covers what `SPEC.md` doesn't: build
status, conventions actually enforced in the code, and decisions made while
implementing it that future work should know about.

## Status

All 7 build phases in `SPEC.md` §14 are complete and passing:
`scope/matcher.py` → `tls/{ca,leaf}.py` → `proxy/sni.py` →
`proxy/{splice,listener}.py` → `proxy/{intercept,upstream}.py` +
`capture/har.py` + plain-HTTP path → `recording/`, `analysis/`,
`capture/buffer.py` → `daemon.py`, `cli.py`, `README.md`.

Manual testing has passed. Coverage sits around 95% (floor is 90%, enforced via
`pyproject.toml`'s `--cov-fail-under=90`). CI (`.github/workflows/ci.yml`)
runs all four gates — `ruff check`, `ruff format --check`, `mypy --strict`,
`pytest` — on every push to `main`, across Python 3.11/3.12/3.13.

`SECURITY.md`, `CHANGELOG.md`, and `CONTRIBUTING.md` now exist at the
repo root (v1.0.0 readiness pass) — keep `CHANGELOG.md`'s `## Unreleased`
section current when making a user-visible change, the same way this
file's own "Post-v1 additions" paragraph below is kept current. The
state directory (`~/.local/state/secondeye`) is locked to `0700` on
every daemon start (`tls/ca.py`'s `_lock_down_state_dir`, called from
`load_or_create_ca` so `ca export`/`ca status` get it too, not just
`proxy start`) — this is now a documented, public guarantee (see
`SECURITY.md`), not just an internal detail.

Post-v1 additions (also reflected in `SPEC.md`, not just here):
`-tf`/`--target-file` (v0.1.2) — line-delimited target list, an alternative
to repeating `--target`. Second-instance guard, three CLI flag renames
(`--listen`→`--listen-address`, `--upstream`→`--upstream-proxy`,
`--capture-all`→`--target-all`, the latter renamed all the way through
internal code and `manifest.json`'s schema key), and full `--help` text on
every flag (v0.2.0). CLI UX pass (v0.3.0): a `proxy start` startup banner
(scope/listen/upstream summary + next-step hint, printed unconditionally via
`Daemon.run()`'s new `on_started` callback, unaffected by `-v`/`-q`);
colorized `✓`/`✗` output (`_green`/`_red` in `cli.py`, respecting `NO_COLOR`
and non-tty streams); and `argcomplete`-based shell completion (the
project's first non-load-bearing dependency). Usability batch (v0.4.0):
install docs corrected to `pipx install
git+https://github.com/ridgebackinfosec/second-eye.git` (never published to
PyPI, intentionally — a deliberate distribution choice, not a gap);
`secondeye --version`/`-V`; `proxy status` reports a live request count for
the active capture (`CaptureManager.active_request_count`); `secondeye ca
status` (read-only — never generates a CA as a side effect, unlike every
other CA-touching command); and a first-run CA-creation note, both on `ca
export` (stderr only — stdout carries the raw cert bytes) and in the
`proxy start` banner (`Daemon.ca_was_created`). ANALYSIS.md derived-signals
batch (v0.5.0): cheap, no-cross-entry-correlation additions to
`analysis/render.py` — timing/size outlier notes on individual flows;
security-header posture and stack fingerprint hints surfaced in a new
`## Capture Signals` section; a `## Contents` table of contents linking to
every narrative flow; and state-changing (`POST`/`PUT`/`DELETE`/`PATCH`)
method highlighting everywhere a method is shown. ANALYSIS.md Phase 2
orientation block (v0.6.0): a classification-confidence marker
(`classify_entries()`'s new `confirmed` field on `ClassifiedEntry`, surfaced
as a `*(guessed)*` heading marker on flows built from unconfirmed entries);
and a new `## Summary` section with four independently-omittable sub-parts —
endpoints touched, auth mechanisms observed, a status-code rollup, and
parameter names observed (query-string and JSON-body top-level keys only,
never values, for spotting IDOR-candidate parameters like `user_id` at a
glance). ANALYSIS.md Phase 3 heavier signals (v0.7.0): framework
debug/error-page detection (fixed Django/Flask-Werkzeug/Rails/ASP.NET/PHP
signature matches, rendered as a per-flow `**Warning:**`); credential-pattern
detection (AWS access keys, PEM private-key headers, JWT-shaped strings in
response bodies, rendered **unredacted** per this tool's no-redaction design
stance — see `SPEC.md` §0); a broadened `## Capture Signals` audit
(`X-XSS-Protection`/`Referrer-Policy`/`Permissions-Policy` header presence, a
CORS misconfiguration check for `Access-Control-Allow-Origin: *` paired with
`Access-Control-Allow-Credentials: true`, and a `Set-Cookie`
`Secure`/`HttpOnly`/`SameSite` flag audit); cross-request ID-value reuse
detection (query-string/JSON-body parameter values reused elsewhere in the
capture, deliberately excluding auth/session values); and a capture-wide
`## Sequence Diagram` section (Mermaid `sequenceDiagram`, one
request/response arrow pair per narrative flow across "Operator" and
"Target" lanes).

## Commands

```sh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest                          # full suite, coverage enforced
pytest tests/test_foo.py -v     # one file
ruff check .                    # lint
ruff format .                   # format
mypy --strict src/secondeye     # type check
```

All four (`pytest`, `ruff check`, `ruff format --check`, `mypy --strict`) must
pass clean before any change is considered done — this was the bar held
throughout the original build, phase by phase.

## Architecture map

```
src/secondeye/
├── cli.py              # argparse entrypoint, all `secondeye <noun> <verb>` subcommands
├── daemon.py            # foreground orchestration + signal handling for `proxy start`
├── exceptions.py         # the only exception types this codebase raises
├── scope/matcher.py      # --target / --target-regex / IDN matching
├── tls/{ca,leaf}.py      # root CA persistence; per-SNI leaf cert generation+cache
├── proxy/
│   ├── sni.py             # ClientHello buffer-and-parse (no true MSG_PEEK in asyncio)
│   ├── splice.py          # blind bidirectional relay, out-of-scope path
│   ├── listener.py        # CONNECT/plain-HTTP entrypoint, loopback+max-conn enforcement
│   ├── upstream.py        # Burp/ZAP CONNECT-chaining vs --no-upstream direct connect
│   ├── intercept.py       # TLS termination (ssl.MemoryBIO) + HTTP/1.1, in-scope path
│   ├── plain_http.py      # absolute-URI (non-CONNECT) in-scope path
│   └── _http_cycle.py     # h11 request/response cycle shared by intercept+plain_http
├── capture/{har,buffer}.py            # HAR entry construction; incremental JSONL buffer
├── analysis/{classify,cluster,manifest,render}.py  # raw.har → manifest.json + ANALYSIS.md
└── recording/{manager,control}.py     # capture lifecycle state machine + control socket
```

Module boundaries are deliberate (see `SPEC.md` §13's rationale) — `proxy/`
doesn't know about HAR/analysis, `recording/control.py` is transport-only
(business logic lives in `manager.py`), `tls/ca.py` (generate-once) and
`tls/leaf.py` (generate-per-SNI, cached) are split because their lifecycles
differ.

## Conventions actually enforced here

- Type hints everywhere, `X | None` not `Optional[X]`, `mypy --strict` clean.
- `pathlib.Path`, never `os.path`.
- Dataclasses for structured data, never raw `dict[str, Any]` passed around.
- Every raised exception is a `secondeye.exceptions.SecondEyeError` subclass —
  no bare `except:`, every catch names its exception type.
- Google-style docstrings on every public function/class.
- CPU-bound/blocking sync calls from async code go through
  `asyncio.to_thread()` (cert generation, JSONL file writes).
- `__all__` declared in every module with a public surface.

## Testing philosophy

Tests in this repo overwhelmingly use **real sockets, real TLS handshakes,
real subprocesses** — not mocks — even where mocking would be faster to write.
This was a deliberate choice, validated repeatedly during the build:
real-transport tests caught bugs mocks would have hidden, including:

- A leaf-cert Authority Key Identifier omission that `openssl verify` didn't
  catch, but a real `ssl.create_default_context()` handshake did.
- An h11 `InformationalResponse` (101 Switching Protocols) handling gap that
  only a real WebSocket-upgrade byte stream surfaced.
- A connection-leak on early-return error paths that only showed up as an
  actual hung real TLS handshake under pytest, not in isolated unit logic.
- A body-encoding fidelity bug (`errors="replace"` silently corrupting binary
  HAR bodies) that only a real byte-for-byte round-trip assertion caught.

New tests for proxy/TLS/capture code should keep following this pattern:
prefer a real loopback `asyncio.start_server` + real client over
`unittest.mock`. TDD (write the test, watch it fail for the right reason, then
implement) was used throughout — keep using it.

## Notable deviations from SPEC.md (and why)

The spec is the source of truth, but it has a few internal contradictions and
gaps that got resolved during the build. Each is worth knowing before
touching the affected area:

- **CA persistence path**: `SPEC.md` §5.2 says `~/.config/secondeye/ca/`, but
  §6.5's directory tree shows `~/.local/state/secondeye/ca/`. Went with §6.5
  (confirmed with the user during the build) — `tls/ca.py`'s
  `default_state_dir()` is the single source of truth for this.
- **`exceptions.py` has more classes than `SPEC.md` §8's literal list.**
  `ConfigError` (bad `--listen-address`, conflicting upstream flags, a
  bind/socket already in use) and `CaptureControlError` + 3 subclasses
  (`CaptureAlreadyActiveError`, `CaptureNameConflictError`,
  `NoActiveCaptureError`) were added because §2's prose describes exactly
  these error conditions but §8's hierarchy — written from a proxy/TLS lens —
  doesn't have a natural home for them.
- **`proxy/_http_cycle.py`** isn't named in §13's module list. It holds the
  h11 request/response-cycle logic shared verbatim by `intercept.py` (TLS) and
  `plain_http.py` (cleartext) via a small `AsyncStream` protocol, rather than
  duplicating it — §4.4 only required plain-HTTP to have its "own entry point,
  not forced through intercept.py's TLS-specific logic," which this satisfies
  without duplicating the trickier parts (101 handling, keep-alive).
- **`daemon.py`** isn't listed under any single phase row in §14, but
  `cli.py`'s `proxy start` needs foreground orchestration + signal handling —
  exactly what §13's one-line description says the file is for. Built in
  Phase 7 alongside `cli.py`.
- **`--target`/`-tf`/`--target-regex`/`--target-all`: at least one is
  required.** §2's CLI table marks `--target` itself as "required (at least
  one)," but `-tf`/`--target-file`, `--target-regex`, or `--target-all`
  alone are all treated as satisfying that too (each is a legitimate
  standalone scope mechanism per §3.3/§3.4/§3.7). `-tf` entries are merged
  into `DaemonConfig.targets` in `cli.py` before `Daemon.__init__` runs its
  check, so the daemon itself never distinguishes the two sources.
- **Second-instance guard** (v0.2.0): `ControlServer.start()`
  (`recording/control.py`) checks whether an existing control socket file has
  something actually listening behind it before unlinking/rebinding — if so,
  raises `ConfigError` instead of silently stealing the running daemon's
  socket. `ProxyListener.start()` wraps a `--listen-address` port collision
  into `ConfigError` too, instead of a raw traceback. `Daemon.start()` checks
  the control socket before binding the listener, so the common case (same
  default `--listen-address` reused) surfaces the more specific
  "another secondeye daemon is already running" message. A stale socket file
  from an unclean shutdown is still reused normally.
- **RSA 2048** for both the CA and per-SNI leaf keys — not spec-mandated,
  chosen for simplicity/compatibility. Leaf certs include an explicit
  Authority Key Identifier (see testing philosophy above for why that
  matters).

## Explicit non-goals — do not implement these

`SPEC.md` §0 lists these as deliberate exclusions for v1, not oversights. An
agentic tool will "helpfully" reach for these — don't:

- GUI/DOM rendering capture (this is a wire-level HTTP proxy, not a browser
  automation tool — a CDP-based companion is an explicit *separate* v2 tool).
- WebSocket frame recording/analysis (frames pass through in scope,
  unrecorded).
- Redaction of any kind (full-fidelity capture is the point — see `SPEC.md`
  §0).
- Config file support (CLI flags only, no
  `~/.config/secondeye/config.toml`).
- Windows or macOS support (Linux only).
- Multi-session/nested capture support (one active capture, hard error
  otherwise).
- Remote/non-loopback binding (no override flag exists, by design).

## Where a v2 might go (explicitly out of scope for this repo, per SPEC.md)

- A CDP-based screenshot/DOM correlator, mentioned in `SPEC.md` §0 as a
  deliberately separate companion tool.
- `secondeye capture recover <path>` — reading a leftover JSONL buffer from a
  crashed daemon. `SPEC.md` §6.3 flags this as "a natural, cheap follow-on"
  but explicitly not required for v1.
