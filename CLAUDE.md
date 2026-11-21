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
`capture/buffer.py` → `daemon.py`, `cli.py`, `README.md`. v1.0.0
shipped 2026-09-23 — see `CHANGELOG.md` for the full readiness-pass
changelog.

Manual testing has passed. Coverage sits around 95% (floor is 90%, enforced via
`pyproject.toml`'s `--cov-fail-under=90`).

**Branching: work lands on `develop`; `main` is the release branch.** Never
push, commit, or merge to `main` — it is only updated by a `develop` → `main`
pull request, and tags are never created by hand (Actions owns tagging).

### `bcp` — never bump, commit, or push unless told

**Do not bump the version, commit, or push unless the user asks in that
turn.** `bcp` is the user's shorthand authorising exactly those three things,
and nothing weaker authorises any of them. Finish the code, tests and docs,
report that the work is ready, and stop.

This is a standing instruction, stated outright on 2026-11-18 after the
v1.1.0 work was committed and pushed unprompted. Two specific traps, both of
which have actually caught an agent here:

- **Approving a plan is not authorisation to execute its release step.** A
  plan saying work "lands on `develop`" describes the eventual destination,
  not permission to push now.
- **Choosing a release option from a prompt is not authorisation either.** On
  2026-11-17 the user interrupted with "I control the `bcp` process. not you"
  during a `gh pr create`, having earlier picked "Bump to 1.0.4 + PR to main"
  from an options list in that same session.

While no `bcp` has been given, put user-visible changes under `CHANGELOG.md`'s
`## [Unreleased]` heading and leave `pyproject.toml`'s `version` alone.

**On `bcp`:** bump `pyproject.toml`'s `version`; convert `## [Unreleased]` to
a dated `## [X.Y.Z] - YYYY-MM-DD` heading; re-run `pip install -e ".[dev]"`
(or `tests/test_version.py` fails on stale editable-install metadata);
re-run `python scripts/generate_doc_examples.py` (the version appears in
generated output); confirm all four gates; commit; push to `develop`; **stop
there**. No `gh pr create`, no merge, no tag — `release.yml` owns tagging once
the bump reaches `main`.

CI is four files:

- `.github/workflows/test.yml` — all four gates (`ruff check`,
  `ruff format --check`, `mypy --strict src/secondeye scripts`, `pytest`)
  across Python 3.11/3.12/3.13, plus a `test-package` job that builds the
  wheel, installs from it, and smoke-tests `secondeye --version`/`--help`.
  Runs on push and PR against both `main` and `develop`.
- `.github/workflows/release.yml` — fires on a push to `main` that touches
  `pyproject.toml`, diffs the version against `HEAD^`, validates plain
  semver, extracts release notes via `scripts/extract_changelog.py`, builds,
  tags `vX.Y.Z`, and publishes a GitHub Release with the artifacts attached.
  No PyPI publish, by design.
- `.github/workflows/security.yml` — CodeQL (`security-extended`) as a hard
  gate; `pip-audit` soft-failed with a report artifact; weekly Monday cron.
- `.github/dependabot.yml` — monthly `pip` and `github-actions` updates
  targeting `develop`, dev toolchain grouped, runtime deps individual.

An optional `.pre-commit-config.yaml` mirrors the same four gates as local
git hooks (see `CONTRIBUTING.md`).

**Documentation examples are generated, not written.** Every command output,
terminal screen and CLI help block in `README.md` and `docs/` is captured from
the real renderers by `scripts/generate_doc_examples.py` and lives between
`<!-- BEGIN GENERATED: name -->` / `<!-- END GENERATED: name -->` markers.
`tests/test_doc_examples.py` fails when the committed output is stale. Twelve
examples, in two tiers: fixture-driven ones (`ANALYSIS.md`, `manifest.json`,
CLI help) that are pure functions over
`tests/fixtures/demo_capture/raw.har`, and live ones (startup banner,
`proxy status`, capture summary, the SVG hero) that drive a real daemon in a
throwaway `HOME` against a local origin on pinned ports. Since v1.1.0 `rich` is
a **runtime** dependency (`src/secondeye/ui.py`), so the `test-package` CI job
asserts the reverse of what it used to: that `rich` *is* installed with the
wheel and `secondeye.ui` imports, while the dev toolchain (`pytest`, `mypy`,
`ruff`) is not. The generator forces colour through its pipe with
`FORCE_COLOR=1`, which `ui.py` honours, so the SVG hero now shows real program
colour; the text examples strip ANSI back out. Masks in the generator
(`_MASKS`) keep live timestamps stable — a style change *inside* a masked
phrase would inject an escape sequence mid-match and silently break drift
detection, which is why `proxy status` renders `since HH:MM:SS` as one styled
segment.

`CHANGELOG.md` uses Keep a Changelog's bracketed headings
(`## [X.Y.Z] - YYYY-MM-DD`, `## [Unreleased]`) — `scripts/extract_changelog.py`
matches on that exact form, date included, so a release fails loudly if a
heading is malformed.

**The version is declared in exactly one place**: `pyproject.toml`'s
`project.version`. `src/secondeye/__init__.py` resolves it at runtime from
the installed distribution metadata as `__version__`; `cli.py`'s `_VERSION`
and `analysis/pipeline.py` (which stamps every `raw.har`'s
`log.creator.version`) both read it from there. Never add a version literal
anywhere else — `tests/test_version.py` fails if one drifts in, and it now
asserts that guarantee by reading a real `raw.har` rather than by comparing a
module constant, so moving the writer again can't silently stop covering it.

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
colorized `✓`/`✗` output (then `_green`/`_red` in `cli.py`, respecting
`NO_COLOR` and non-tty streams; superseded by `ui.py` in v1.1.0); and
`argcomplete`-based shell completion (the project's first non-load-bearing
dependency). Usability batch (v0.4.0):
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
"Target" lanes). Terminal UI pass (v1.1.0): `src/secondeye/ui.py`, a `rich`
presentation layer every human-facing surface goes through, with colour
chosen **light-terminal-first** (see the non-goals below); `rich` promoted
from `dev` extra to runtime dependency; `FORCE_COLOR` honoured; and
`--cluster-window`, which had been accepted and documented but inert, wired
through to `cluster_entries()` with its default consolidated as
`analysis/cluster.py`'s `DEFAULT_CLUSTER_WINDOW_MS`. Capture-lifecycle pass
(v1.2.0): `analysis/pipeline.py` and `capture/store.py` (see the module
boundaries below); `capture analyze` (re-render an existing capture, so one
recorded under an older renderer isn't frozen there) and `capture recover`
(rebuild from a crashed daemon's leftover JSONL buffer), both daemon-free;
`capture list` reading the captures directory instead of the daemon's
in-memory history, so it survives the daemon exiting; `--captures-dir`
(`SPEC.md` §6.5's path is now the default, not fixed); a `findings` block in
`manifest.json` counting only *actionable* signals (`schema_version` →
`"1.1"`); and a correction to `--cluster-window`'s `--help`, which described
polling dedup — a thing the window does not affect at all (`SPEC.md` §11.3). First-run
pass (v1.3.0): `secondeye doctor` (`doctor.py`) collecting the environment
failures an operator otherwise meets one at a time; `secondeye ca install`
(`tls/trust.py`) automating the NSS half of trust-store setup while
**printing, never running**, the sudo commands for the system store;
an upstream TCP preflight on `proxy start` so a wrong `--upstream-proxy`
fails at startup instead of on every connection; `--json` on `proxy
status`/`capture list`/`doctor`; a clear error for a control-socket path
exceeding AF_UNIX's 107-byte limit; and a README topology chooser covering
all three wirings, including Burp → secondeye → target. CLI help pass
(v1.4.0): `cli.py`'s `SecondEyeParser` overrides `format_help()` and
renders through `ui.py`'s new `help_screen()` — chosen over a
`formatter_class` because argparse sizes its help column from raw string
length, so an ANSI-injecting formatter corrupts its own alignment, and
because `-h`, `print_help()` and the doc generator all route through
`format_help()`. All wrapping (usage line included, synthesised at
`_UNBOUNDED_WIDTH` and re-wrapped here) lives in `ui.py`; examples are
deliberately *not* wrapped, since a broken command line looks runnable and
isn't. `proxy start`'s flags are grouped, and the three upstream-trust flags
are now a **required mutually exclusive group** — the requirement was always
enforced in `proxy/upstream.py` but appeared in no help text, and
`--no-upstream --upstream-ca x.pem` used to be accepted with the CA silently
ignored. `docs/CLI.md` now generates a block for all 14 subcommands (was 6).

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
├── tls/trust.py          # NSS trust-store install for `ca install` (certutil)
├── proxy/
│   ├── sni.py             # ClientHello buffer-and-parse (no true MSG_PEEK in asyncio)
│   ├── splice.py          # blind bidirectional relay, out-of-scope path
│   ├── listener.py        # CONNECT/plain-HTTP entrypoint, loopback+max-conn enforcement
│   ├── upstream.py        # Burp/ZAP CONNECT-chaining vs --no-upstream direct connect
│   ├── intercept.py       # TLS termination (ssl.MemoryBIO) + HTTP/1.1, in-scope path
│   ├── plain_http.py      # absolute-URI (non-CONNECT) in-scope path
│   └── _http_cycle.py     # h11 request/response cycle shared by intercept+plain_http
├── ui.py                 # rich presentation layer; ALL human output goes through it
├── doctor.py             # read-only environment checks behind `secondeye doctor`
├── capture/{har,buffer}.py            # HAR entry construction; incremental JSONL buffer
├── capture/store.py                   # reading finished captures back off disk
├── analysis/{classify,cluster,manifest,render,signals}.py  # the analysis passes
├── analysis/pipeline.py               # the one entries+metadata → three-files path
└── recording/{manager,control}.py     # capture lifecycle state machine + control socket
```

Module boundaries are deliberate (see `SPEC.md` §13's rationale) — `proxy/`
doesn't know about HAR/analysis, `recording/control.py` is transport-only
(business logic lives in `manager.py`), `tls/ca.py` (generate-once) and
`tls/leaf.py` (generate-per-SNI, cached) are split because their lifecycles
differ.

Two boundaries added in v1.2.0 are worth respecting for the same reason:

- **`analysis/pipeline.py` is the only place that writes a capture's three
  output files.** `capture stop`, `capture analyze` and `capture recover` are
  all callers. Don't re-inline the
  `classify_entries`→`build_flows`→`build_manifest`/`render_analysis_md`
  sequence anywhere else — that is exactly what made captures
  un-re-renderable before, and a second copy lets a flushed capture and a
  re-rendered one diverge.
- **Read-only means read-only in diagnostics.** `doctor.py` and `ca install`
  must never create a CA or change permissions as a side effect of being run.
  That is why `tls/ca.py` has `load_ca_certificate()` alongside
  `load_or_create_ca()`: the latter both generates key material *and* calls
  `_lock_down_state_dir()`, so a diagnostic built on it would silently *fix*
  the 0700 problem it exists to report. Reach for the read-only loader in
  anything diagnostic.
- **`capture/store.py` owns reading captures off disk**, and splits its error
  policy on purpose: `load_capture()` *raises* when `manifest.json` is missing
  (guessing a capture's name and scope would fabricate provenance into the
  re-rendered output), while `discover_captures()` *skips* anything unparseable
  (one corrupt capture must not make `capture list` useless for the rest).

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
  doesn't have a natural home for them. (Since the v1.0.0 readiness pass,
  `exceptions.py` also has one *fewer* class than §8's list — see the
  last bullet in this section.)
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
- **`MalformedClientHelloError` was removed** (v1.0.0 readiness pass).
  `SPEC.md` §8 lists it as part of the "required" custom exception
  hierarchy, but it was never raised anywhere — confirmed unused since
  the initial commit, across every version bump since. §8's actual
  behavioral requirement ("Malformed/non-TLS ClientHello → drop that
  connection only, `WARNING`") is fully met a different way:
  `proxy/sni.py`'s `parse_client_hello()` returns a
  `ClientHelloParseResult` with `outcome=SniOutcome.MALFORMED` instead of
  raising, by design (see that module's own docstring — a single
  malformed connection can never take down the daemon this way), and
  `proxy/listener.py` logs exactly the required `WARNING` and drops the
  connection when it sees that outcome. Spec intent honored, literal
  mechanism intentionally different — same shape as every other
  deviation in this list.

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

Three CI-specific ones, for the same reason — an agentic tool porting a
generic workflow template will reach for all three:

- **`windows-latest`/`macos-latest` matrix cells in `test.yml`.** Linux
  only; a matrix cell for either would assert support that was never
  intended.
- **`continue-on-error` on any of the four gates.** They have been hard
  gates since the first commit and the tree is clean against all of them.
  A soft-failed gate reports green for something that doesn't work. (The
  two soft-failed checks that *do* exist — `pip-audit` in `security.yml` —
  each carry an in-file comment saying why and what would make them hard.)
- **Hand-editing anything between `BEGIN GENERATED` / `END GENERATED`
  markers.** The obvious "fix" for a stale doc block is to type the correct
  text into it; that is always wrong here. The block is overwritten on the
  next generator run and the drift test will flag it. Change the renderer or
  the capture function in `scripts/generate_doc_examples.py`, then re-run
  `python scripts/generate_doc_examples.py`.
- **Changing the program's output in order to improve the docs.** This rule
  used to read "never make `rich` a runtime dependency," on the grounds that
  routing output through `rich` to get prettier docs would change what users
  see in order to change what readers see. As of v1.1.0 `rich` *is* a runtime
  dependency and `src/secondeye/ui.py` renders every human-facing surface
  with it — but that was driven by operator UX on a light terminal, not by
  the docs, and the README SVG being nicer is now a by-product rather than a
  motive. The original principle survives in that narrower form: the
  direction of causation matters, and a docs-only library still must never
  be imported from `src/secondeye` (`.github/workflows/test.yml` asserts the
  dev toolchain never reaches the wheel, and that `rich` does).
- **Hardcoding colour values in terminal output.** `ui.py` uses only the 16
  ANSI colours plus `bold`/`dim`, which the user's own terminal theme
  resolves against the user's own background. A 256-colour `greyNN`,
  truecolor hex, or literal `white`/`black` assumes a background and breaks
  on the opposite theme — `bold white` is invisible on a light terminal, and
  **light terminals are the primary target**. `tests/test_ui.py` enforces
  this structurally; `color_system="standard"` and `highlight=False` on the
  Consoles are what make it hold even for styles rich picks itself.
- **A bandit job in `security.yml`.** Bandit's checks already run as a
  *hard* gate via ruff's `S` rule family over the whole tree, with every
  suppression justified in `pyproject.toml`. A second soft-failed bandit
  pass would be strictly weaker and duplicate its findings as
  non-blocking noise. `security.yml` says this in a comment; don't delete
  it and "fill the gap."

## Where a v2 might go (explicitly out of scope for this repo, per SPEC.md)

- A CDP-based screenshot/DOM correlator, mentioned in `SPEC.md` §0 as a
  deliberately separate companion tool.

(`secondeye capture recover <path>` used to be listed here. It shipped in
v1.2.0 alongside `capture analyze` and a disk-backed `capture list` — see
`SPEC.md` §6.2a.)
