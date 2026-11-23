# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.0] - 2026-11-21

### Added
- **Examples on every help screen.** `secondeye --help` opens with the
  four-step first-run workflow; each subcommand carries one or two real
  invocations. Previously the only worked examples lived in `README.md`, which
  is not what an operator reads mid-engagement.
- **Grouped flags on `proxy start`.** Its thirteen flags were one
  undifferentiated list; they are now split into Scope, Upstream, Listener and
  output, and Logging, each with a line saying what the group decides.
- **Help renders through `ui.py`** like every other human-facing surface, in
  the same light-terminal-first palette — the 16 ANSI colours plus
  `bold`/`dim`, nothing absolute. `NO_COLOR`, `FORCE_COLOR` and a non-tty
  stream are honoured exactly as elsewhere, so piped and redirected help stays
  plain text.
- **Generated help blocks in `docs/CLI.md` for every subcommand.** `doctor`,
  `ca install`, `ca status`, `ca import-upstream`, `proxy stop` and
  `capture list`/`analyze`/`recover` had no generated block, so their help
  could drift with no test failing. Twenty examples are now checked, up from
  twelve.

### Changed
- **`proxy start` now requires exactly one of `--upstream-ca`,
  `--upstream-insecure` or `--no-upstream` at argument-parsing time.** The
  requirement was already enforced — it just wasn't documented anywhere, so
  `secondeye proxy start --target example.com` failed with an error `--help`
  gave no warning of. As a required mutually exclusive group it appears in the
  usage line and is rejected before the daemon starts.
- Informative metavars throughout: `--target DOMAIN`, `-tf FILE`,
  `--listen-address HOST:PORT`, `--cluster-window MS` and so on, in place of
  argparse's shouted `TARGET`/`TARGET_FILE`/`LISTEN_ADDRESS`.
- `proxy`, `capture` and `ca` each explain what the noun is for instead of
  printing a bare list of verbs; `capture` subcommands now say whether they
  need a running daemon.

### Fixed
- **`--no-upstream` combined with `--upstream-ca` is now rejected rather than
  silently ignoring the CA.** An operator could believe they had pinned the
  upstream leg while nothing was validating it. A trust flag that is quietly
  discarded is worse than one that is refused.
- **`-v` and `-q` together are now an error** instead of silently resolving in
  favour of `-v`.

## [1.3.0] - 2026-11-19

### Added
- **`secondeye doctor`** — one pass over the environment problems an operator
  otherwise meets one at a time, each looking like a different fault: CA
  missing or expired, state directory not `0700`, captures directory not
  writable, listen port taken, upstream unreachable or with no trust
  configured, `certutil` absent, shell completion inactive. Read-only; it
  never generates a CA. Exits non-zero only on a real failure — warnings
  alone exit 0.
- **`secondeye ca install`** — adds the CA to every Firefox and Chromium NSS
  profile it can find (distribution, Snap and Flatpak layouts, plus the shared
  `~/.pki/nssdb`) via `certutil`, trusted for TLS server certificates only.
  The system trust store is **printed, never written**: it needs `sudo`, and a
  security tool should not quietly write to the machine's root trust.
  `--print-only` changes nothing and prints every manual step (what to use when
  `certutil` isn't installed, which on most distributions it isn't);
  `--remove` undoes the NSS side; `--dry-run` lists what would change.
- **Upstream preflight on `proxy start`.** Unless `--no-upstream` is set, the
  upstream is TCP-probed before anything binds, and startup fails naming the
  address and offering `--no-upstream`. Previously a wrong or stale
  `--upstream-proxy` printed a successful banner and then failed every
  connection.
- **`--json`** on `proxy status`, `capture list` and `doctor`, for scripting.
  It bypasses the renderer entirely so the output stays byte-exact whether or
  not stdout looks like a terminal.
- `tls/ca.py` gains `load_ca_certificate()`, a strictly read-only CA reader.
  `load_or_create_ca()` both generates a CA and locks down the state
  directory, so a diagnostic using it would create key material as a side
  effect *and* silently fix the permission problem it was meant to report.

### Fixed
- **An over-long control socket path now fails with an explanation.** The path
  derives from `Path.home()`, and `AF_UNIX` caps it at 107 bytes, so an unusual
  or deeply nested `$HOME` produced a bare `OSError: AF_UNIX path too long`
  traceback naming neither the path nor the limit. Now a `ConfigError` giving
  both, plus the remedy.
- A race in the test suite's daemon fixture teardown, which stopped an
  already-stopping daemon and intermittently raised `ConnectionResetError`.

### Changed
- `SPEC.md` gains §4.7a (upstream preflight), §5.6 (`ca install`) and §5.7
  (`doctor`).
- README leads with a **topology chooser** covering all three wirings, including
  Burp → secondeye → target (Burp's upstream proxy pointed at `:8079` with
  `--no-upstream`), which was previously undocumented despite being a common
  setup. Each topology states which CA has to be trusted and which doesn't.

## [1.2.0] - 2026-11-18

### Added
- **`secondeye capture analyze <dir>`** — re-render `manifest.json` and
  `ANALYSIS.md` from an existing capture's `raw.har`. Captures were
  write-once, so every one stayed frozen at whichever renderer version
  produced it, which matters because the analysis signals arrived across
  v0.5.0, v0.6.0 and v0.7.0. Takes `--cluster-window` to re-cluster without
  re-recording. `raw.har` is never modified, and no daemon is required.
- **`secondeye capture recover <path>`** — rebuild a capture from the
  incremental JSONL buffer a crashed daemon leaves behind, writing the three
  files `capture stop` would have. Accepts a capture directory or the buffer
  file itself; `--keep-buffer` leaves it in place, `--name` overrides the name
  taken from the directory. A buffer carries entries only, so the recovered
  manifest records an empty scope and a window derived from the entries' own
  timestamps rather than inventing provenance it doesn't have.
- **`--captures-dir`** on `proxy start`, so captures can be written beside an
  engagement's notes instead of under the state directory. `capture list`,
  `analyze` and `recover` accept it too. The default is unchanged, so existing
  setups behave exactly as before.
- `manifest.json` gains a `findings` block tallying the *actionable* signals
  (debug pages, credential patterns, cookie-flag issues, CORS
  misconfigurations, ID-value reuse, legacy HTTP versions). Descriptive
  signals are deliberately excluded — they describe a capture rather than
  flagging something to look at, and counting them would make the total
  meaningless. `schema_version` is now `"1.1"`; the block is always present,
  zeroed when nothing was found.
- `capture stop` and the new commands report flow and finding counts, so "did
  this capture find anything?" is answerable without opening `ANALYSIS.md`.

### Changed
- **`secondeye capture list` reads the captures directory instead of the
  daemon's in-memory history.** It previously required a running daemon and
  could only see captures from the run that was still alive. It now works with
  no daemon, shows captures from previous runs, lists newest first, and marks
  the active capture when a daemon happens to be up. Columns are capture,
  requests, size, findings and start time; the capture path moved to a footer,
  because at 80 columns a path column either truncated — making it
  uncopyable — or crowded out every other column.
- The render pipeline moved to `analysis/pipeline.py`, now the only place a
  capture's three output files are written. `capture stop` is one caller of it
  rather than the implementation, so a capture flushed by the daemon and one
  re-rendered later cannot diverge.
- `SPEC.md` §6.5's captures path is documented as the default rather than a
  fixed location, and §6.2a describes revisiting a finished capture.

### Fixed
- **`--cluster-window`'s `--help` text described the wrong behaviour.** It
  claimed to control how "repeated near-identical requests (e.g. polling)" are
  collapsed, but polling deduplication keys off request-interval regularity
  and is not affected by this window at all. The window governs whether a
  request is grouped with the navigation that preceded it, which surfaces as
  the per-navigation "Assets loaded" summary. Corrected on both `proxy start`
  and `capture analyze`, and `SPEC.md` §11.3 now states the flag's scope
  explicitly. (The flag itself was fixed in v1.1.0, where it did nothing at
  all; this is the description catching up with it.)

## [1.1.0] - 2026-11-18

### Fixed
- **`--cluster-window` did nothing.** The flag was accepted, documented and
  threaded as far as `CaptureManager`, which stored it and never read it —
  `render_analysis_md()` always called `cluster_entries()` with the
  hardcoded 2000 ms default. Passing `--cluster-window 500` produced
  byte-identical output to `--cluster-window 5000`. The configured value now
  reaches the clustering pass, so it affects which static assets are
  collapsed into their navigation's cluster in `ANALYSIS.md`. The default
  (2000 ms) was duplicated across four modules and is now declared once as
  `analysis/cluster.py`'s `DEFAULT_CLUSTER_WINDOW_MS`.
- **Output written past a redirected stream.** Terminal output is now
  resolved against `sys.stdout`/`sys.stderr` at print time rather than at
  import time, so redirecting either stream after import works as expected.

### Added
- **`src/secondeye/ui.py`** — a single presentation layer, built on `rich`,
  through which all human-facing output now flows. `cli.py` is reduced to
  argparse plumbing plus control-socket calls: it builds a view dataclass
  and hands it over. Each renderer takes a fully-resolved view and only
  formats it, so a future `--json` can serialise the same dataclass instead
  of re-deriving the data.
- `FORCE_COLOR` is now honoured, so styling survives a pipe. `NO_COLOR`
  still wins, and is now treated per no-color.org as set-and-non-empty
  rather than merely set.

### Changed
- **All terminal output restyled.** The startup banner, `proxy status`,
  capture start/stop, `capture list` (now a table) and `ca status` are
  redesigned around an aligned label/value layout with a `●`/`○` recording
  marker. `capture list`'s output path folds rather than being truncated
  with an ellipsis, so it stays copyable.
- **Colour is chosen for light terminals first.** Output uses only the 16
  ANSI colours plus `bold`/`dim`, which the user's terminal theme resolves
  against its own background; previous output hardcoded values that assumed
  a dark background. Enforced structurally — `color_system="standard"` and
  `highlight=False` — and asserted in `tests/test_ui.py`.
- **`rich` moved from the `dev` extra to runtime dependencies.** It had been
  docs-only, with CI asserting it never reached the wheel; that assertion is
  now reversed for `rich` and re-pointed at the dev toolchain (`pytest`,
  `mypy`, `ruff`), which is a larger tree than `rich` ever was. `SPEC.md`
  §12 records this as a deliberate exception to the minimal-footprint rule,
  and `SPEC.md` gains §7.1 for the human-output contract.
- The README SVG hero now shows the program's real colour, since the
  generator's long-standing `FORCE_COLOR=1` is finally honoured.

## [1.0.4] - 2026-11-17

### Fixed
- **HTTP/1.0 traffic no longer kills the connection.** Any exchange where
  either side spoke HTTP/1.0 died with
  `h11._util.LocalProtocolError: I only send HTTP/1.1`, dropped the
  connection, leaked the upstream socket, and — worst of all — recorded
  nothing, leaving a silent hole in the capture. h11 parses HTTP/1.0 but
  refuses to serialize it, and secondeye was copying the peer's version
  verbatim onto the events it sent. Both legs are now re-framed as HTTP/1.1
  on the wire: a destination answering HTTP/1.0 (appliances, embedded and
  aged stacks, anything built on Python's `BaseHTTPRequestHandler`) and a
  client sending an HTTP/1.0 request are both relayed and recorded
  correctly. An HTTP/1.0 request with no `Host` header — legal at 1.0,
  rejected by h11 at 1.1 — gets one synthesized from the known destination.

  The capture keeps full fidelity (`SPEC.md` §0): `raw.har` still records
  the true `"httpVersion": "HTTP/1.0"` on whichever leg sent it. Only the
  bytes on the wire are re-framed. One deliberate limitation: the client
  sees `HTTP/1.1` in the status line even when the destination said
  `HTTP/1.0`, because h11 cannot write a 1.0 status line. The HAR and
  `ANALYSIS.md` both show the truth.
- A protocol error while forwarding a request now degrades to a logged
  `502` with the upstream connection closed, instead of escaping as an
  unhandled traceback — `h11.LocalProtocolError` is not a subclass of
  `h11.RemoteProtocolError`, so the existing guards in `proxy/intercept.py`
  and `proxy/plain_http.py` never caught it.

### Added
- `ANALYSIS.md`'s `## Capture Signals` section now reports **Legacy HTTP
  versions** — a count of pre-HTTP/1.1 responses and the first entry index
  for each version. A destination still speaking HTTP/1.0 is a mild finding
  in its own right.

## [1.0.3] - 2026-11-12

### Added
- **The README now shows what the tool actually produces.** New generated
  examples: an `ANALYSIS.md` excerpt (summary, auth mechanisms, status
  rollup, parameter names, security-header audit, cookie-flag issues), the
  matching `manifest.json`, a terminal SVG of a full capture session, and
  `proxy status` / capture-summary output with real request counts.
- `docs/CLI.md` — a complete flag reference for every subcommand, captured
  from the real argument parser. Replaces the hand-written five-flag list the
  README used to carry, which nothing verified.
- `docs/examples/ANALYSIS.sample.md` — a complete worked `ANALYSIS.md`, so
  the format can be judged before running a capture.
- `scripts/generate_doc_examples.py` plus `tests/test_doc_examples.py`: every
  command output and help block in the docs is captured from the real
  renderers and verified on every test run, so documentation can no longer
  drift from the program without the suite going red. Run
  `python scripts/generate_doc_examples.py` after changing anything a reader
  sees.
- `src/secondeye/py.typed` — the package now advertises its inline type hints
  (PEP 561), so `mypy` checks downstream code against them instead of
  treating `secondeye` as untyped.

### Changed
- `rich` added to the `dev` extra as docs tooling, used only to render the
  README's terminal SVG. It is deliberately not a runtime dependency: nothing
  in the package imports it, and the `test-package` CI job now fails if it
  ever appears alongside the installed wheel.
- Registered the `slow` and `integration` pytest markers.

## [1.0.2] - 2026-11-12

### Added
- Security scanning (`.github/workflows/security.yml`): CodeQL with the
  `security-extended` query suite as a blocking check, plus a
  soft-failed `pip-audit` dependency audit that uploads a report. Both
  run on every push and pull request and on a weekly Monday cron, so a
  newly-published advisory against an unchanged dependency surfaces
  without needing a commit to trigger it.
- Dependency automation (`.github/dependabot.yml`): monthly `pip` and
  `github-actions` updates targeting `develop`. The dev toolchain
  (pytest, ruff, mypy) batches into one pull request; the four runtime
  dependencies stay individual, since each needs its own smoke test.
- Packaging verification (the `test-package` job in
  `.github/workflows/test.yml`): builds the wheel, asserts the
  `secondeye` package is actually inside it, installs from that
  artifact into a clean environment, and smoke-tests `secondeye
  --version` and `--help`. Catches the class of bug where the test
  suite passes but the installed artifact is broken.

### Changed
- **Contributions now target `develop`, not `main`.** `main` is the
  release branch, updated only by a `develop` → `main` pull request. If
  you have an open pull request against `main`, retarget it. CI gates
  both branches, so `develop` is checked before a release PR is ever
  opened. See `CONTRIBUTING.md`'s new "Branching" section.
- `CHANGELOG.md` headings now use Keep a Changelog's bracketed form
  (`## [X.Y.Z] - YYYY-MM-DD`, `## [Unreleased]`). Release notes are
  extracted by the new `scripts/extract_changelog.py`, which matches on
  that exact form — a version bump whose changelog heading is malformed
  or undated now fails the release with a message listing the versions
  it did find.
- CI split from the single `ci.yml` into `test.yml` (the four gates,
  now also type-checking `scripts/`) and `release.yml`. The release
  trigger is narrower and better-validated: it fires only on a `main`
  push that touches `pyproject.toml`, diffs the version against the
  previous commit, rejects anything that isn't plain semver `X.Y.Z`, and
  attaches the built sdist and wheel to the GitHub Release. The previous
  job's idempotency guard is retained, so a re-run won't double-tag.
  Still no PyPI publish — that remains deliberate.

### Fixed
- `raw.har`'s `log.creator.version` reported `1.0.1` regardless of the
  version actually installed: `recording/manager.py` carried a hardcoded
  literal that nothing updated on a version bump. It now resolves from
  the installed distribution's metadata via the new
  `secondeye.__version__`, which `secondeye --version` also uses, making
  `pyproject.toml`'s `project.version` the single source of truth.
  `tests/test_version.py` fails if a version literal drifts back in.

## [1.0.1] - 2026-09-23

### Added
- A `tag-release` CI job (`.github/workflows/ci.yml`) that auto-tags and
  publishes a GitHub Release whenever `pyproject.toml`'s `version` is
  bumped on `main` and the four gates pass — release notes are pulled
  verbatim from this file's matching `## X.Y.Z - YYYY-MM-DD` section.
  Idempotent (skips if that version's tag already exists), so it's safe
  to run on every push regardless of whether that push touched the
  version. Replaces manual tagging going forward.

## [1.0.0] - 2026-09-23

### Added
- `pyproject.toml` metadata completion: `readme`, `authors`,
  `[project.urls]` (Homepage/Repository/Issues), `classifiers`, and
  `keywords`, ahead of the first public v1.0.0 announcement.
- v1.0.0 readiness pass: the state directory
  (`~/.local/state/secondeye`) is now locked to `0700` on every daemon
  start, transitively protecting the CA, all captured credentials/tokens,
  and the control socket — covering every entry point that touches it
  (the daemon, `ca export`, `ca status`), not just the daemon path. A
  warning is now logged before a partially-corrupted CA (missing its
  cert or key file, but not both) is silently regenerated. GitHub
  Actions CI (`.github/workflows/ci.yml`) now runs `ruff check`,
  `ruff format --check`, `mypy --strict`, and `pytest` on every push to
  `main` and on every pull request, across Python 3.11/3.12/3.13. `ruff`'s lint coverage was
  expanded with the `PTH` (pathlib enforcement) and `S` (bandit
  security) rule families. Test coverage closed for several previously-
  untested paths: scope-matcher edge cases (IP-literal targets, null-byte
  handling, a bare `"*"` target), the default `--upstream-proxy` CLI
  wiring path, `manifest.json`'s redirect-chain/polling-group
  serialization, and three of this codebase's four crash-isolation
  safety nets.
- `SECURITY.md`, `CONTRIBUTING.md`, and an optional
  `.pre-commit-config.yaml` mirroring the four CI gates as local git
  hooks (install with `pipx install pre-commit && pre-commit install`).

### Changed
- Test-coverage floor raised from 80% to 90%, reflecting the coverage
  level the readiness pass's test additions actually reached (~95%).
- Every CLI subcommand now shows a one-line description both in its
  parent's `--help` listing and in its own `--help` output. The
  scope-required startup error now mentions `--target-file` as a
  satisfying alternative. `--upstream-ca`/`--upstream-insecure`/
  `--no-upstream` are now validated before any CA material is generated
  or the `--upstream-insecure` warning is logged, so an invalid
  combination fails immediately instead of generating a CA first.

### Removed
- The unused `MalformedClientHelloError` exception class — never raised
  anywhere; malformed ClientHellos are handled via a returned
  `SniOutcome.MALFORMED` result instead, so a single bad connection can
  never crash the daemon.

### Fixed
- A stale-control-socket-recovery test that didn't actually exercise the
  recovery code path it claimed to.

## [0.7.0] - 2026-09-21

### Added
- ANALYSIS.md Phase 3 heavier signals: framework debug/error-page
  detection (fixed Django/Flask-Werkzeug/Rails/ASP.NET/PHP signature
  matches); credential-pattern detection (AWS access keys, PEM
  private-key headers, JWT-shaped strings in response bodies, rendered
  unredacted per this tool's no-redaction design stance); a broadened
  `## Capture Signals` audit (`X-XSS-Protection`/`Referrer-Policy`/
  `Permissions-Policy` header presence, a CORS misconfiguration check, a
  `Set-Cookie` flag audit); cross-request ID-value reuse detection; and
  a capture-wide Mermaid `## Sequence Diagram` section.

## [0.6.0] - 2026-09-21

### Added
- ANALYSIS.md Phase 2 orientation block: a classification-confidence
  marker (`*(guessed)*` on heuristically-classified flows) and a new
  `## Summary` section (endpoints touched, auth mechanisms observed, a
  status-code rollup, parameter names observed — never values).

## [0.5.0] - 2026-09-21

### Added
- ANALYSIS.md Phase 1 derived signals: timing/size outlier notes,
  security-header posture and stack-fingerprint hints in a new
  `## Capture Signals` section, a linked `## Contents` table of
  contents, and state-changing-method highlighting.

## [0.4.0] - 2026-09-17

### Added
- `secondeye --version`/`-V`; `proxy status` reports a live request
  count for the active capture; `secondeye ca status` (read-only,
  never generates a CA as a side effect); a first-run CA-creation note
  on `ca export` and in the `proxy start` banner.

### Fixed
- Install docs corrected to `pipx install
  git+https://github.com/ridgebackinfosec/second-eye.git` (never
  published to PyPI, intentionally).

## [0.3.2] - 2026-09-17

### Changed
- Updated the README hero banner artwork.

## [0.3.1] - 2026-09-17

### Added
- A hero banner image to the README.

## [0.3.0] - 2026-09-16

### Added
- A `proxy start` startup banner (scope/listen/upstream summary + next
  step); colorized `✓`/`✗` output (respecting `NO_COLOR` and non-tty
  streams); `argcomplete`-based shell completion.

## [0.2.0] - 2026-09-16

### Added
- A second-instance guard (refuses to steal a running daemon's control
  socket); full `--help` text on every flag.

### Changed
- Renamed `--listen`→`--listen-address`, `--upstream`→`--upstream-proxy`,
  `--capture-all`→`--target-all` (the latter renamed all the way through
  internal code and `manifest.json`'s schema key).

## [0.1.2] - 2026-09-16

### Added
- `-tf`/`--target-file`: a line-delimited target list, an alternative to
  repeating `--target`.

## [0.1.1] - 2026-09-16

### Changed
- Moved architecture flow diagrams to `docs/ARCHITECTURE.md`.

## [0.1.0] - 2026-09-16

### Added
- Initial release: all 7 core build phases — scope matching, TLS CA/leaf
  certificate generation, SNI-based routing, the CONNECT/plain-HTTP
  listener, TLS interception and Burp/ZAP upstream chaining, HAR
  capture, and the `analysis/`/`recording/`/`cli.py` pipeline producing
  `raw.har`, `manifest.json`, and `ANALYSIS.md` per capture.
