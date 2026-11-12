# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
