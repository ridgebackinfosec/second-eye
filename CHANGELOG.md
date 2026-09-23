# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added
- v1.0.0 readiness pass, in progress: the state directory
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

## 0.7.0 - 2026-09-21

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

## 0.6.0 - 2026-09-21

### Added
- ANALYSIS.md Phase 2 orientation block: a classification-confidence
  marker (`*(guessed)*` on heuristically-classified flows) and a new
  `## Summary` section (endpoints touched, auth mechanisms observed, a
  status-code rollup, parameter names observed — never values).

## 0.5.0 - 2026-09-21

### Added
- ANALYSIS.md Phase 1 derived signals: timing/size outlier notes,
  security-header posture and stack-fingerprint hints in a new
  `## Capture Signals` section, a linked `## Contents` table of
  contents, and state-changing-method highlighting.

## 0.4.0 - 2026-09-17

### Added
- `secondeye --version`/`-V`; `proxy status` reports a live request
  count for the active capture; `secondeye ca status` (read-only,
  never generates a CA as a side effect); a first-run CA-creation note
  on `ca export` and in the `proxy start` banner.

### Fixed
- Install docs corrected to `pipx install
  git+https://github.com/ridgebackinfosec/second-eye.git` (never
  published to PyPI, intentionally).

## 0.3.2 - 2026-09-17

### Changed
- Updated the README hero banner artwork.

## 0.3.1 - 2026-09-17

### Added
- A hero banner image to the README.

## 0.3.0 - 2026-09-16

### Added
- A `proxy start` startup banner (scope/listen/upstream summary + next
  step); colorized `✓`/`✗` output (respecting `NO_COLOR` and non-tty
  streams); `argcomplete`-based shell completion.

## 0.2.0 - 2026-09-16

### Added
- A second-instance guard (refuses to steal a running daemon's control
  socket); full `--help` text on every flag.

### Changed
- Renamed `--listen`→`--listen-address`, `--upstream`→`--upstream-proxy`,
  `--capture-all`→`--target-all` (the latter renamed all the way through
  internal code and `manifest.json`'s schema key).

## 0.1.2 - 2026-09-16

### Added
- `-tf`/`--target-file`: a line-delimited target list, an alternative to
  repeating `--target`.

## 0.1.1 - 2026-09-16

### Changed
- Moved architecture flow diagrams to `docs/ARCHITECTURE.md`.

## 0.1.0 - 2026-09-16

### Added
- Initial release: all 7 core build phases — scope matching, TLS CA/leaf
  certificate generation, SNI-based routing, the CONNECT/plain-HTTP
  listener, TLS interception and Burp/ZAP upstream chaining, HAR
  capture, and the `analysis/`/`recording/`/`cli.py` pipeline producing
  `raw.har`, `manifest.json`, and `ANALYSIS.md` per capture.
