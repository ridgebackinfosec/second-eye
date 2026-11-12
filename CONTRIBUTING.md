# Contributing to secondeye

## Development setup

Requires Python 3.11 or newer (`pyproject.toml`'s `requires-python`
floor).

```sh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## The four gates

Every change must pass all four of these, clean, before it's considered
done — this is the same bar the project has held since it was first
built, and the same one CI (`.github/workflows/test.yml`) now enforces on
every push and pull request against `main` *and* `develop`:

```sh
pytest -q                            # full test suite, coverage enforced (floor: 90%)
ruff check .                         # lint
ruff format --check .                # formatting
mypy --strict src/secondeye scripts  # type check
```

Run `ruff format .` (without `--check`) to auto-fix formatting issues
before committing.

An optional `.pre-commit-config.yaml` at the repo root mirrors these
same four gates as local git hooks — install with `pipx install
pre-commit && pre-commit install`. It runs whatever `ruff`/`mypy`/
`pytest` are on `PATH`, so activate this repo's `.venv` (or otherwise
have the dev extras installed) before committing.

Two more workflows run alongside it:
`.github/workflows/security.yml` (CodeQL as a blocking check; `pip-audit`
soft-failed, since a new advisory against a transitive dependency usually
can't be fixed in whatever pull request happens to be open) and
`.github/workflows/release.yml` (see below).

## Branching

- **`develop` is where work lands.** Branch from it, open pull requests
  against it.
- **`main` is the release branch.** It is only ever updated by a
  `develop` → `main` pull request; nothing is pushed to it directly, and
  tags are never created by hand.

## Releases

A push to `main` that changes `version` in `pyproject.toml` is
automatically tagged and published as a GitHub Release
(`.github/workflows/release.yml`). The version bump *is* the release
signal — there's no tag trigger and no manual dispatch. The job validates
that the new version is plain semver (`X.Y.Z`, no `v` prefix and no
pre-release suffix), builds the sdist and wheel, and attaches them to the
release. Nothing is published to PyPI; that's intentional (install is
`pipx install git+https://github.com/ridgebackinfosec/second-eye.git`).

Release notes are pulled verbatim from `CHANGELOG.md`'s matching
`## [X.Y.Z] - YYYY-MM-DD` section by `scripts/extract_changelog.py` — so a
version bump without a matching `CHANGELOG.md` entry (or with the date
missing from the heading) fails that job loudly rather than publishing an
empty release. Bumping the version and adding its `CHANGELOG.md` entry in
the same change (already asked of every contributor above) is what makes
this automatic.

The version is declared in exactly one place, `pyproject.toml`'s
`project.version`. Everything that reports a version reads it from the
installed distribution's metadata via `secondeye.__version__` — don't add
a version literal anywhere else; `tests/test_version.py` fails if one
drifts in.

## Documentation examples are generated

Every command output, terminal screen and CLI help block in `README.md` and
`docs/` is captured from the real code by
`scripts/generate_doc_examples.py` — never hand-written, never a screenshot.
Hand-pasted output rots silently: nothing fails when it drifts, so it stays
wrong until someone follows a README that no longer matches the program.

```sh
python scripts/generate_doc_examples.py              # regenerate everything
python scripts/generate_doc_examples.py --check      # non-zero on drift (what CI runs)
python scripts/generate_doc_examples.py --only NAME  # iterate on one example
```

**Never hand-edit between `<!-- BEGIN GENERATED: name -->` and
`<!-- END GENERATED: name -->`.** Change the renderer, or the capture function
in the generator, and re-run it. The prose around the markers is hand-owned and
safe to edit. `tests/test_doc_examples.py` fails if the committed output is
stale, and names the command that fixes it.

If you change anything a reader sees — a flag's help text, the startup banner,
`ANALYSIS.md`'s layout — regenerate in the same commit. A dirty tree after
regenerating means the docs were about to ship stale; commit the regenerated
output with your change rather than reverting it.

Two things the examples depend on:

- `tests/fixtures/demo_capture/raw.har`, a synthetic capture that the
  `ANALYSIS.md` and `manifest.json` examples are rendered from. Its
  credential-shaped values are deliberately obvious fakes, because this tool
  renders credential findings **unredacted** by design (`SPEC.md` §0) — a
  realistic-looking token in the fixture would appear verbatim in the
  committed README.
- `rich`, in the `dev` extra only. It is used solely to wrap a captured
  terminal session as an SVG. Nothing under `src/secondeye` imports it, the
  program's own output is plain `print()`, and the `test-package` CI job
  asserts it never reaches the built wheel. Any future docs-only library
  follows the same rule.

## Testing conventions

This repo overwhelmingly tests against **real sockets, real TLS
handshakes, and real subprocesses** rather than mocks, even where mocking
would be faster to write — this has repeatedly caught real bugs mocks
would have hidden (see `CLAUDE.md`'s "Testing philosophy" section for
specific examples). New tests for proxy/TLS/capture code should follow
the same pattern: a real loopback `asyncio.start_server` and a real
client, not `unittest.mock`. Write the test first, watch it fail for the
right reason, then implement (TDD) — this was used throughout the
original build and every batch since.

## Areas that need extra scrutiny

Two areas are safety-critical to this tool's core promise ("never
intercept out-of-scope traffic," "never expose a leaf certificate for
the wrong host") and get closer review than the rest of the codebase:

- **`scope/matcher.py`** and anything touching how a hostname/SNI value
  is evaluated against `--target`/`--target-regex`/`--target-all`.
- **`tls/ca.py`/`tls/leaf.py`** and anything touching certificate
  generation, trust chain handling, or where key material is written to
  disk.

A change in either area should include tests for the specific edge case
it addresses, not just the happy path — see `tests/test_scope_matcher.py`
for the established style (exact-match, subdomain, wildcard, regex,
IDN/punycode normalization, and adversarial-input cases all get their
own test classes).

## Conventions

See `CLAUDE.md`'s "Conventions actually enforced here" section for the
full list (type hints everywhere, `pathlib.Path` never `os.path`,
dataclasses over raw dicts, every exception a `SecondEyeError` subclass,
Google-style docstrings, `__all__` in every module with a public
surface). These are enforced by `mypy --strict`/`ruff check` where
possible, and by review where not.

## Submitting a change

Fork the repo, create a branch off `develop`, and open a pull request
against `develop` (not `main` — see "Branching" above).
CI runs the four gates automatically on every pull request. If your
change is user-visible, add an entry under `## [Unreleased]` in
`CHANGELOG.md` — see its existing entries for the expected level of
detail (a sentence or two from a user's perspective, not a commit-message
dump).

## Commit messages

Describe the *why*, not just the *what* — the diff already shows what
changed. Keep the subject line under ~70 characters.
