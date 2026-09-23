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
built, and the same one CI (`.github/workflows/ci.yml`) now enforces on
every push to `main` and on every pull request:

```sh
pytest -q                       # full test suite, coverage enforced (floor: 90%)
ruff check .                    # lint
ruff format --check .           # formatting
mypy --strict src/secondeye     # type check
```

Run `ruff format .` (without `--check`) to auto-fix formatting issues
before committing.

An optional `.pre-commit-config.yaml` at the repo root mirrors these
same four gates as local git hooks — install with `pipx install
pre-commit && pre-commit install`. It runs whatever `ruff`/`mypy`/
`pytest` are on `PATH`, so activate this repo's `.venv` (or otherwise
have the dev extras installed) before committing.

A push to `main` that bumps `version` in `pyproject.toml` is
automatically tagged and released on GitHub (the `tag-release` job in
`.github/workflows/ci.yml`, gated on the four gates passing first). Its
release notes are pulled verbatim from `CHANGELOG.md`'s matching
`## X.Y.Z - YYYY-MM-DD` section — so a version bump without a matching
`CHANGELOG.md` entry fails that job loudly rather than publishing an
empty release. Bumping the version and adding its `CHANGELOG.md` entry
in the same change (already asked of every contributor above) is what
makes this automatic.

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

Fork the repo, create a branch, and open a pull request against `main`.
CI runs the four gates automatically on every pull request. If your
change is user-visible, add an entry under `## Unreleased` in
`CHANGELOG.md` — see its existing entries for the expected level of
detail (a sentence or two from a user's perspective, not a commit-message
dump).

## Commit messages

Describe the *why*, not just the *what* — the diff already shows what
changed. Keep the subject line under ~70 characters.
