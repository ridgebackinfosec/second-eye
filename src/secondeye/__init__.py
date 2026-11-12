"""Second-eye: scope-gated HTTP/HTTPS recording proxy for offensive security engagements."""

import importlib.metadata

__all__: list[str] = ["__version__"]

# The single source of truth for this project's version is
# pyproject.toml's `project.version`; it reaches runtime only through the
# installed distribution's metadata, so nothing in src/ carries a version
# literal that could drift from it (tests/test_version.py enforces this).
# A source checkout that was never installed has no metadata to read —
# fall back rather than raise, so `secondeye --version` still prints
# something instead of traceback-ing.
try:
    __version__ = importlib.metadata.version("second-eye")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"
