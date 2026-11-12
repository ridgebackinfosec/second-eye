"""Tests for the single-source-of-truth version string.

``pyproject.toml``'s ``project.version`` is the only place this project's
version is declared. Everything that reports a version — ``secondeye
--version``, and ``raw.har``'s ``log.creator.version`` — must derive from
it rather than carrying its own literal, or a version bump silently ships
stale metadata in every capture. These tests fail when that drifts.
"""

import tomllib
from pathlib import Path

import pytest

import secondeye
from secondeye.recording import manager

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version() -> str:
    """Read ``project.version`` straight out of ``pyproject.toml``."""
    with _PYPROJECT.open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    assert isinstance(version, str)
    return version


class TestVersionSourceOfTruth:
    def test_package_version_matches_pyproject(self) -> None:
        # Only meaningful against an install that resolves to this tree
        # (editable/source, as CONTRIBUTING.md's setup produces). A wheel
        # installed from elsewhere legitimately reports its own version.
        if secondeye.__version__ == "unknown":
            pytest.skip("second-eye is not installed; no metadata to compare")
        assert secondeye.__version__ == _declared_version()

    def test_har_creator_version_is_not_a_hardcoded_literal(self) -> None:
        assert manager._CREATOR_VERSION == secondeye.__version__

    def test_cli_version_is_not_a_hardcoded_literal(self) -> None:
        from secondeye import cli

        assert cli._VERSION == secondeye.__version__


class TestVersionFallback:
    def test_version_is_always_a_string(self) -> None:
        # Never raises and never None, even from a non-installed checkout:
        # `secondeye --version` has to print something rather than crash.
        assert isinstance(secondeye.__version__, str)
        assert secondeye.__version__
