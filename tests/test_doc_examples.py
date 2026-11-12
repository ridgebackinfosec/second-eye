"""Drift test for generated documentation examples.

The generator alone only means the docs *can* be current. This test is what
makes them current: it re-captures every example and fails if the committed
output differs, naming the command that fixes it.

See scripts/generate_doc_examples.py for the mechanism.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "generate_doc_examples.py"

# Exit codes the generator uses; mirrored here rather than imported, because
# importing the generator in-process would pull the capture machinery into the
# test session.
EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_CONFIG = 2
EXIT_UNAVAILABLE = 3

# argparse's help formatting is not stable across Python versions: 3.13 renders
# an option with a short and long form as "-tf, --target-file TARGET_FILE",
# where earlier versions repeat the metavar. The committed CLI help blocks are
# therefore byte-identical only on the version that generated them. Pinning the
# check to one version is deliberate: this test exists to catch a maintainer
# forgetting to regenerate, and it still does that in the 3.13 matrix cell and
# in local development. Contorting the output to satisfy every version would
# mean shipping help text that matches no version exactly.
GENERATOR_PYTHON = (3, 13)


@pytest.mark.slow
@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="path separators and console encoding differ; this project is Linux-only",
)
@pytest.mark.skipif(
    sys.version_info[:2] != GENERATOR_PYTHON,
    reason=(
        f"generated CLI help is byte-identical only on Python "
        f"{GENERATOR_PYTHON[0]}.{GENERATOR_PYTHON[1]} (argparse formatting differs by version)"
    ),
)
def test_generated_doc_examples_are_current() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GENERATOR), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    if result.returncode == EXIT_UNAVAILABLE:
        pytest.skip(f"doc-example fixture unavailable on this machine:\n{result.stderr}")

    assert result.returncode != EXIT_CONFIG, (
        "The doc-example generator is misconfigured (a marker is missing, or an "
        "example targets a file that does not exist).\n\n"
        f"{result.stderr}"
    )

    # The generator's own stderr already ends with the regenerate command, so
    # it isn't repeated here.
    assert result.returncode == EXIT_OK, (
        f"Documentation examples are out of date.\n\n{result.stderr}"
    )


def test_generator_exists_and_is_not_shipped() -> None:
    """The generator must stay outside the installed package.

    scripts/ is excluded from the wheel (pyproject.toml's hatchling config
    ships only src/secondeye), and nothing in the package may import it — a
    docs-only tool must never become a runtime dependency.
    """
    assert GENERATOR.is_file(), f"missing generator at {GENERATOR}"

    package_root = REPO_ROOT / "src" / "secondeye"
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in package_root.rglob("*.py")
        if "generate_doc_examples" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, f"shipped modules reference the doc generator: {offenders}"
