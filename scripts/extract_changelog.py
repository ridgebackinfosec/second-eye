#!/usr/bin/env python3
"""Extract changelog section for a specific version from CHANGELOG.md.

Writes ``release_notes.md`` for ``.github/workflows/release.yml`` to pass to
``gh release create --notes-file``. Deliberately dependency-free (stdlib
only) so the release job can run it without installing anything.
"""

import re
import sys
from pathlib import Path


def extract_changelog_section(changelog_path: Path, version: str) -> str:
    """Extract changelog content for a specific version.

    Args:
        changelog_path: Path to the ``CHANGELOG.md`` to read.
        version: Plain semver version (``X.Y.Z``, no ``v`` prefix).

    Returns:
        The section body, stripped of surrounding blank lines.

    Raises:
        FileNotFoundError: If ``changelog_path`` does not exist.
        ValueError: If no ``## [version] - YYYY-MM-DD`` heading matches.
    """
    if not changelog_path.exists():
        raise FileNotFoundError(f"CHANGELOG.md not found at {changelog_path}")

    content = changelog_path.read_text(encoding="utf-8")

    # Pattern matches: ## [version] - YYYY-MM-DD
    version_pattern = rf"## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}"
    version_match = re.search(version_pattern, content)
    if not version_match:
        raise ValueError(
            f"Version [{version}] not found in CHANGELOG.md. "
            f"Expected format: ## [{version}] - YYYY-MM-DD"
        )

    start_pos = version_match.end()
    next_match = re.search(r"\n## \[\d+\.\d+\.\d+\]", content[start_pos:])
    if next_match:
        section_content = content[start_pos : start_pos + next_match.start()]
    else:
        section_content = content[start_pos:]

    lines = section_content.strip().split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def main() -> None:
    """Write ``release_notes.md`` for the version named in ``argv[1]``."""
    if len(sys.argv) != 2:
        print("Usage: python extract_changelog.py <version>", file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1]
    changelog_path = Path("CHANGELOG.md")
    output_path = Path("release_notes.md")

    try:
        notes = extract_changelog_section(changelog_path, version)
        output_path.write_text(f"# Release v{version}\n\n{notes}\n", encoding="utf-8")
        print(f"Successfully extracted changelog for version {version}")
        print(f"Release notes written to {output_path}")
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        # This message is the whole point of the error path: it tells you
        # whether you mistyped the version or forgot the date on the
        # heading, which is the actual failure mode in practice.
        print(f"Error: {exc}", file=sys.stderr)
        print("\nAvailable versions in CHANGELOG.md:", file=sys.stderr)
        if changelog_path.exists():
            found = re.findall(
                r"## \[(\d+\.\d+\.\d+)\]", changelog_path.read_text(encoding="utf-8")
            )
            for available in found:
                print(f"  - {available}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
