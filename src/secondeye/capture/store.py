"""Reading finished captures back off disk (SPEC.md §6.5).

A capture used to be write-once: ``capture list`` answered from an
in-memory history that died with the daemon, and nothing could re-read a
finished capture at all. This module supplies the filesystem side, so
``capture list``, ``capture analyze`` and ``capture recover`` all work
with no daemon running.

Two deliberate choices:

- ``load_capture()`` requires ``manifest.json``, and fails loudly without
  it rather than inferring a capture's name, scope and window from the
  directory layout. Guessing would fabricate provenance into the
  re-rendered ``ANALYSIS.md``, which is worse than refusing.
- ``discover_captures()`` does the opposite: it skips anything it cannot
  parse instead of raising, because one corrupt capture must not make
  ``capture list`` useless for every other capture in the tree.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from pathlib import Path

from secondeye.analysis.cluster import DEFAULT_CLUSTER_WINDOW_MS
from secondeye.analysis.pipeline import (
    ANALYSIS_FILENAME,
    MANIFEST_FILENAME,
    RAW_HAR_FILENAME,
    CaptureMetadata,
)
from secondeye.capture.har import HarEntry, parse_har_entry
from secondeye.exceptions import CaptureStoreError

__all__ = [
    "BUFFER_FILENAME",
    "CaptureSummary",
    "LoadedCapture",
    "discover_captures",
    "find_buffer",
    "load_capture",
]

BUFFER_FILENAME = ".buffer.jsonl"
"""Name of the incremental JSONL buffer an active capture appends to.

Must match ``recording/manager.py``'s own constant, or ``capture
recover`` silently finds nothing; asserted in tests/test_capture_store.py.
"""


@dataclass(frozen=True)
class LoadedCapture:
    """A capture read back from disk, ready to re-render.

    Attributes:
        output_dir: The directory it was read from.
        entries: Its recorded request/response pairs.
        metadata: Its identity, scope and clustering window.
    """

    output_dir: Path
    entries: list[HarEntry]
    metadata: CaptureMetadata


@dataclass(frozen=True)
class CaptureSummary:
    """One capture's headline numbers, for listing without loading it.

    Read from ``manifest.json`` alone — deliberately not from
    ``raw.har``, so listing a tree of large captures stays cheap.

    Attributes:
        name: The capture's --name label.
        output_dir: Where it lives.
        started_at: When it started, or None if unparseable.
        target: Its first configured target, for display.
        request_count: Entries recorded.
        total_bytes: Request+response body bytes recorded.
        flow_count: Narrative flows in its ANALYSIS.md.
        finding_count: Actionable findings tallied for it.
    """

    name: str
    output_dir: Path
    started_at: datetime.datetime | None
    target: str
    request_count: int
    total_bytes: int
    flow_count: int
    finding_count: int

    @property
    def analysis_path(self) -> Path:
        """Path to this capture's ANALYSIS.md."""
        return self.output_dir / ANALYSIS_FILENAME


def load_capture(output_dir: Path) -> LoadedCapture:
    """Read a capture's entries and metadata back from disk.

    Args:
        output_dir: A capture directory containing ``raw.har`` and
            ``manifest.json``.

    Returns:
        The loaded capture, ready to pass to ``write_capture_outputs()``.

    Raises:
        CaptureStoreError: If the path isn't a directory, either file is
            missing, or either file can't be parsed.
    """
    if not output_dir.is_dir():
        raise CaptureStoreError(f"{output_dir} is not a directory")

    raw_har_path = output_dir / RAW_HAR_FILENAME
    manifest_path = output_dir / MANIFEST_FILENAME
    if not raw_har_path.is_file():
        raise CaptureStoreError(f"no {RAW_HAR_FILENAME} in {output_dir}")
    if not manifest_path.is_file():
        raise CaptureStoreError(
            f"no {MANIFEST_FILENAME} in {output_dir} — cannot recover the capture's "
            "name, scope or clustering window without it"
        )

    manifest = _read_json(manifest_path, MANIFEST_FILENAME)
    entries = _read_entries(raw_har_path)
    return LoadedCapture(
        output_dir=output_dir,
        entries=entries,
        metadata=_metadata_from_manifest(manifest, fallback_name=output_dir.name),
    )


def discover_captures(captures_dir: Path) -> list[CaptureSummary]:
    """List every readable capture under a captures directory, newest first.

    Walks ``<date>_<label>/<name>/manifest.json`` (SPEC.md §6.5). An
    entry that can't be parsed is skipped rather than raised, so one
    corrupt capture doesn't break the listing.

    Args:
        captures_dir: The captures root to walk.

    Returns:
        Summaries ordered newest first; empty if the directory is absent.
    """
    if not captures_dir.is_dir():
        return []

    summaries: list[CaptureSummary] = []
    for day_dir in sorted(captures_dir.iterdir()):
        if not day_dir.is_dir():
            continue
        for capture_dir in sorted(day_dir.iterdir()):
            summary = _summarize(capture_dir)
            if summary is not None:
                summaries.append(summary)

    # Newest first by manifest timestamp. Two fallbacks keep the order
    # deterministic rather than incidental: a capture whose start time is
    # unparseable sorts last instead of crashing the comparison, and the
    # directory path breaks ties -- it begins with the date (SPEC.md
    # §6.5's <date>_<label>/ layout), so sibling captures recorded in the
    # same second still come out in a stable, meaningful order.
    # Note the rank values: the whole key is sorted descending, so the
    # group meant to come last needs the *lower* rank, not the higher one.
    def sort_key(summary: CaptureSummary) -> tuple[int, datetime.datetime, str]:
        if summary.started_at is None:
            return (0, datetime.datetime.min.replace(tzinfo=datetime.UTC), str(summary.output_dir))
        return (1, summary.started_at, str(summary.output_dir))

    summaries.sort(key=sort_key, reverse=True)
    return summaries


def find_buffer(path: Path) -> Path:
    """Resolve a leftover JSONL buffer from a crashed daemon.

    Args:
        path: Either the buffer file itself, or a capture directory
            containing one.

    Returns:
        Path to the buffer file.

    Raises:
        CaptureStoreError: If the path doesn't exist, or names a
            directory with no buffer in it.
    """
    if path.is_file():
        return path
    if path.is_dir():
        candidate = path / BUFFER_FILENAME
        if candidate.is_file():
            return candidate
        raise CaptureStoreError(
            f"no {BUFFER_FILENAME} buffer in {path} — nothing to recover "
            "(a capture that stopped cleanly has already been written out)"
        )
    raise CaptureStoreError(f"{path} does not exist")


def _summarize(capture_dir: Path) -> CaptureSummary | None:
    if not capture_dir.is_dir():
        return None
    manifest_path = capture_dir / MANIFEST_FILENAME
    if not manifest_path.is_file():
        return None
    try:
        manifest = _read_json(manifest_path, MANIFEST_FILENAME)
        capture = _section(manifest, "capture")
        stats = _section(manifest, "stats")
        scope = _section(manifest, "scope")
        findings = _section(manifest, "findings")
        targets = scope.get("targets")
        flows = manifest.get("flows")
        return CaptureSummary(
            name=str(capture.get("name") or capture_dir.name),
            output_dir=capture_dir,
            started_at=_parse_iso(capture.get("started_at")),
            target=str(targets[0]) if isinstance(targets, list) and targets else "—",
            request_count=_as_int(stats.get("total_requests")),
            total_bytes=_as_int(stats.get("total_bytes_transferred")),
            flow_count=(
                sum(1 for f in flows if isinstance(f, dict) and f.get("collapsed_into") is None)
                if isinstance(flows, list)
                else 0
            ),
            finding_count=_as_int(findings.get("total")),
        )
    except (CaptureStoreError, KeyError, TypeError, ValueError):
        # Unreadable capture: leave it out of the listing rather than
        # making every other capture unlistable.
        return None


def _metadata_from_manifest(manifest: dict[str, object], *, fallback_name: str) -> CaptureMetadata:
    capture = _section(manifest, "capture")
    scope = _section(manifest, "scope")
    started_at = _parse_iso(capture.get("started_at"))
    ended_at = _parse_iso(capture.get("ended_at"))
    if started_at is None or ended_at is None:
        raise CaptureStoreError(
            f"{MANIFEST_FILENAME} is missing a usable capture start/end timestamp"
        )
    raw_targets = scope.get("targets")
    raw_regex = scope.get("target_regex")
    upstream = scope.get("upstream")
    return CaptureMetadata(
        name=str(capture.get("name") or fallback_name),
        started_at=started_at,
        ended_at=ended_at,
        targets=[str(t) for t in raw_targets] if isinstance(raw_targets, list) else [],
        target_regex=([str(r) for r in raw_regex] if isinstance(raw_regex, list) else None),
        target_all=bool(scope.get("target_all")),
        upstream=None if upstream is None else str(upstream),
        no_upstream=bool(scope.get("no_upstream")),
        cluster_window_ms=DEFAULT_CLUSTER_WINDOW_MS,
    )


def _read_entries(raw_har_path: Path) -> list[HarEntry]:
    raw_har = _read_json(raw_har_path, RAW_HAR_FILENAME)
    log = raw_har.get("log")
    if not isinstance(log, dict):
        raise CaptureStoreError(f"{RAW_HAR_FILENAME} has no 'log' object")
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise CaptureStoreError(f"{RAW_HAR_FILENAME} has no 'log.entries' array")
    try:
        return [parse_har_entry(entry) for entry in entries]
    except (KeyError, TypeError, ValueError) as exc:
        raise CaptureStoreError(f"{RAW_HAR_FILENAME} contains an unreadable entry: {exc}") from exc


def _read_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CaptureStoreError(f"failed to read {label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CaptureStoreError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CaptureStoreError(f"{label} is not a JSON object")
    return payload


def _section(manifest: dict[str, object], key: str) -> dict[str, object]:
    value = manifest.get(key)
    return value if isinstance(value, dict) else {}


def _as_int(value: object) -> int:
    """Coerce an untrusted manifest value to an int, defaulting to 0.

    Manifest contents are read from disk and may have been written by an
    older version, hand-edited, or truncated, so a non-numeric value
    must degrade to 0 rather than raise out of a listing.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _parse_iso(value: object) -> datetime.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
