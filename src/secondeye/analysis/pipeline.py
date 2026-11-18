"""The one path from recorded entries to a capture's three output files.

``classify_entries`` → ``build_flows`` → ``build_manifest`` /
``render_analysis_md`` → write ``raw.har``, ``manifest.json`` and
``ANALYSIS.md``.

This sequence was previously inlined in ``CaptureManager.stop_capture()``,
which made it reachable only while a daemon was running and holding the
capture in memory. Extracting it is what lets a capture already on disk be
re-rendered — ``secondeye capture analyze`` (a capture frozen at whatever
renderer version produced it) and ``secondeye capture recover`` (a JSONL
buffer orphaned by a crashed daemon) are both callers of this module, and
``stop_capture()`` is now a third rather than the implementation.

Writing is synchronous: async callers wrap it in ``asyncio.to_thread()``
per SPEC.md §13's rule for blocking I/O.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from pathlib import Path

import secondeye
from secondeye.analysis.classify import classify_entries
from secondeye.analysis.cluster import DEFAULT_CLUSTER_WINDOW_MS
from secondeye.analysis.manifest import build_flows, build_manifest
from secondeye.analysis.render import render_analysis_md
from secondeye.analysis.signals import FindingCounts, compute_finding_counts
from secondeye.capture.har import HarEntry

__all__ = [
    "ANALYSIS_FILENAME",
    "MANIFEST_FILENAME",
    "RAW_HAR_FILENAME",
    "CaptureMetadata",
    "CaptureOutputs",
    "write_capture_outputs",
]

RAW_HAR_FILENAME = "raw.har"
MANIFEST_FILENAME = "manifest.json"
ANALYSIS_FILENAME = "ANALYSIS.md"

_HAR_VERSION = "1.2"
_CREATOR_NAME = "secondeye"


@dataclass(frozen=True)
class CaptureMetadata:
    """Everything about a capture that isn't derivable from its entries.

    Attributes:
        name: The capture's --name label.
        started_at: When the capture started.
        ended_at: When the capture ended.
        targets: Configured --target values.
        target_regex: Configured --target-regex values, if any.
        target_all: Whether --target-all was set.
        upstream: "host:port" of the upstream, if one was configured.
        no_upstream: Whether --no-upstream was set.
        cluster_window_ms: --cluster-window, forwarded to clustering.
    """

    name: str
    started_at: datetime.datetime
    ended_at: datetime.datetime
    targets: list[str] = field(default_factory=list)
    target_regex: list[str] | None = None
    target_all: bool = False
    upstream: str | None = None
    no_upstream: bool = False
    cluster_window_ms: int = DEFAULT_CLUSTER_WINDOW_MS


@dataclass(frozen=True)
class CaptureOutputs:
    """Where a capture's files landed, and what was in it.

    Attributes:
        output_dir: The directory written to.
        raw_har_path: Path to raw.har.
        manifest_path: Path to manifest.json.
        analysis_path: Path to ANALYSIS.md.
        request_count: Entries recorded.
        total_bytes: Request+response body bytes recorded.
        flow_count: Narrative flows in ANALYSIS.md (collapsed polling
            occurrences are not counted separately).
        findings: Actionable-finding tally for this capture.
    """

    output_dir: Path
    raw_har_path: Path
    manifest_path: Path
    analysis_path: Path
    request_count: int
    total_bytes: int
    flow_count: int
    findings: FindingCounts


def write_capture_outputs(
    output_dir: Path, entries: list[HarEntry], metadata: CaptureMetadata
) -> CaptureOutputs:
    """Render ``entries`` and write all three output files.

    Blocking: creates ``output_dir`` if needed and writes three files.
    Call via ``asyncio.to_thread()`` from async code.

    Args:
        output_dir: Directory to write into; created if absent.
        entries: The capture's recorded request/response pairs.
        metadata: The capture's identity, scope and clustering window.

    Returns:
        A CaptureOutputs describing what was written.
    """
    classified = classify_entries(entries)
    flows = build_flows(classified)
    findings = compute_finding_counts(classified)

    manifest = build_manifest(
        capture_name=metadata.name,
        started_at=metadata.started_at,
        ended_at=metadata.ended_at,
        targets=metadata.targets,
        target_regex=metadata.target_regex,
        target_all=metadata.target_all,
        upstream=metadata.upstream,
        no_upstream=metadata.no_upstream,
        classified=classified,
        flows=flows,
        findings=findings,
    )
    analysis_md = render_analysis_md(
        capture_name=metadata.name,
        targets=metadata.targets,
        started_at=metadata.started_at,
        ended_at=metadata.ended_at,
        classified=classified,
        flows=flows,
        cluster_window_ms=metadata.cluster_window_ms,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    raw_har_path = output_dir / RAW_HAR_FILENAME
    manifest_path = output_dir / MANIFEST_FILENAME
    analysis_path = output_dir / ANALYSIS_FILENAME
    raw_har_path.write_text(json.dumps(_build_raw_har(entries), indent=2), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    analysis_path.write_text(analysis_md, encoding="utf-8")

    return CaptureOutputs(
        output_dir=output_dir,
        raw_har_path=raw_har_path,
        manifest_path=manifest_path,
        analysis_path=analysis_path,
        request_count=len(entries),
        total_bytes=sum(len(e.request.body) + len(e.response.body) for e in entries),
        flow_count=sum(1 for f in flows if f.collapsed_into is None),
        findings=findings,
    )


def _build_raw_har(entries: list[HarEntry]) -> dict[str, object]:
    return {
        "log": {
            "version": _HAR_VERSION,
            "creator": {"name": _CREATOR_NAME, "version": secondeye.__version__},
            "entries": [entry.to_har_dict() for entry in entries],
        }
    }
