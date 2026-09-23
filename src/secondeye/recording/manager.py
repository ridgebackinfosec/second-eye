"""Capture lifecycle state machine (SPEC.md §2, §6.1-§6.3).

Transport-agnostic: recording/control.py (the Unix domain socket layer) is
a thin client/server relaying requests to this class, so the socket
protocol can change later without touching capture lifecycle logic
(SPEC.md §13's module boundary rationale).

One active capture at a time (SPEC.md §6.3); ``record_entry()`` is a no-op
when none is active (SPEC.md §6.2's no-active-capture invariant — in-scope
traffic still flows, but nothing is buffered/written). ``stop_capture()``
is also what a later phase's SIGINT/SIGTERM handler calls to flush
whatever was captured so far (SPEC.md §9) — there's no separate "emergency"
code path, so this method being complete/correct on its own is what makes
that graceful-shutdown flush safe.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from secondeye.analysis.classify import classify_entries
from secondeye.analysis.manifest import build_flows, build_manifest
from secondeye.analysis.render import render_analysis_md
from secondeye.capture.buffer import CaptureBuffer, read_buffer
from secondeye.capture.har import HarEntry
from secondeye.exceptions import (
    CaptureAlreadyActiveError,
    CaptureNameConflictError,
    NoActiveCaptureError,
)

__all__ = ["ActiveCapture", "CaptureManager", "CaptureResult"]

logger = logging.getLogger(__name__)

_HAR_VERSION = "1.2"
_CREATOR_NAME = "secondeye"
_CREATOR_VERSION = "1.0.0"
_BUFFER_FILENAME = ".buffer.jsonl"


@dataclass(frozen=True)
class ActiveCapture:
    """The currently-active capture's identity (SPEC.md §6.3).

    Attributes:
        name: The capture's --name label.
        started_at: When the capture started.
        output_dir: Where its outputs will be written on stop.
    """

    name: str
    started_at: datetime.datetime
    output_dir: Path


@dataclass(frozen=True)
class CaptureResult:
    """The outcome of a completed capture (SPEC.md §2's stop confirmation).

    Attributes:
        name: The capture's --name label.
        request_count: Total requests recorded.
        total_bytes: Total request+response body bytes recorded.
        output_dir: Where raw.har/manifest.json/ANALYSIS.md were written.
        raw_har_path: Path to raw.har.
        manifest_path: Path to manifest.json.
        analysis_path: Path to ANALYSIS.md.
    """

    name: str
    request_count: int
    total_bytes: int
    output_dir: Path
    raw_har_path: Path
    manifest_path: Path
    analysis_path: Path


class CaptureManager:
    """Owns the single-active-capture state machine for one daemon run."""

    def __init__(
        self,
        *,
        state_dir: Path,
        target_label: str,
        targets: list[str],
        target_regex: list[str] | None,
        target_all: bool,
        upstream: str | None,
        no_upstream: bool,
        cluster_window_ms: int = 2000,
    ) -> None:
        """Store fixed daemon-startup configuration for this run.

        Args:
            state_dir: secondeye's state directory (captures/ lives under it).
            target_label: Precomputed label identifying the configured
                target(s) for the output directory name (SPEC.md §6.5,
                e.g. "example-com"); derived by the caller (daemon.py).
            targets: Configured --target values, for manifest.json's scope.
            target_regex: Configured --target-regex values, if any.
            target_all: Whether --target-all was set.
            upstream: "host:port" of the configured upstream, if any.
            no_upstream: Whether --no-upstream was set.
            cluster_window_ms: Flow-clustering time window (SPEC.md
                --cluster-window). Reserved for future use by the
                clustering pipeline's window parameter.
        """
        self._state_dir = state_dir
        self._target_label = target_label
        self._targets = targets
        self._target_regex = target_regex
        self._target_all = target_all
        self._upstream = upstream
        self._no_upstream = no_upstream
        self._cluster_window_ms = cluster_window_ms
        self._active: ActiveCapture | None = None
        self._buffer: CaptureBuffer | None = None
        self._history: list[CaptureResult] = []
        self._active_request_count = 0

    @property
    def active_capture(self) -> ActiveCapture | None:
        """The currently-active capture, or None if none is active."""
        return self._active

    @property
    def active_request_count(self) -> int:
        """How many requests the current capture has recorded so far (0 if none active)."""
        return self._active_request_count

    def scope_summary(self) -> dict[str, object]:
        """This run's fixed scope configuration, for status/confirmation output.

        Returns:
            {"targets": [...], "target_regex": [...] | None, "target_all":
            bool, "upstream": str | None, "no_upstream": bool}.
        """
        return {
            "targets": self._targets,
            "target_regex": self._target_regex,
            "target_all": self._target_all,
            "upstream": self._upstream,
            "no_upstream": self._no_upstream,
        }

    def start_capture(self, name: str) -> ActiveCapture:
        """Begin a new capture (SPEC.md §2's ``capture start``).

        Args:
            name: The capture's --name label.

        Returns:
            The new ActiveCapture.

        Raises:
            CaptureAlreadyActiveError: If a capture is already active.
            CaptureNameConflictError: If today's output directory for this
                name already exists.
        """
        if self._active is not None:
            raise CaptureAlreadyActiveError(self._active.name, self._active.started_at)

        started_at = datetime.datetime.now(datetime.UTC)
        date_label = started_at.strftime("%Y-%m-%d")
        output_dir = self._state_dir / "captures" / f"{date_label}_{self._target_label}" / name
        if output_dir.exists():
            raise CaptureNameConflictError(name, output_dir)

        self._buffer = CaptureBuffer(output_dir / _BUFFER_FILENAME)
        self._active = ActiveCapture(name=name, started_at=started_at, output_dir=output_dir)
        self._active_request_count = 0
        logger.info("capture started: %s", name)
        return self._active

    async def record_entry(self, entry: HarEntry) -> None:
        """Buffer one completed request/response pair.

        A no-op when no capture is active (SPEC.md §6.2) — bind this as
        the ``on_entry_recorded`` callback for proxy/intercept.py and
        proxy/plain_http.py.

        Args:
            entry: The completed request/response pair to record.
        """
        if self._buffer is None:
            return
        await self._buffer.append(entry)
        self._active_request_count += 1

    async def stop_capture(self) -> CaptureResult:
        """End the active capture and write raw.har/manifest.json/ANALYSIS.md.

        Returns:
            A CaptureResult summarizing the completed capture.

        Raises:
            NoActiveCaptureError: If no capture is active.
        """
        if self._active is None or self._buffer is None:
            raise NoActiveCaptureError("no capture is currently active")

        active = self._active
        self._buffer.close()
        buffer_path = active.output_dir / _BUFFER_FILENAME

        entries = read_buffer(buffer_path) if buffer_path.exists() else []
        ended_at = datetime.datetime.now(datetime.UTC)

        classified = classify_entries(entries)
        flows = build_flows(classified)
        manifest_dict = build_manifest(
            capture_name=active.name,
            started_at=active.started_at,
            ended_at=ended_at,
            targets=self._targets,
            target_regex=self._target_regex,
            target_all=self._target_all,
            upstream=self._upstream,
            no_upstream=self._no_upstream,
            classified=classified,
            flows=flows,
        )
        analysis_md = render_analysis_md(
            capture_name=active.name,
            targets=self._targets,
            started_at=active.started_at,
            ended_at=ended_at,
            classified=classified,
            flows=flows,
        )
        raw_har = _build_raw_har(entries)

        await asyncio.to_thread(
            _write_outputs, active.output_dir, raw_har, manifest_dict, analysis_md
        )
        buffer_path.unlink(missing_ok=True)

        total_bytes = sum(len(e.request.body) + len(e.response.body) for e in entries)
        result = CaptureResult(
            name=active.name,
            request_count=len(entries),
            total_bytes=total_bytes,
            output_dir=active.output_dir,
            raw_har_path=active.output_dir / "raw.har",
            manifest_path=active.output_dir / "manifest.json",
            analysis_path=active.output_dir / "ANALYSIS.md",
        )
        logger.info(
            "capture stopped: %s (%d requests, %d bytes)",
            active.name,
            result.request_count,
            total_bytes,
        )

        self._active = None
        self._buffer = None
        self._history.append(result)
        return result

    def list_captures(self) -> list[CaptureResult]:
        """Return completed captures from this daemon run, in order."""
        return list(self._history)


def _build_raw_har(entries: list[HarEntry]) -> dict[str, object]:
    return {
        "log": {
            "version": _HAR_VERSION,
            "creator": {"name": _CREATOR_NAME, "version": _CREATOR_VERSION},
            "entries": [entry.to_har_dict() for entry in entries],
        }
    }


def _write_outputs(
    output_dir: Path, raw_har: dict[str, object], manifest: dict[str, object], analysis_md: str
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "raw.har").write_text(json.dumps(raw_har, indent=2), encoding="utf-8")
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (output_dir / "ANALYSIS.md").write_text(analysis_md, encoding="utf-8")
