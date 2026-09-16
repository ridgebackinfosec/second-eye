"""Tests for secondeye.recording.manager (SPEC.md §2, §6.1-§6.3, §14 Phase 6)."""

import datetime
import json
from pathlib import Path

import pytest

from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse
from secondeye.exceptions import (
    CaptureAlreadyActiveError,
    CaptureNameConflictError,
    NoActiveCaptureError,
)
from secondeye.recording.manager import CaptureManager


def _entry(
    path: str = "/page", body: bytes = b"", started_at: datetime.datetime | None = None
) -> HarEntry:
    return HarEntry(
        started_at=started_at or datetime.datetime.now(datetime.UTC),
        time_ms=1.0,
        request=HarRequest(
            method="GET",
            url=f"https://example.com{path}",
            http_version="1.1",
            headers=(HarHeader("Sec-Fetch-Mode", "navigate"),),
            body=b"",
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "text/html"),),
            body=body,
        ),
    )


def _manager(tmp_path: Path, target_label: str = "example-com") -> CaptureManager:
    return CaptureManager(
        state_dir=tmp_path,
        target_label=target_label,
        targets=["example.com"],
        target_regex=None,
        target_all=False,
        upstream="127.0.0.1:8080",
        no_upstream=False,
    )


class TestNoActiveCaptureInvariant:
    async def test_record_entry_is_a_noop_without_an_active_capture(self, tmp_path: Path) -> None:
        # SPEC.md §6.2: no writes happen when no capture is active.
        manager = _manager(tmp_path)
        await manager.record_entry(_entry())  # must not raise
        assert manager.active_capture is None

    async def test_stop_without_active_capture_raises(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        with pytest.raises(NoActiveCaptureError):
            await manager.stop_capture()


class TestStartCapture:
    def test_start_returns_active_capture_with_correct_output_dir(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        active = manager.start_capture("auth-flow-test")
        assert active.name == "auth-flow-test"
        today = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
        assert (
            active.output_dir == tmp_path / "captures" / f"{today}_example-com" / "auth-flow-test"
        )
        assert manager.active_capture == active

    def test_second_start_while_active_raises_with_active_capture_info(
        self, tmp_path: Path
    ) -> None:
        manager = _manager(tmp_path)
        manager.start_capture("first")
        with pytest.raises(CaptureAlreadyActiveError) as exc_info:
            manager.start_capture("second")
        assert exc_info.value.name == "first"

    async def test_duplicate_name_same_day_raises_without_overwriting(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        manager.start_capture("dup-test")
        await manager.record_entry(_entry())
        result = await manager.stop_capture()
        assert result.output_dir.exists()

        with pytest.raises(CaptureNameConflictError):
            manager.start_capture("dup-test")

        # The original output must be untouched.
        assert (result.output_dir / "raw.har").exists()


class TestStopCaptureProducesCompleteOutput:
    async def test_produces_all_three_files_with_consistent_counts(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        manager.start_capture("auth-flow-test")
        await manager.record_entry(_entry("/login"))
        await manager.record_entry(_entry("/dashboard"))
        result = await manager.stop_capture()

        assert result.request_count == 2
        assert manager.active_capture is None

        raw_har_path = result.output_dir / "raw.har"
        manifest_path = result.output_dir / "manifest.json"
        analysis_path = result.output_dir / "ANALYSIS.md"
        assert raw_har_path.exists()
        assert manifest_path.exists()
        assert analysis_path.exists()

        raw_har = json.loads(raw_har_path.read_text(encoding="utf-8"))
        assert len(raw_har["log"]["entries"]) == 2
        assert raw_har["log"]["entries"][0]["request"]["url"] == "https://example.com/login"

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["schema_version"] == "1.0"
        assert manifest["stats"]["total_requests"] == 2
        assert manifest["scope"]["targets"] == ["example.com"]

        # har_entry_indices in the manifest resolve correctly against raw.har.
        for flow in manifest["flows"]:
            for idx in flow["har_entry_indices"]:
                assert 0 <= idx < len(raw_har["log"]["entries"])

        analysis_text = analysis_path.read_text(encoding="utf-8")
        assert "auth-flow-test" in analysis_text
        assert "har_entry_index: 0" in analysis_text
        assert "har_entry_index: 1" in analysis_text

    async def test_buffer_file_removed_after_successful_stop(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        active = manager.start_capture("cleanup-test")
        await manager.record_entry(_entry())
        await manager.stop_capture()
        leftover = list(active.output_dir.glob("*.jsonl"))
        assert leftover == []

    async def test_empty_capture_still_produces_valid_output(self, tmp_path: Path) -> None:
        # Operator starts and immediately stops with zero traffic.
        manager = _manager(tmp_path)
        manager.start_capture("empty")
        result = await manager.stop_capture()
        assert result.request_count == 0
        manifest = json.loads((result.output_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["stats"]["total_requests"] == 0


class TestGracefulShutdownFlush:
    async def test_stop_capture_produces_complete_output_when_called_abruptly(
        self, tmp_path: Path
    ) -> None:
        # SPEC.md §9: a SIGINT handler (daemon.py, a later phase) calls this
        # exact same stop_capture() to flush whatever was captured so far —
        # there is no separate "emergency" code path, so proving normal
        # stop_capture() always yields complete, valid output on the buffered
        # data is what makes the eventual signal-triggered flush safe.
        manager = _manager(tmp_path)
        manager.start_capture("interrupted")
        await manager.record_entry(_entry("/one"))
        await manager.record_entry(_entry("/two"))
        await manager.record_entry(_entry("/three"))

        result = await manager.stop_capture()

        assert result.request_count == 3
        raw_har = json.loads((result.output_dir / "raw.har").read_text(encoding="utf-8"))
        assert len(raw_har["log"]["entries"]) == 3


class TestCaptureList:
    async def test_list_captures_tracks_completed_captures_this_run(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        manager.start_capture("first")
        await manager.stop_capture()
        manager.start_capture("second")
        await manager.stop_capture()

        names = [c.name for c in manager.list_captures()]
        assert names == ["first", "second"]

    def test_list_captures_empty_before_any_completed(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        assert manager.list_captures() == []


class TestScopeSummary:
    def test_reflects_constructor_configuration(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        summary = manager.scope_summary()
        assert summary == {
            "targets": ["example.com"],
            "target_regex": None,
            "target_all": False,
            "upstream": "127.0.0.1:8080",
            "no_upstream": False,
        }
