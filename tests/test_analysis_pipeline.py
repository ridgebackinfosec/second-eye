"""Tests for secondeye.analysis.pipeline — entries + metadata -> three files.

This is the one path that produces a capture's outputs, shared by
``capture stop`` (recording/manager.py), ``capture analyze`` and
``capture recover`` (cli.py). Before it existed the sequence was inlined
in stop_capture(), so re-rendering an existing capture was impossible
without duplicating it.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from secondeye.analysis.pipeline import CaptureMetadata, write_capture_outputs
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse

_T0 = datetime.datetime(2026, 11, 18, 9, 15, 0, tzinfo=datetime.UTC)
_T1 = datetime.datetime(2026, 11, 18, 9, 16, 30, tzinfo=datetime.UTC)

_EXAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


def _nav(at_offset: float = 0.0, url: str = "https://example.com/login") -> HarEntry:
    return HarEntry(
        started_at=_T0 + datetime.timedelta(seconds=at_offset),
        time_ms=12.0,
        request=HarRequest(
            method="GET",
            url=url,
            http_version="1.1",
            headers=(HarHeader("Sec-Fetch-Mode", "navigate"),),
            body=b"",
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "text/html"),),
            body=b"<html>hi</html>",
        ),
    )


def _xhr(at_offset: float, body: bytes = b'{"ok":true}') -> HarEntry:
    return HarEntry(
        started_at=_T0 + datetime.timedelta(seconds=at_offset),
        time_ms=8.0,
        request=HarRequest(
            method="GET",
            url="https://example.com/api/data",
            http_version="1.1",
            headers=(HarHeader("X-Requested-With", "XMLHttpRequest"),),
            body=b"",
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "application/json"),),
            body=body,
        ),
    )


def _metadata(**overrides: object) -> CaptureMetadata:
    defaults: dict[str, object] = {
        "name": "pipeline-test",
        "started_at": _T0,
        "ended_at": _T1,
        "targets": ["example.com"],
        "no_upstream": True,
    }
    defaults.update(overrides)
    return CaptureMetadata(**defaults)  # type: ignore[arg-type]


class TestWritesAllThreeFiles:
    def test_creates_raw_har_manifest_and_analysis(self, tmp_path: Path) -> None:
        out = write_capture_outputs(tmp_path / "cap", [_nav(), _xhr(1.0)], _metadata())
        assert out.raw_har_path.is_file()
        assert out.manifest_path.is_file()
        assert out.analysis_path.is_file()

    def test_creates_the_output_directory_if_absent(self, tmp_path: Path) -> None:
        target = tmp_path / "deep" / "nested" / "cap"
        write_capture_outputs(target, [_nav()], _metadata())
        assert (target / "raw.har").is_file()

    def test_raw_har_preserves_every_entry(self, tmp_path: Path) -> None:
        out = write_capture_outputs(tmp_path / "cap", [_nav(), _xhr(1.0)], _metadata())
        har = json.loads(out.raw_har_path.read_text(encoding="utf-8"))
        assert len(har["log"]["entries"]) == 2
        assert har["log"]["creator"]["name"] == "secondeye"

    def test_manifest_records_scope_and_capture_name(self, tmp_path: Path) -> None:
        out = write_capture_outputs(
            tmp_path / "cap",
            [_nav()],
            _metadata(targets=["a.example", "b.example"], target_all=True),
        )
        manifest = json.loads(out.manifest_path.read_text(encoding="utf-8"))
        assert manifest["capture"]["name"] == "pipeline-test"
        assert manifest["scope"]["targets"] == ["a.example", "b.example"]
        assert manifest["scope"]["target_all"] is True

    def test_analysis_is_markdown_naming_the_capture(self, tmp_path: Path) -> None:
        out = write_capture_outputs(tmp_path / "cap", [_nav()], _metadata())
        text = out.analysis_path.read_text(encoding="utf-8")
        assert text.startswith("# Second-Eye Capture Analysis")
        assert "pipeline-test" in text

    def test_empty_capture_still_produces_valid_output(self, tmp_path: Path) -> None:
        out = write_capture_outputs(tmp_path / "cap", [], _metadata())
        assert out.request_count == 0
        assert out.total_bytes == 0
        assert json.loads(out.raw_har_path.read_text(encoding="utf-8"))["log"]["entries"] == []


class TestReportedCounts:
    def test_request_count_and_total_bytes(self, tmp_path: Path) -> None:
        out = write_capture_outputs(
            tmp_path / "cap", [_nav(), _xhr(1.0, body=b"0123456789")], _metadata()
        )
        assert out.request_count == 2
        # request bodies are empty; responses are 15 + 10 bytes
        assert out.total_bytes == len(b"<html>hi</html>") + 10

    def test_flow_count_counts_narrative_flows(self, tmp_path: Path) -> None:
        out = write_capture_outputs(tmp_path / "cap", [_nav(), _xhr(1.0)], _metadata())
        assert out.flow_count == 2

    def test_findings_are_tallied(self, tmp_path: Path) -> None:
        out = write_capture_outputs(
            tmp_path / "cap", [_xhr(0.0, body=_EXAMPLE_JWT.encode())], _metadata()
        )
        assert out.findings.secrets == 1
        assert out.findings.total == 1

    def test_manifest_carries_the_findings_block(self, tmp_path: Path) -> None:
        out = write_capture_outputs(
            tmp_path / "cap", [_xhr(0.0, body=_EXAMPLE_JWT.encode())], _metadata()
        )
        manifest = json.loads(out.manifest_path.read_text(encoding="utf-8"))
        assert manifest["findings"]["total"] == 1
        assert manifest["findings"]["by_kind"]["secret"] == 1


class TestClusterWindowIsApplied:
    def test_window_changes_the_rendered_analysis(self, tmp_path: Path) -> None:
        entries = [
            _nav(),
            HarEntry(
                started_at=_T0 + datetime.timedelta(seconds=3),
                time_ms=1.0,
                request=HarRequest(
                    method="GET",
                    url="https://example.com/app.js",
                    http_version="1.1",
                    headers=(HarHeader("Referer", "https://example.com/login"),),
                    body=b"",
                ),
                response=HarResponse(
                    status=200,
                    status_text="OK",
                    http_version="1.1",
                    headers=(HarHeader("Content-Type", "application/javascript"),),
                    body=b"x",
                ),
            ),
        ]
        narrow = write_capture_outputs(tmp_path / "narrow", entries, _metadata())
        wide = write_capture_outputs(tmp_path / "wide", entries, _metadata(cluster_window_ms=5000))
        assert "**Assets loaded" not in narrow.analysis_path.read_text(encoding="utf-8")
        assert "**Assets loaded (1):**" in wide.analysis_path.read_text(encoding="utf-8")


class TestRerenderIsStable:
    def test_rendering_the_same_input_twice_matches_byte_for_byte(self, tmp_path: Path) -> None:
        """What makes `capture analyze` safe to re-run on a capture."""
        entries = [_nav(), _xhr(1.0)]
        first = write_capture_outputs(tmp_path / "a", entries, _metadata())
        second = write_capture_outputs(tmp_path / "b", entries, _metadata())
        for attr in ("raw_har_path", "manifest_path", "analysis_path"):
            assert getattr(first, attr).read_text(encoding="utf-8") == getattr(
                second, attr
            ).read_text(encoding="utf-8")
