"""Tests for secondeye.capture.store — reading captures back off disk.

Until this existed, a capture was write-once: `capture list` answered
from an in-memory history that died with the daemon, and nothing could
re-read a finished capture at all. These functions are what let
`capture list`, `capture analyze` and `capture recover` work against the
filesystem, with no daemon running.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from secondeye.analysis.pipeline import CaptureMetadata, write_capture_outputs
from secondeye.capture.buffer import CaptureBuffer
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse
from secondeye.capture.store import (
    BUFFER_FILENAME,
    discover_captures,
    find_buffer,
    load_capture,
)
from secondeye.exceptions import CaptureStoreError

_T0 = datetime.datetime(2026, 11, 18, 9, 15, 0, tzinfo=datetime.UTC)


def _entry(path: str = "/login", body: bytes = b"<html/>") -> HarEntry:
    return HarEntry(
        started_at=_T0,
        time_ms=5.0,
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


def _write_capture(
    captures_dir: Path,
    *,
    day: str = "2026-11-18",
    label: str = "example-com",
    name: str = "auth-flow-test",
    entries: list[HarEntry] | None = None,
    targets: list[str] | None = None,
) -> Path:
    output_dir = captures_dir / f"{day}_{label}" / name
    # Derive the manifest timestamp from `day` so a capture written into a
    # given date directory actually claims that date, as a real one does.
    started_at = datetime.datetime.fromisoformat(f"{day}T09:15:00+00:00")
    write_capture_outputs(
        output_dir,
        entries if entries is not None else [_entry()],
        CaptureMetadata(
            name=name,
            started_at=started_at,
            ended_at=started_at + datetime.timedelta(minutes=1),
            targets=targets or ["example.com"],
            no_upstream=True,
        ),
    )
    return output_dir


class TestLoadCapture:
    def test_reads_entries_back_from_raw_har(self, tmp_path: Path) -> None:
        output_dir = _write_capture(tmp_path, entries=[_entry("/a"), _entry("/b")])
        loaded = load_capture(output_dir)
        assert len(loaded.entries) == 2
        assert loaded.entries[0].request.url.endswith("/a")

    def test_reads_metadata_back_from_the_manifest(self, tmp_path: Path) -> None:
        output_dir = _write_capture(tmp_path, targets=["a.example", "b.example"])
        loaded = load_capture(output_dir)
        assert loaded.metadata.name == "auth-flow-test"
        assert loaded.metadata.targets == ["a.example", "b.example"]
        assert loaded.metadata.started_at == _T0

    def test_round_trips_byte_for_byte_through_the_pipeline(self, tmp_path: Path) -> None:
        """The property `capture analyze` depends on: reload, re-render, same bytes."""
        output_dir = _write_capture(tmp_path, entries=[_entry("/a"), _entry("/b")])
        original = (output_dir / "ANALYSIS.md").read_text(encoding="utf-8")
        loaded = load_capture(output_dir)
        rerendered = write_capture_outputs(tmp_path / "again", loaded.entries, loaded.metadata)
        assert rerendered.analysis_path.read_text(encoding="utf-8") == original

    def test_missing_directory_is_a_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(CaptureStoreError, match="not a directory"):
            load_capture(tmp_path / "nope")

    def test_missing_raw_har_is_a_clear_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(CaptureStoreError, match="raw.har"):
            load_capture(empty)

    def test_missing_manifest_is_a_clear_error_naming_the_file(self, tmp_path: Path) -> None:
        # A raw.har without a manifest can't supply the capture name,
        # scope or window, and guessing them would silently fabricate
        # provenance into the re-rendered output.
        output_dir = _write_capture(tmp_path)
        (output_dir / "manifest.json").unlink()
        with pytest.raises(CaptureStoreError, match="manifest.json"):
            load_capture(output_dir)

    def test_unparseable_raw_har_is_a_clear_error(self, tmp_path: Path) -> None:
        output_dir = _write_capture(tmp_path)
        (output_dir / "raw.har").write_text("{not json", encoding="utf-8")
        with pytest.raises(CaptureStoreError, match="raw.har"):
            load_capture(output_dir)


class TestDiscoverCaptures:
    def test_empty_or_absent_directory_yields_nothing(self, tmp_path: Path) -> None:
        assert discover_captures(tmp_path / "absent") == []
        (tmp_path / "present").mkdir()
        assert discover_captures(tmp_path / "present") == []

    def test_finds_captures_across_date_directories(self, tmp_path: Path) -> None:
        _write_capture(tmp_path, day="2026-11-17", name="older")
        _write_capture(tmp_path, day="2026-11-18", name="newer")
        found = {c.name for c in discover_captures(tmp_path)}
        assert found == {"older", "newer"}

    def test_orders_newest_first(self, tmp_path: Path) -> None:
        _write_capture(tmp_path, day="2026-11-16", name="oldest")
        _write_capture(tmp_path, day="2026-11-18", name="newest")
        _write_capture(tmp_path, day="2026-11-17", name="middle")
        assert [c.name for c in discover_captures(tmp_path)] == [
            "newest",
            "middle",
            "oldest",
        ]

    def test_reports_counts_read_from_the_manifest(self, tmp_path: Path) -> None:
        _write_capture(tmp_path, entries=[_entry("/a"), _entry("/b")])
        summary = discover_captures(tmp_path)[0]
        assert summary.request_count == 2
        assert summary.total_bytes == len(b"<html/>") * 2
        assert summary.flow_count == 2
        assert summary.target == "example.com"

    def test_reports_findings_from_the_manifest(self, tmp_path: Path) -> None:
        jwt = (
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            b"dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        _write_capture(tmp_path, entries=[_entry(body=jwt)])
        assert discover_captures(tmp_path)[0].finding_count == 1

    def test_skips_directories_without_a_manifest(self, tmp_path: Path) -> None:
        _write_capture(tmp_path, name="real")
        junk = tmp_path / "2026-11-18_example-com" / "not-a-capture"
        junk.mkdir(parents=True)
        (junk / "stray.txt").write_text("hi", encoding="utf-8")
        assert [c.name for c in discover_captures(tmp_path)] == ["real"]

    def test_a_capture_with_a_corrupt_manifest_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        # One unreadable capture must not make `capture list` useless.
        _write_capture(tmp_path, name="good")
        broken = _write_capture(tmp_path, name="broken")
        (broken / "manifest.json").write_text("{not json", encoding="utf-8")
        assert [c.name for c in discover_captures(tmp_path)] == ["good"]

    def test_a_file_where_a_date_directory_belongs_is_ignored(self, tmp_path: Path) -> None:
        _write_capture(tmp_path, name="real")
        (tmp_path / "stray-file.txt").write_text("hi", encoding="utf-8")
        assert [c.name for c in discover_captures(tmp_path)] == ["real"]


class TestFindBuffer:
    def _buffer(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        buffer = CaptureBuffer(directory / BUFFER_FILENAME)
        buffer.close()
        return directory / BUFFER_FILENAME

    def test_accepts_a_direct_path_to_a_buffer_file(self, tmp_path: Path) -> None:
        path = self._buffer(tmp_path / "cap")
        assert find_buffer(path) == path

    def test_accepts_a_capture_directory_containing_one(self, tmp_path: Path) -> None:
        directory = tmp_path / "cap"
        path = self._buffer(directory)
        assert find_buffer(directory) == path

    def test_directory_without_a_buffer_is_a_clear_error(self, tmp_path: Path) -> None:
        directory = tmp_path / "cap"
        directory.mkdir()
        with pytest.raises(CaptureStoreError, match="no .* buffer"):
            find_buffer(directory)

    def test_nonexistent_path_is_a_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(CaptureStoreError):
            find_buffer(tmp_path / "nothing-here")

    def test_buffer_entries_are_readable_after_a_simulated_crash(self, tmp_path: Path) -> None:
        """A buffer is left behind when a daemon dies before `capture stop`."""
        directory = tmp_path / "crashed"
        directory.mkdir()
        buffer = CaptureBuffer(directory / BUFFER_FILENAME)
        for path in ("/one", "/two"):
            buffer._append_sync(_entry(path))
        # Deliberately no close(): the daemon was killed.
        from secondeye.capture.buffer import read_buffer

        entries = read_buffer(find_buffer(directory))
        assert [e.request.url.rsplit("/", 1)[-1] for e in entries] == ["one", "two"]


class TestManifestFilenameConstants:
    def test_buffer_filename_matches_what_the_manager_writes(self, tmp_path: Path) -> None:
        # store.py and recording/manager.py must agree on the buffer's
        # name, or `capture recover` silently finds nothing.
        from secondeye.recording import manager

        assert manager._BUFFER_FILENAME == BUFFER_FILENAME

    def test_discovered_capture_exposes_its_directory(self, tmp_path: Path) -> None:
        output_dir = _write_capture(tmp_path)
        assert discover_captures(tmp_path)[0].output_dir == output_dir
        assert json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))


class TestOrderingIsDeterministic:
    """Ordering must not depend on filesystem iteration order."""

    def test_captures_sharing_a_timestamp_order_stably_by_path(self, tmp_path: Path) -> None:
        for name in ("c-third", "a-first", "b-second"):
            output_dir = tmp_path / "2026-11-18_example-com" / name
            write_capture_outputs(
                output_dir,
                [_entry()],
                CaptureMetadata(
                    name=name,
                    started_at=_T0,
                    ended_at=_T0,
                    targets=["example.com"],
                    no_upstream=True,
                ),
            )
        # Identical timestamps, so the path tiebreak decides: descending.
        assert [c.name for c in discover_captures(tmp_path)] == [
            "c-third",
            "b-second",
            "a-first",
        ]

    def test_capture_with_unparseable_timestamp_sorts_last(self, tmp_path: Path) -> None:
        _write_capture(tmp_path, day="2026-11-16", name="dated")
        broken = _write_capture(tmp_path, day="2026-11-18", name="undated")
        manifest_path = broken / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        capture = manifest["capture"]
        assert isinstance(capture, dict)
        capture["started_at"] = "not-a-timestamp"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert [c.name for c in discover_captures(tmp_path)] == ["dated", "undated"]
