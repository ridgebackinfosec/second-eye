"""Tests for secondeye.capture.buffer (SPEC.md §6.3, §14 Phase 6)."""

import datetime
import json
from pathlib import Path

from secondeye.capture.buffer import CaptureBuffer, read_buffer
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse


def _entry(path: str, body: bytes = b"") -> HarEntry:
    return HarEntry(
        started_at=datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC),
        time_ms=1.0,
        request=HarRequest(
            method="GET",
            url=f"https://example.com{path}",
            http_version="1.1",
            headers=(HarHeader("Host", "example.com"),),
            body=b"",
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "text/plain"),),
            body=body,
        ),
    )


class TestCaptureBufferAppendAndFlush:
    async def test_append_writes_one_jsonl_line_per_entry(self, tmp_path: Path) -> None:
        path = tmp_path / "buffer.jsonl"
        buffer = CaptureBuffer(path)
        try:
            await buffer.append(_entry("/a"))
            await buffer.append(_entry("/b"))
        finally:
            buffer.close()

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["request"]["url"] == "https://example.com/a"
        assert json.loads(lines[1])["request"]["url"] == "https://example.com/b"

    async def test_each_append_is_flushed_immediately_not_batched(self, tmp_path: Path) -> None:
        # SPEC.md §6.3: flushed to disk as each pair completes, not batched
        # in memory — verified by reading the file WHILE the buffer (and its
        # underlying file handle) is still open, before close().
        path = tmp_path / "buffer.jsonl"
        buffer = CaptureBuffer(path)
        try:
            await buffer.append(_entry("/a"))
            on_disk = path.read_text(encoding="utf-8")
            assert "https://example.com/a" in on_disk
        finally:
            buffer.close()

    async def test_creates_parent_directories(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "dir" / "buffer.jsonl"
        buffer = CaptureBuffer(path)
        try:
            await buffer.append(_entry("/a"))
        finally:
            buffer.close()
        assert path.exists()


class TestReadBuffer:
    async def test_reads_back_entries_in_order(self, tmp_path: Path) -> None:
        path = tmp_path / "buffer.jsonl"
        buffer = CaptureBuffer(path)
        try:
            await buffer.append(_entry("/a", body=b"first"))
            await buffer.append(_entry("/b", body=b"second"))
            await buffer.append(_entry("/c", body=b"third"))
        finally:
            buffer.close()

        entries = read_buffer(path)
        assert [e.request.url for e in entries] == [
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c",
        ]
        assert [e.response.body for e in entries] == [b"first", b"second", b"third"]

    def test_reads_empty_file_as_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.jsonl"
        path.write_text("", encoding="utf-8")
        assert read_buffer(path) == []

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "buffer.jsonl"
        entry_dict = _entry("/a").to_har_dict()
        path.write_text(f"\n{json.dumps(entry_dict)}\n\n", encoding="utf-8")
        entries = read_buffer(path)
        assert len(entries) == 1
        assert entries[0].request.url == "https://example.com/a"

    async def test_round_trips_binary_body_exactly(self, tmp_path: Path) -> None:
        path = tmp_path / "buffer.jsonl"
        binary_body = bytes(range(256))
        buffer = CaptureBuffer(path)
        try:
            await buffer.append(_entry("/image.png", body=binary_body))
        finally:
            buffer.close()

        entries = read_buffer(path)
        assert entries[0].response.body == binary_body
