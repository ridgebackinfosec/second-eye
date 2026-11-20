"""Tests for the daemon-free capture commands: analyze, recover, list.

These three are what make a finished capture revisitable. All work
against whatever is on disk, with no daemon running, which is the point:
before them a capture was frozen at whichever renderer version produced
it, and `capture list` could only report captures from the daemon run
that was still alive.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from secondeye import cli
from secondeye.analysis.pipeline import CaptureMetadata, write_capture_outputs
from secondeye.capture.buffer import CaptureBuffer
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse
from secondeye.capture.store import BUFFER_FILENAME

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


def _capture(
    captures_dir: Path,
    *,
    day: str = "2026-11-18",
    name: str = "auth-flow-test",
    entries: list[HarEntry] | None = None,
) -> Path:
    output_dir = captures_dir / f"{day}_example-com" / name
    started_at = datetime.datetime.fromisoformat(f"{day}T09:15:00+00:00")
    write_capture_outputs(
        output_dir,
        entries if entries is not None else [_entry()],
        CaptureMetadata(
            name=name,
            started_at=started_at,
            ended_at=started_at + datetime.timedelta(minutes=1),
            targets=["example.com"],
            no_upstream=True,
        ),
    )
    return output_dir


def _run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = cli.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


class TestCaptureAnalyze:
    def test_rerenders_analysis_and_manifest_in_place(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = _capture(tmp_path)
        (output_dir / "ANALYSIS.md").write_text("clobbered", encoding="utf-8")
        code, out, _err = _run(capsys, "capture", "analyze", str(output_dir))
        assert code == 0
        assert (
            (output_dir / "ANALYSIS.md")
            .read_text(encoding="utf-8")
            .startswith("# Second-Eye Capture Analysis")
        )
        assert "auth-flow-test" in out

    def test_needs_no_running_daemon(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # No daemon fixture here at all: that is the assertion.
        output_dir = _capture(tmp_path)
        code, _out, _err = _run(capsys, "capture", "analyze", str(output_dir))
        assert code == 0

    def test_leaves_raw_har_byte_identical(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Re-analysis must never alter the ground truth it derives from."""
        output_dir = _capture(tmp_path, entries=[_entry("/a"), _entry("/b")])
        before = (output_dir / "raw.har").read_bytes()
        _run(capsys, "capture", "analyze", str(output_dir))
        assert (output_dir / "raw.har").read_bytes() == before

    def test_cluster_window_override_changes_the_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        asset = HarEntry(
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
        )
        output_dir = _capture(tmp_path, entries=[_entry(), asset])
        analysis = output_dir / "ANALYSIS.md"
        assert "**Assets loaded" not in analysis.read_text(encoding="utf-8")

        code, _out, _err = _run(
            capsys, "capture", "analyze", str(output_dir), "--cluster-window", "5000"
        )
        assert code == 0
        assert "**Assets loaded (1):**" in analysis.read_text(encoding="utf-8")

    def test_missing_directory_fails_with_a_clear_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _out, err = _run(capsys, "capture", "analyze", str(tmp_path / "nope"))
        assert code == 1
        assert "not a directory" in err

    def test_directory_without_a_manifest_fails_rather_than_guessing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = _capture(tmp_path)
        (output_dir / "manifest.json").unlink()
        code, _out, err = _run(capsys, "capture", "analyze", str(output_dir))
        assert code == 1
        assert "manifest.json" in err


class TestCaptureRecover:
    def _orphaned_buffer(self, tmp_path: Path, entries: list[HarEntry]) -> Path:
        """A capture directory as a killed daemon would leave it."""
        output_dir = tmp_path / "2026-11-18_example-com" / "crashed-run"
        output_dir.mkdir(parents=True)
        buffer = CaptureBuffer(output_dir / BUFFER_FILENAME)
        for entry in entries:
            buffer._append_sync(entry)
        # No close(), no stop_capture(): the daemon died.
        return output_dir

    def test_writes_all_three_outputs_from_a_leftover_buffer(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry("/a"), _entry("/b")])
        code, out, _err = _run(capsys, "capture", "recover", str(output_dir))
        assert code == 0
        assert (output_dir / "raw.har").is_file()
        assert (output_dir / "manifest.json").is_file()
        assert (output_dir / "ANALYSIS.md").is_file()
        assert "2 requests" in out

    def test_recovers_every_buffered_entry(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry("/a"), _entry("/b"), _entry("/c")])
        _run(capsys, "capture", "recover", str(output_dir))
        har = json.loads((output_dir / "raw.har").read_text(encoding="utf-8"))
        assert len(har["log"]["entries"]) == 3

    def test_accepts_a_direct_path_to_the_buffer_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry()])
        code, _out, _err = _run(capsys, "capture", "recover", str(output_dir / BUFFER_FILENAME))
        assert code == 0
        assert (output_dir / "ANALYSIS.md").is_file()

    def test_removes_the_buffer_once_recovered(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry()])
        _run(capsys, "capture", "recover", str(output_dir))
        assert not (output_dir / BUFFER_FILENAME).exists()

    def test_keeps_the_buffer_when_asked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry()])
        _run(capsys, "capture", "recover", str(output_dir), "--keep-buffer")
        assert (output_dir / BUFFER_FILENAME).is_file()

    def test_derives_the_capture_name_from_the_directory(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry()])
        _run(capsys, "capture", "recover", str(output_dir))
        manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["capture"]["name"] == "crashed-run"

    def test_explicit_name_overrides_the_directory(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = self._orphaned_buffer(tmp_path, [_entry()])
        _run(capsys, "capture", "recover", str(output_dir), "--name", "renamed")
        manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["capture"]["name"] == "renamed"

    def test_no_buffer_present_fails_with_a_clear_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        clean = _capture(tmp_path)
        code, _out, err = _run(capsys, "capture", "recover", str(clean))
        assert code == 1
        assert "nothing to recover" in err

    def test_recovered_scope_is_recorded_as_unknown_not_invented(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A buffer carries no scope configuration, and fabricating one
        # would put false provenance in the manifest.
        output_dir = self._orphaned_buffer(tmp_path, [_entry()])
        _run(capsys, "capture", "recover", str(output_dir))
        manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["scope"]["targets"] == []


class TestCaptureListFromDisk:
    def test_lists_captures_with_no_daemon_running(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _capture(tmp_path, name="first")
        _capture(tmp_path, name="second")
        code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(tmp_path))
        assert code == 0
        assert "first" in out
        assert "second" in out

    def test_lists_captures_from_previous_runs(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _capture(tmp_path, day="2026-11-01", name="last-week")
        code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(tmp_path))
        assert code == 0
        assert "last-week" in out

    def test_reports_counts_and_findings(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        jwt = (
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            b"dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        _capture(tmp_path, name="withfindings", entries=[_entry(body=jwt)])
        _code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(tmp_path))
        assert "withfindings" in out
        assert "1" in out

    def test_empty_directory_says_so(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(tmp_path))
        assert code == 0
        assert "No captures" in out

    def test_newest_capture_listed_first(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _capture(tmp_path, day="2026-11-01", name="older")
        _capture(tmp_path, day="2026-11-18", name="newer")
        _code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(tmp_path))
        assert out.index("newer") < out.index("older")
