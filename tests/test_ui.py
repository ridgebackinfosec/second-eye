"""Tests for secondeye.ui — the rich-based terminal presentation layer.

The colour-safety tests here are the regression guard for the whole
module: secondeye's output must stay readable on a *light* terminal
(the primary target) as well as a dark one. That holds only while the
module sticks to the 16 ANSI colours plus the bold/dim attributes, which
the user's own terminal theme resolves against its own background.
Absolute values — 256-colour ``greyNN``, truecolor hex, or a literal
``white``/``black`` — silently assume a background and break the other
theme.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
from collections.abc import Iterator

import pytest

from secondeye import ui

_ESC = re.compile(r"\x1b\[[0-9;]*m")
# 256-colour (38;5;N) and truecolor (38;2;R;G;B) foreground selectors.
_ABSOLUTE_COLOUR = re.compile(r"\x1b\[[0-9;]*38;[25];")
# Literal white/black foregrounds: 30 (black), 37 (white), 90 (bright black),
# 97 (bright white). Each assumes a background to sit on.
_LITERAL_MONOCHROME = re.compile(r"\x1b\[(?:[0-9;]*;)?(?:30|37|90|97)(?:;[0-9;]*)?m")


@contextlib.contextmanager
def _console_width(columns: int) -> Iterator[None]:
    """Pin rich's detected terminal width for one render."""
    previous = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = str(columns)
    try:
        yield
    finally:
        if previous is None:
            del os.environ["COLUMNS"]
        else:
            os.environ["COLUMNS"] = previous


def _ui(*, force_color: bool = True) -> tuple[ui.Ui, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    return ui.Ui(stdout=out, stderr=err, force_color=force_color), out, err


def _scope() -> ui.ScopeView:
    return ui.ScopeView(
        targets=("app.example-corp.com", "*.corp.internal"),
        target_regex=(r"^(dev|stg)-.*\.example-corp\.com$",),
    )


def _startup() -> ui.StartupView:
    return ui.StartupView(
        version="1.1.0",
        listen="127.0.0.1:8079",
        scope=_scope(),
        upstream="127.0.0.1:8080",
        captures_dir="~/.local/state/secondeye/captures",
    )


def _status(*, recording: bool) -> ui.StatusView:
    return ui.StatusView(
        version="1.1.0",
        listen="127.0.0.1:8079",
        scope=_scope(),
        upstream="127.0.0.1:8080",
        active=(
            ui.ActiveCaptureView(name="auth-flow-test", started_at="09:15:00", request_count=13)
            if recording
            else None
        ),
    )


def _all_renderings() -> list[tuple[str, str, str]]:
    """Render every surface once. Returns (label, stdout, stderr) triples."""
    rendered: list[tuple[str, str, str]] = []

    def run(label: str, action: str) -> None:
        u, out, err = _ui()
        getattr_target = {
            "startup_banner": lambda: u.startup_banner(_startup()),
            "startup_banner_new_ca": lambda: u.startup_banner(
                ui.StartupView(
                    version="1.1.0",
                    listen="127.0.0.1:8079",
                    scope=_scope(),
                    upstream=None,
                    captures_dir="~/.local/state/secondeye/captures",
                    ca_was_created=True,
                )
            ),
            "proxy_status_idle": lambda: u.proxy_status(_status(recording=False)),
            "proxy_status_recording": lambda: u.proxy_status(_status(recording=True)),
            "capture_started": lambda: u.capture_started(
                ui.CaptureStartedView(
                    name="auth-flow-test",
                    started_at="2026-11-18 09:15:00 UTC",
                    output_dir="/home/op/captures/2026-11-18_app/auth-flow-test",
                    scope=_scope(),
                )
            ),
            "capture_stopped": lambda: u.capture_stopped(
                ui.CaptureStoppedView(name="auth-flow-test", request_count=13, total_bytes=1742)
            ),
            "capture_list": lambda: u.capture_list(
                [
                    ui.CaptureRow(
                        name="auth-flow-test",
                        request_count=13,
                        total_bytes=1742,
                        output_dir="/home/op/captures/a",
                    ),
                    ui.CaptureRow(
                        name="idor-probe-orders",
                        request_count=47,
                        total_bytes=1_283_402,
                        output_dir="/home/op/captures/b",
                    ),
                ]
            ),
            "ca_status": lambda: u.ca_status(
                ui.CaStatusView(
                    cert_path="/home/x/.local/state/secondeye/ca/secondeye-ca.pem",
                    subject="secondeye Root CA",
                    serial=12345678901234567890,
                    fingerprint="AA:BB:CC",
                    valid_from="2026-01-01 00:00:00 UTC",
                    valid_until="2036-01-01 00:00:00 UTC",
                    expired=False,
                    days=3650,
                )
            ),
            "ca_status_expired": lambda: u.ca_status(
                ui.CaStatusView(
                    cert_path="/x/ca.pem",
                    subject="secondeye Root CA",
                    serial=1,
                    fingerprint="AA",
                    valid_from="2020-01-01 00:00:00 UTC",
                    valid_until="2021-01-01 00:00:00 UTC",
                    expired=True,
                    days=42,
                )
            ),
            "success": lambda: u.success("secondeye daemon stopping."),
            "error": lambda: u.error("No running secondeye daemon found."),
            "error_with_hint": lambda: u.error(
                "Cannot start capture: no running daemon.",
                "Run 'secondeye proxy start --target <domain>' first.",
            ),
            "warn": lambda: u.warn("--upstream-insecure set."),
            "plain": lambda: u.plain("No captures recorded yet this run."),
        }[action]
        getattr_target()
        rendered.append((label, out.getvalue(), err.getvalue()))

    for action in (
        "startup_banner",
        "startup_banner_new_ca",
        "proxy_status_idle",
        "proxy_status_recording",
        "capture_started",
        "capture_stopped",
        "capture_list",
        "ca_status",
        "ca_status_expired",
        "success",
        "error",
        "error_with_hint",
        "warn",
        "plain",
    ):
        run(action, action)
    return rendered


class TestFormatBytes:
    def test_small_values_in_bytes(self) -> None:
        assert ui.format_bytes(500) == "500B"

    def test_kilobyte_values(self) -> None:
        assert ui.format_bytes(4300) == "4.2KB"

    def test_megabyte_values(self) -> None:
        assert ui.format_bytes(4_400_000) == "4.2MB"

    def test_zero(self) -> None:
        assert ui.format_bytes(0) == "0B"


class TestColourSafety:
    """Light-terminal readability, enforced structurally rather than by eye."""

    @pytest.mark.parametrize("label", [r[0] for r in _all_renderings()])
    def test_no_absolute_colour_values_anywhere(self, label: str) -> None:
        for name, out, err in _all_renderings():
            if name != label:
                continue
            for stream in (out, err):
                assert not _ABSOLUTE_COLOUR.search(stream), (
                    f"{name} emitted a 256-colour/truecolor value; these assume a "
                    "background and break on the opposite terminal theme"
                )

    @pytest.mark.parametrize("label", [r[0] for r in _all_renderings()])
    def test_no_literal_white_or_black_foreground(self, label: str) -> None:
        for name, out, err in _all_renderings():
            if name != label:
                continue
            for stream in (out, err):
                assert not _LITERAL_MONOCHROME.search(stream), (
                    f"{name} emitted a literal white/black foreground; use bold or "
                    "dim so the terminal's own foreground colour is used instead"
                )

    def test_renderings_do_emit_some_colour_when_forced(self) -> None:
        # Guards the tests above from passing trivially because nothing is styled.
        joined = "".join(out + err for _n, out, err in _all_renderings())
        assert _ESC.search(joined), "forced-colour rendering produced no ANSI at all"

    def test_no_color_env_disables_all_escapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        u, out, _err = _ui(force_color=False)
        u.startup_banner(_startup())
        assert not _ESC.search(out.getvalue())

    def test_non_tty_stream_disables_all_escapes(self) -> None:
        u, out, _err = _ui(force_color=False)  # StringIO is not a tty
        u.startup_banner(_startup())
        assert not _ESC.search(out.getvalue())


class TestStreamRouting:
    """SPEC.md §7: stdout stays clean; diagnostics go to stderr."""

    def test_error_goes_to_stderr_only(self) -> None:
        u, out, err = _ui(force_color=False)
        u.error("boom")
        assert "boom" in err.getvalue()
        assert out.getvalue() == ""

    def test_warn_goes_to_stderr_only(self) -> None:
        u, out, err = _ui(force_color=False)
        u.warn("careful")
        assert "careful" in err.getvalue()
        assert out.getvalue() == ""

    def test_success_goes_to_stdout_only(self) -> None:
        u, out, err = _ui(force_color=False)
        u.success("done")
        assert "done" in out.getvalue()
        assert err.getvalue() == ""

    def test_error_detail_lines_appear_on_stderr(self) -> None:
        u, _out, err = _ui(force_color=False)
        u.error("headline", "a follow-up hint")
        assert "headline" in err.getvalue()
        assert "a follow-up hint" in err.getvalue()


class TestNoTrailingWhitespace:
    """Key/value blocks must not pad lines out to a column width.

    capture_list is exempt: it is a rich Table, and table renderers pad
    cells to their column width by design.
    """

    @pytest.mark.parametrize(
        "label",
        [r[0] for r in _all_renderings() if r[0] != "capture_list"],
    )
    def test_no_line_has_trailing_whitespace(self, label: str) -> None:
        for name, out, err in _all_renderings():
            if name != label:
                continue
            for stream in (out, err):
                for line in _ESC.sub("", stream).splitlines():
                    assert line == line.rstrip(), f"{name}: trailing whitespace in {line!r}"


class TestStartupBanner:
    def _render(self, view: ui.StartupView) -> str:
        u, out, _err = _ui(force_color=False)
        u.startup_banner(view)
        return out.getvalue()

    def test_shows_listen_address(self) -> None:
        assert "127.0.0.1:8079" in self._render(_startup())

    def test_shows_every_target_and_regex(self) -> None:
        text = self._render(_startup())
        assert "app.example-corp.com" in text
        assert "*.corp.internal" in text
        assert r"^(dev|stg)-.*\.example-corp\.com$" in text

    def test_shows_upstream_when_chaining(self) -> None:
        assert "127.0.0.1:8080" in self._render(_startup())

    def test_shows_no_upstream_marker_when_direct(self) -> None:
        view = ui.StartupView(
            version="1.1.0",
            listen="127.0.0.1:8079",
            scope=_scope(),
            upstream=None,
            captures_dir="/home/op/captures/c",
        )
        assert "--no-upstream" in self._render(view)

    def test_points_the_operator_at_capture_start(self) -> None:
        assert "capture start" in self._render(_startup())

    def test_first_run_ca_note_shown_only_when_ca_was_created(self) -> None:
        assert "ca export" not in self._render(_startup())
        view = ui.StartupView(
            version="1.1.0",
            listen="127.0.0.1:8079",
            scope=_scope(),
            upstream=None,
            captures_dir="/home/op/captures/c",
            ca_was_created=True,
        )
        assert "ca export" in self._render(view)

    def test_shows_target_all_when_scope_is_bypassed(self) -> None:
        view = ui.StartupView(
            version="1.1.0",
            listen="127.0.0.1:8079",
            scope=ui.ScopeView(targets=(), target_all=True),
            upstream=None,
            captures_dir="/home/op/captures/c",
        )
        assert "--target-all" in self._render(view)


class TestProxyStatus:
    def _render(self, *, recording: bool) -> str:
        u, out, _err = _ui(force_color=False)
        u.proxy_status(_status(recording=recording))
        return out.getvalue()

    def test_idle_says_idle(self) -> None:
        assert "idle" in self._render(recording=False)

    def test_recording_shows_name_and_live_request_count(self) -> None:
        text = self._render(recording=True)
        assert "auth-flow-test" in text
        assert "13" in text
        assert "09:15:00" in text

    def test_idle_does_not_mention_a_capture_name(self) -> None:
        assert "auth-flow-test" not in self._render(recording=False)


class TestCaptureOutputs:
    def test_started_shows_name_output_dir_and_next_step(self) -> None:
        u, out, _err = _ui(force_color=False)
        u.capture_started(
            ui.CaptureStartedView(
                name="auth-flow-test",
                started_at="2026-11-18 09:15:00 UTC",
                output_dir="/home/op/captures/x/auth-flow-test",
                scope=_scope(),
            )
        )
        text = out.getvalue()
        assert "auth-flow-test" in text
        assert "/home/op/captures/x/auth-flow-test" in text
        assert "capture stop" in text

    def test_stopped_shows_counts_and_human_readable_size(self) -> None:
        u, out, _err = _ui(force_color=False)
        u.capture_stopped(
            ui.CaptureStoppedView(name="auth-flow-test", request_count=13, total_bytes=1742)
        )
        text = out.getvalue()
        assert "auth-flow-test" in text
        assert "13" in text
        assert "1.7KB" in text

    def test_stopped_points_at_analysis_md(self) -> None:
        u, out, _err = _ui(force_color=False)
        u.capture_stopped(
            ui.CaptureStoppedView(
                name="c", request_count=1, total_bytes=1, output_dir="/home/op/captures/c"
            )
        )
        assert "ANALYSIS.md" in out.getvalue()

    def test_list_renders_one_row_per_capture(self) -> None:
        u, out, _err = _ui(force_color=False)
        u.capture_list(
            [
                ui.CaptureRow(
                    name="auth-flow-test",
                    request_count=13,
                    total_bytes=1742,
                    output_dir="/home/op/captures/a",
                ),
                ui.CaptureRow(
                    name="idor-probe",
                    request_count=47,
                    total_bytes=1_283_402,
                    output_dir="/home/op/captures/b",
                ),
            ]
        )
        text = out.getvalue()
        assert "auth-flow-test" in text
        assert "idor-probe" in text
        assert "1.7KB" in text
        assert "1.2MB" in text


class TestCaStatus:
    def test_shows_fingerprint_and_remaining_validity(self) -> None:
        u, out, _err = _ui(force_color=False)
        u.ca_status(
            ui.CaStatusView(
                cert_path="/x/ca.pem",
                subject="secondeye Root CA",
                serial=7,
                fingerprint="AA:BB:CC",
                valid_from="2026-01-01 00:00:00 UTC",
                valid_until="2036-01-01 00:00:00 UTC",
                expired=False,
                days=3650,
            )
        )
        text = out.getvalue()
        assert "AA:BB:CC" in text
        assert "3650" in text

    def test_expired_ca_is_called_out(self) -> None:
        u, out, _err = _ui(force_color=False)
        u.ca_status(
            ui.CaStatusView(
                cert_path="/x/ca.pem",
                subject="secondeye Root CA",
                serial=7,
                fingerprint="AA",
                valid_from="2020-01-01 00:00:00 UTC",
                valid_until="2021-01-01 00:00:00 UTC",
                expired=True,
                days=42,
            )
        )
        assert "EXPIRED" in out.getvalue()


class TestScopeView:
    def test_summary_joins_targets_and_regexes(self) -> None:
        assert "app.example-corp.com" in _scope().summary()
        assert r"^(dev|stg)-.*\.example-corp\.com$" in _scope().summary()

    def test_summary_marks_target_all(self) -> None:
        assert "--target-all" in ui.ScopeView(targets=(), target_all=True).summary()

    def test_summary_of_empty_scope(self) -> None:
        assert ui.ScopeView(targets=()).summary() == "(none)"


class TestCaptureListLayout:
    """`capture list` has to stay legible at 80 columns.

    rich shrinks table columns proportionally, which at narrow widths
    first mangles short headers into "R…"/"SI…", then blanks cells while
    keeping their headers, and finally clips the last column -- which
    rendered a start date as a bare "2026-". The narrow columns are
    pinned with min_width and CAPTURE is capped with max_width so the
    only thing that ever degrades is an over-long capture name.
    """

    ROWS = [
        ui.CaptureRow(
            name="a-deliberately-long-capture-name-for-an-engagement",
            request_count=112,
            total_bytes=4_019_118,
            output_dir="/captures/x",
            target="staging.internal.corp.example.net",
            finding_count=7,
            started_at="2026-11-17 16:02",
        ),
        ui.CaptureRow(
            name="auth-flow-test",
            request_count=13,
            total_bytes=1742,
            output_dir="/captures/y",
            target="app.example-corp.com",
            finding_count=0,
            started_at="2026-11-18 09:15",
            active=True,
        ),
    ]

    def _render(self, columns: int, *, captures_dir: str | None = "/captures") -> str:
        out, err = io.StringIO(), io.StringIO()
        with _console_width(columns):
            ui.Ui(stdout=out, stderr=err, force_color=False).capture_list(
                self.ROWS, captures_dir=captures_dir
            )
        return _ESC.sub("", out.getvalue())

    @pytest.mark.parametrize("columns", [70, 80, 100, 140])
    def test_never_exceeds_the_terminal_width(self, columns: int) -> None:
        for line in self._render(columns).splitlines():
            assert len(line) <= columns, f"{len(line)} > {columns}: {line!r}"

    @pytest.mark.parametrize("columns", [70, 80, 100, 140])
    def test_every_header_stays_intact(self, columns: int) -> None:
        header = self._render(columns).splitlines()[0]
        for column in ("CAPTURE", "REQS", "SIZE", "SIG", "STARTED"):
            assert column in header, f"{column} mangled at {columns} columns"

    @pytest.mark.parametrize("columns", [80, 100, 140])
    def test_narrow_columns_keep_their_whole_values(self, columns: int) -> None:
        text = self._render(columns)
        assert "112" in text
        assert "3.8MB" in text
        assert "7" in text
        # The timestamp in particular: clipping it to "2026-" was the bug
        # that capping CAPTURE fixed.
        assert "2026-11-17 16:02" in text

    def test_a_short_name_is_never_truncated(self) -> None:
        assert "auth-flow-test" in self._render(80)

    def test_an_over_long_name_truncates_rather_than_starving_other_columns(self) -> None:
        text = self._render(80)
        assert "a-deliberately-long-capture-name" in text
        assert "…" in text
        assert "2026-11-17 16:02" in text

    def test_captures_directory_is_printed_whole_in_the_footer(self) -> None:
        captures_dir = "/home/operator/.local/state/secondeye/captures"
        footer = [
            line
            for line in self._render(80, captures_dir=captures_dir).splitlines()
            if "capture(s) in" in line
        ]
        assert footer, "no captures-directory footer was printed"
        assert captures_dir in footer[0]
        assert "…" not in footer[0]

    def test_targets_are_named_when_the_listing_spans_more_than_one(self) -> None:
        text = self._render(80)
        assert "targets:" in text
        assert "app.example-corp.com" in text
        assert "staging.internal.corp.example.net" in text

    def test_targets_line_is_omitted_for_a_single_target(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        ui.Ui(stdout=out, stderr=err, force_color=False).capture_list(
            [
                ui.CaptureRow(
                    name="only",
                    request_count=1,
                    total_bytes=1,
                    output_dir="/captures/z",
                    target="app.example-corp.com",
                )
            ],
            captures_dir="/captures",
        )
        assert "targets:" not in _ESC.sub("", out.getvalue())

    def test_findings_column_shows_a_dash_when_nothing_was_found(self) -> None:
        assert "—" in self._render(80)

    def test_active_capture_is_marked_and_the_marker_explained(self) -> None:
        text = self._render(80)
        assert "●" in text
        assert "active" in text


class TestColourEnvironmentConventions:
    """FORCE_COLOR / NO_COLOR, as the wider CLI ecosystem defines them."""

    def test_force_color_env_enables_colour_through_a_pipe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        u, out, _err = _ui(force_color=False)  # StringIO is not a tty
        u.startup_banner(_startup())
        assert _ESC.search(out.getvalue())

    def test_empty_no_color_is_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # no-color.org: honour the variable only when set AND non-empty.
        # scripts/generate_doc_examples.py sets NO_COLOR="" alongside
        # FORCE_COLOR=1, and expects the empty value to mean "unset".
        monkeypatch.setenv("NO_COLOR", "")
        monkeypatch.setenv("FORCE_COLOR", "1")
        u, out, _err = _ui(force_color=False)
        u.startup_banner(_startup())
        assert _ESC.search(out.getvalue())

    def test_no_color_beats_force_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("FORCE_COLOR", "1")
        u, out, _err = _ui(force_color=True)
        u.startup_banner(_startup())
        assert not _ESC.search(out.getvalue())
