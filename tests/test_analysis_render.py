"""Tests for secondeye.analysis.render (SPEC.md §11.6, §11.7, Appendix A, §14 Phase 6)."""

import datetime

from secondeye.analysis.classify import classify_entries
from secondeye.analysis.manifest import build_flows
from secondeye.analysis.render import render_analysis_md
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse

_T0 = datetime.datetime(2026, 9, 15, 14, 2, 0, tzinfo=datetime.UTC)


def _at(offset_seconds: float) -> datetime.datetime:
    return _T0 + datetime.timedelta(seconds=offset_seconds)


def _nav_entry(
    at: datetime.datetime,
    url: str,
    status: int = 200,
    location: str | None = None,
    body: bytes = b"",
) -> HarEntry:
    response_headers = [HarHeader("Content-Type", "text/html")]
    if location is not None:
        response_headers.append(HarHeader("Location", location))
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(
            method="GET",
            url=url,
            http_version="1.1",
            headers=(HarHeader("Sec-Fetch-Mode", "navigate"),),
            body=b"",
        ),
        response=HarResponse(
            status=status,
            status_text="OK",
            http_version="1.1",
            headers=tuple(response_headers),
            body=body,
        ),
    )


def _xhr_entry(
    at: datetime.datetime,
    url: str,
    referer: str | None = None,
    body: bytes = b'{"ok":true}',
    request_body: bytes = b"",
) -> HarEntry:
    headers = [HarHeader("X-Requested-With", "XMLHttpRequest"), HarHeader("Sec-Fetch-Mode", "cors")]
    if referer is not None:
        headers.append(HarHeader("Referer", referer))
    method = "POST" if request_body else "GET"
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(
            method=method, url=url, http_version="1.1", headers=tuple(headers), body=request_body
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "application/json"),),
            body=body,
        ),
    )


def _static_entry(
    at: datetime.datetime,
    url: str,
    content_type: str,
    body: bytes = b"x",
    referer: str = "https://example.com/login",
) -> HarEntry:
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(
            method="GET",
            url=url,
            http_version="1.1",
            headers=(HarHeader("Referer", referer),),
            body=b"",
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", content_type),),
            body=body,
        ),
    )


def _other_entry(at: datetime.datetime, url: str, status: int = 204, body: bytes = b"") -> HarEntry:
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(method="GET", url=url, http_version="1.1", headers=(), body=b""),
        response=HarResponse(
            status=status, status_text="No Content", http_version="1.1", headers=(), body=body
        ),
    )


def _render(entries: list[HarEntry], capture_name: str = "test-capture") -> str:
    classified = classify_entries(entries)
    flows = build_flows(classified)
    return render_analysis_md(
        capture_name=capture_name,
        targets=["example.com"],
        started_at=_at(0),
        ended_at=_at(100),
        classified=classified,
        flows=flows,
    )


class TestHeaderBlock:
    def test_header_contains_capture_name_targets_and_raw_har_pointer(self) -> None:
        md = _render(
            [_nav_entry(_at(0), "https://example.com/login")], capture_name="auth-flow-test"
        )
        assert "auth-flow-test" in md
        assert "example.com" in md
        assert "raw.har" in md


class TestNavigationRendering:
    def test_short_body_rendered_inline_without_truncation_marker(self) -> None:
        md = _render([_nav_entry(_at(0), "https://example.com/login", body=b"<html>short</html>")])
        assert "<html>short</html>" in md
        assert "truncated" not in md

    def test_long_body_truncated_at_2000_chars_with_marker(self) -> None:
        long_body = ("<p>" + "x" * 3000 + "</p>").encode("ascii")
        md = _render([_nav_entry(_at(0), "https://example.com/login", body=long_body)])
        assert "truncated" in md
        assert str(len(long_body)) in md
        assert "x" * 3000 not in md  # full body must not appear verbatim

    def test_har_entry_index_cross_reference_present(self) -> None:
        md = _render([_nav_entry(_at(0), "https://example.com/login")])
        assert "har_entry_index: 0" in md


class TestXhrApiRendering:
    def test_request_and_response_body_not_truncated_even_if_large(self) -> None:
        big_json = ('{"data":"' + "y" * 5000 + '"}').encode("ascii")
        md = _render([_xhr_entry(_at(0), "https://example.com/api/big", body=big_json)])
        assert "y" * 5000 in md  # xhr-api is never truncated

    def test_referer_shown_in_flow_header(self) -> None:
        md = _render(
            [_xhr_entry(_at(0), "https://example.com/api/a", referer="https://example.com/login")]
        )
        assert "referer:" in md
        assert "/login" in md

    def test_request_body_rendered_when_present(self) -> None:
        md = _render(
            [_xhr_entry(_at(0), "https://example.com/api/login", request_body=b'{"user":"a"}')]
        )
        assert '"user"' in md


class TestOtherRendering:
    def test_small_body_rendered_inline(self) -> None:
        md = _render([_other_entry(_at(0), "https://example.com/heartbeat", body=b"pong")])
        assert "pong" in md

    def test_large_body_not_rendered_inline(self) -> None:
        big_body = b"z" * 600
        md = _render([_other_entry(_at(0), "https://example.com/heartbeat", body=big_body)])
        assert "z" * 600 not in md


class TestRedirectChainRendering:
    def test_collapsed_summary_and_hop_table_present(self) -> None:
        entries = [
            _nav_entry(
                _at(0), "https://example.com/dashboard", status=302, location="/dashboard/home"
            ),
            _nav_entry(_at(0.1), "https://example.com/dashboard/home", status=200, body=b"<html/>"),
        ]
        md = _render(entries)
        assert "redirect chain" in md
        assert "302" in md
        assert "Redirect chain detail" in md
        assert "| Hop | URL | Status | Location |" in md
        # Only ONE narrative flow section for the whole chain, not two.
        assert md.count("## Flow") == 1


class TestPollingNoteRendering:
    def test_note_present_on_first_occurrence_capped_at_three_plus_count(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(12)
        ]
        entries.append(
            _xhr_entry(
                _at(12 * 30),
                "https://api.example.com/v2/notifications/poll",
                body=b'{"unread":9}',
            )
        )
        md = _render(entries)
        assert "polling" in md
        assert "Note:" in md
        # 11 subsequent occurrences (indices 1-11) collapsed: cap display at
        # first 3 plus a count of the rest (SPEC.md §11.5).
        assert "more occurrences" in md
        # The state-change breakout (13th call, different body) gets its own
        # separate flow section, distinct from the collapsed note.
        assert md.count("## Flow") == 2

    def test_collapsed_occurrences_do_not_get_their_own_narrative_section(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(5)
        ]
        md = _render(entries)
        assert md.count("## Flow") == 1


class TestAssetAggregation:
    def test_assets_collapsed_into_summary_line_under_parent_navigation(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _static_entry(_at(0.1), "https://example.com/app.js", "application/javascript"),
            _static_entry(_at(0.1), "https://example.com/app2.js", "application/javascript"),
            _static_entry(_at(0.1), "https://example.com/app.css", "text/css"),
        ]
        md = _render(entries)
        assert "Assets loaded (3)" in md
        assert "2x JS" in md
        assert "1x CSS" in md
        # No individual flow sections for the static assets themselves.
        assert md.count("## Flow") == 1


class TestFlowOrderingAndFooter:
    def test_flows_rendered_in_chronological_order(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _xhr_entry(_at(5), "https://example.com/api/late"),
            _other_entry(_at(2), "https://example.com/mid"),
        ]
        md = _render(entries)
        pos_login = md.index("/login")
        pos_mid = md.index("/mid")
        pos_late = md.index("/late")
        assert pos_login < pos_mid < pos_late

    def test_footer_mentions_total_request_count(self) -> None:
        entries = [_nav_entry(_at(0), "https://example.com/login")]
        md = _render(entries)
        assert "1 total request" in md


class TestOutlierNotes:
    def test_slow_response_gets_timing_note(self) -> None:
        entries = [_xhr_entry(_at(i), f"https://example.com/api/{i}") for i in range(5)]
        entries[2] = _xhr_entry(_at(2), "https://example.com/api/2")
        # override time_ms on the slow one by rebuilding it directly
        slow = entries[2]
        entries[2] = HarEntry(
            started_at=slow.started_at,
            time_ms=5000.0,
            request=slow.request,
            response=slow.response,
        )
        md = _render(entries)
        assert "response time 5000ms" in md
        assert "median" in md

    def test_no_note_when_timing_unremarkable(self) -> None:
        entries = [_xhr_entry(_at(i), f"https://example.com/api/{i}") for i in range(5)]
        md = _render(entries)
        assert "response time" not in md


class TestCaptureSignalsSection:
    def test_security_header_posture_rendered(self) -> None:
        md = _render(
            [_xhr_entry(_at(0), "https://example.com/api/data")],
        )
        assert "## Capture Signals" in md
        assert "Strict-Transport-Security: present on 0/1 responses" in md

    def test_stack_hints_rendered(self) -> None:
        entry = HarEntry(
            started_at=_at(0),
            time_ms=1.0,
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
                headers=(
                    HarHeader("Content-Type", "application/json"),
                    HarHeader("Server", "nginx/1.25.0"),
                ),
                body=b'{"ok":true}',
            ),
        )
        md = _render([entry])
        assert "Stack fingerprint hints" in md
        assert "nginx/1.25.0" in md


class TestTableOfContents:
    def test_toc_section_present_with_correct_anchor(self) -> None:
        md = _render([_nav_entry(_at(0), "https://example.com/login")])
        assert "## Contents" in md
        assert "[Flow 1 — 14:02:00 (navigation)](#flow-1--140200-navigation)" in md

    def test_toc_omitted_when_no_flows(self) -> None:
        md = _render([])
        assert "## Contents" not in md

    def test_toc_lists_every_narrative_flow(self) -> None:
        md = _render(
            [
                _nav_entry(_at(0), "https://example.com/login"),
                _xhr_entry(
                    _at(1), "https://example.com/api/a", referer="https://example.com/login"
                ),
            ]
        )
        assert "[Flow 1 —" in md
        assert "[Flow 2 —" in md


class TestStateChangingMethodHighlighting:
    def test_post_request_marked_state_changing(self) -> None:
        md = _render(
            [_xhr_entry(_at(0), "https://example.com/api/create", request_body=b'{"x":1}')]
        )
        assert "**POST** *(state-changing)*" in md

    def test_get_request_not_marked(self) -> None:
        md = _render([_xhr_entry(_at(0), "https://example.com/api/data")])
        assert "**GET**" in md
        assert "*(state-changing)*" not in md
