"""Tests for secondeye.analysis.signals."""

import datetime

from secondeye.analysis.classify import classify_entries
from secondeye.analysis.signals import (
    compute_security_header_posture,
    compute_size_outliers,
    compute_stack_hints,
    compute_timing_outliers,
)
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse

_T0 = datetime.datetime(2026, 9, 15, 14, 2, 0, tzinfo=datetime.UTC)


def _entry(
    time_ms: float = 100.0,
    body: bytes = b"ok",
    extra_response_headers: tuple[HarHeader, ...] = (),
) -> HarEntry:
    return HarEntry(
        started_at=_T0,
        time_ms=time_ms,
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
            headers=(HarHeader("Content-Type", "application/json"), *extra_response_headers),
            body=body,
        ),
    )


def _static_entry(time_ms: float = 100.0, body: bytes = b"x") -> HarEntry:
    return HarEntry(
        started_at=_T0,
        time_ms=time_ms,
        request=HarRequest(
            method="GET", url="https://example.com/app.js", http_version="1.1", headers=(), body=b""
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "application/javascript"),),
            body=body,
        ),
    )


class TestTimingOutliers:
    def test_flags_entry_far_above_median(self) -> None:
        entries = [_entry(time_ms=100.0) for _ in range(5)]
        entries[2] = _entry(time_ms=900.0)  # 9x the 100ms median
        classified = classify_entries(entries)

        outliers = compute_timing_outliers(classified)

        assert set(outliers) == {2}
        assert outliers[2].value == 900.0
        assert outliers[2].median == 100.0
        assert outliers[2].multiple == 9.0

    def test_no_outliers_when_all_similar(self) -> None:
        entries = [_entry(time_ms=100.0 + i) for i in range(5)]
        classified = classify_entries(entries)

        assert compute_timing_outliers(classified) == {}

    def test_empty_below_minimum_sample_size(self) -> None:
        entries = [_entry(time_ms=100.0), _entry(time_ms=5000.0)]
        classified = classify_entries(entries)

        assert compute_timing_outliers(classified) == {}

    def test_custom_threshold_multiple(self) -> None:
        entries = [_entry(time_ms=100.0) for _ in range(5)]
        entries[1] = _entry(time_ms=250.0)  # 2.5x median
        classified = classify_entries(entries)

        outliers = compute_timing_outliers(classified, threshold_multiple=2.0)

        assert set(outliers) == {1}
        assert outliers[1].multiple == 2.5

    def test_static_assets_excluded_from_baseline_and_flagging(self) -> None:
        entries = [_static_entry(time_ms=100.0) for _ in range(4)]
        entries.append(_static_entry(time_ms=5000.0))  # would flag if counted
        entries += [_entry(time_ms=100.0) for _ in range(4)]  # non-static baseline
        classified = classify_entries(entries)

        assert compute_timing_outliers(classified) == {}


class TestSizeOutliers:
    def test_flags_entry_far_above_median_size(self) -> None:
        entries = [_entry(body=b"x" * 100) for _ in range(5)]
        entries[3] = _entry(body=b"x" * 2000)  # 20x the 100-byte median
        classified = classify_entries(entries)

        outliers = compute_size_outliers(classified)

        assert set(outliers) == {3}
        assert outliers[3].value == 2000.0
        assert outliers[3].multiple == 20.0

    def test_no_outliers_when_sizes_similar(self) -> None:
        entries = [_entry(body=b"x" * (100 + i)) for i in range(5)]
        classified = classify_entries(entries)

        assert compute_size_outliers(classified) == {}

    def test_static_assets_excluded(self) -> None:
        entries = [_static_entry(body=b"x" * 100) for _ in range(4)]
        entries.append(_static_entry(body=b"x" * 500_000))  # would flag if counted
        entries += [_entry(body=b"x" * 100) for _ in range(4)]
        classified = classify_entries(entries)

        assert compute_size_outliers(classified) == {}


class TestSecurityHeaderPosture:
    def test_counts_presence_across_non_static_entries(self) -> None:
        entries = [
            _entry(extra_response_headers=(HarHeader("Strict-Transport-Security", "max-age=1"),)),
            _entry(),
            _entry(extra_response_headers=(HarHeader("Strict-Transport-Security", "max-age=1"),)),
        ]
        classified = classify_entries(entries)

        posture = compute_security_header_posture(classified)

        hsts = next(p for p in posture if p.header_name == "Strict-Transport-Security")
        assert hsts.present_count == 2
        assert hsts.total_count == 3

    def test_tracks_all_four_headers_even_if_never_present(self) -> None:
        classified = classify_entries([_entry()])

        posture = compute_security_header_posture(classified)

        names = {p.header_name for p in posture}
        assert names == {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        }

    def test_excludes_static_asset_entries(self) -> None:
        classified = classify_entries([_static_entry()])

        assert compute_security_header_posture(classified) == []


class TestStackHints:
    def test_server_header_hint(self) -> None:
        classified = classify_entries(
            [_entry(extra_response_headers=(HarHeader("Server", "nginx/1.25.0"),))]
        )

        hints = compute_stack_hints(classified)

        assert any(h.value == "nginx/1.25.0" and h.source == "Server header" for h in hints)

    def test_x_powered_by_hint(self) -> None:
        classified = classify_entries(
            [_entry(extra_response_headers=(HarHeader("X-Powered-By", "Express"),))]
        )

        hints = compute_stack_hints(classified)

        assert any(h.value == "Express" and h.source == "X-Powered-By header" for h in hints)

    def test_known_cookie_name_hint(self) -> None:
        classified = classify_entries(
            [_entry(extra_response_headers=(HarHeader("Set-Cookie", "JSESSIONID=abc123; Path=/"),))]
        )

        hints = compute_stack_hints(classified)

        assert any(h.value == "Java/Tomcat" and h.source == "cookie name jsessionid" for h in hints)

    def test_unknown_cookie_name_produces_no_hint(self) -> None:
        classified = classify_entries(
            [_entry(extra_response_headers=(HarHeader("Set-Cookie", "mystery_token=xyz; Path=/"),))]
        )

        assert compute_stack_hints(classified) == []

    def test_deduplicates_repeated_hints(self) -> None:
        classified = classify_entries(
            [
                _entry(extra_response_headers=(HarHeader("Server", "nginx"),)),
                _entry(extra_response_headers=(HarHeader("Server", "nginx"),)),
            ]
        )

        hints = compute_stack_hints(classified)

        assert len(hints) == 1
