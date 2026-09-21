"""Tests for secondeye.analysis.signals."""

import datetime

from secondeye.analysis.classify import classify_entries
from secondeye.analysis.signals import compute_size_outliers, compute_timing_outliers
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
