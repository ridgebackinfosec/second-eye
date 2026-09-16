"""Tests for secondeye.analysis.cluster (SPEC.md §11.3, §11.4, §11.5, §14 Phase 6)."""

import datetime

from secondeye.analysis.classify import classify_entries
from secondeye.analysis.cluster import (
    cluster_entries,
    detect_polling_groups,
    detect_redirect_chains,
)
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse

_T0 = datetime.datetime(2026, 9, 15, 14, 2, 0, tzinfo=datetime.UTC)


def _at(offset_seconds: float) -> datetime.datetime:
    return _T0 + datetime.timedelta(seconds=offset_seconds)


def _nav_entry(
    at: datetime.datetime, url: str, status: int = 200, location: str | None = None
) -> HarEntry:
    headers = [HarHeader("Sec-Fetch-Mode", "navigate")]
    response_headers = [HarHeader("Content-Type", "text/html")]
    if location is not None:
        response_headers.append(HarHeader("Location", location))
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(
            method="GET", url=url, http_version="1.1", headers=tuple(headers), body=b""
        ),
        response=HarResponse(
            status=status,
            status_text="OK",
            http_version="1.1",
            headers=tuple(response_headers),
            body=b"",
        ),
    )


def _xhr_entry(
    at: datetime.datetime,
    url: str,
    referer: str | None = None,
    body: bytes = b'{"ok":true}',
    method: str = "GET",
) -> HarEntry:
    headers = [HarHeader("X-Requested-With", "XMLHttpRequest"), HarHeader("Sec-Fetch-Mode", "cors")]
    if referer is not None:
        headers.append(HarHeader("Referer", referer))
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(
            method=method, url=url, http_version="1.1", headers=tuple(headers), body=b""
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "application/json"),),
            body=body,
        ),
    )


class TestClusterEntries:
    def test_navigation_always_starts_a_new_cluster(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _nav_entry(_at(1), "https://example.com/dashboard"),
        ]
        classified = classify_entries(entries)
        clusters = cluster_entries(classified, window_ms=2000)
        assert len(clusters) == 2
        assert clusters[0].anchor.entry.request.url == "https://example.com/login"
        assert clusters[1].anchor.entry.request.url == "https://example.com/dashboard"

    def test_same_referer_within_window_joins_current_cluster(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _xhr_entry(_at(0.5), "https://example.com/api/a", referer="https://example.com/login"),
            _xhr_entry(_at(1.0), "https://example.com/api/b", referer="https://example.com/login"),
        ]
        classified = classify_entries(entries)
        clusters = cluster_entries(classified, window_ms=2000)
        assert len(clusters) == 1
        assert len(clusters[0].members) == 2

    def test_gap_exceeding_window_closes_cluster_even_with_same_referer(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _xhr_entry(_at(0.5), "https://example.com/api/a", referer="https://example.com/login"),
            # 5 seconds later, still same referer, but window is 2s.
            _xhr_entry(_at(5.5), "https://example.com/api/b", referer="https://example.com/login"),
        ]
        classified = classify_entries(entries)
        clusters = cluster_entries(classified, window_ms=2000)
        assert len(clusters) == 2
        assert len(clusters[0].members) == 1
        assert clusters[1].anchor.entry.request.url == "https://example.com/api/b"

    def test_different_referer_starts_new_cluster(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _xhr_entry(_at(0.5), "https://example.com/api/a", referer="https://example.com/other"),
        ]
        classified = classify_entries(entries)
        clusters = cluster_entries(classified, window_ms=2000)
        assert len(clusters) == 2

    def test_entries_processed_in_chronological_order_regardless_of_input_order(self) -> None:
        entries = [
            _xhr_entry(_at(1.0), "https://example.com/api/b", referer="https://example.com/login"),
            _nav_entry(_at(0), "https://example.com/login"),
        ]
        classified = classify_entries(entries)
        clusters = cluster_entries(classified, window_ms=2000)
        assert len(clusters) == 1
        assert clusters[0].anchor.entry.request.url == "https://example.com/login"


class TestDetectRedirectChains:
    def test_single_hop_redirect_chain_detected(self) -> None:
        entries = [
            _nav_entry(
                _at(0),
                "https://example.com/dashboard",
                status=302,
                location="/dashboard/home",
            ),
            _nav_entry(_at(0.1), "https://example.com/dashboard/home", status=200),
        ]
        classified = classify_entries(entries)
        chains = detect_redirect_chains(classified)
        assert len(chains) == 1
        chain = chains[0]
        assert len(chain.hops) == 2
        assert chain.hops[0].entry.request.url == "https://example.com/dashboard"
        assert chain.hops[1].entry.request.url == "https://example.com/dashboard/home"

    def test_multi_hop_redirect_chain_detected(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/a", status=302, location="/b"),
            _nav_entry(_at(0.1), "https://example.com/b", status=302, location="/c"),
            _nav_entry(_at(0.2), "https://example.com/c", status=200),
        ]
        classified = classify_entries(entries)
        chains = detect_redirect_chains(classified)
        assert len(chains) == 1
        assert len(chains[0].hops) == 3

    def test_unrelated_navigations_are_not_chained(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login", status=200),
            _nav_entry(_at(1), "https://example.com/dashboard", status=200),
        ]
        classified = classify_entries(entries)
        chains = detect_redirect_chains(classified)
        assert chains == {}

    def test_redirect_to_unmatched_url_is_not_chained(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/a", status=302, location="/expected"),
            _nav_entry(_at(0.1), "https://example.com/unexpected", status=200),
        ]
        classified = classify_entries(entries)
        chains = detect_redirect_chains(classified)
        assert chains == {}


class TestDetectPollingGroups:
    def test_twelve_regular_occurrences_form_one_group(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(12)
        ]
        classified = classify_entries(entries)
        groups = detect_polling_groups(classified)
        assert len(groups) == 1
        assert groups[0].first_index == 0
        assert groups[0].occurrence_indices == list(range(12))
        assert groups[0].interval_seconds == 30.0

    def test_body_change_breaks_the_run_into_a_separate_occurrence(self) -> None:
        # SPEC.md §11.5 Phase 6 fixture: 12 identical occurrences, then one
        # where the body differs — the state change ends the group and is
        # not itself part of any polling group.
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(12)
        ]
        entries.append(
            _xhr_entry(
                _at(12 * 30),
                "https://api.example.com/v2/notifications/poll",
                body=b'{"unread":3,"items":["new"]}',
            )
        )
        classified = classify_entries(entries)
        groups = detect_polling_groups(classified)
        assert len(groups) == 1
        assert groups[0].occurrence_indices == list(range(12))
        collapsed_indices = {idx for g in groups for idx in g.occurrence_indices}
        assert 12 not in collapsed_indices

    def test_fewer_than_three_occurrences_is_not_a_polling_group(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(2)
        ]
        classified = classify_entries(entries)
        groups = detect_polling_groups(classified)
        assert groups == []

    def test_irregular_intervals_are_not_a_polling_group(self) -> None:
        offsets = [0, 30, 200]  # wildly inconsistent gaps
        entries = [
            _xhr_entry(_at(o), "https://api.example.com/v2/notifications/poll") for o in offsets
        ]
        classified = classify_entries(entries)
        groups = detect_polling_groups(classified)
        assert groups == []

    def test_different_signatures_are_not_grouped_together(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(3)
        ] + [_xhr_entry(_at(i * 30), "https://api.example.com/v2/other/poll") for i in range(3)]
        classified = classify_entries(entries)
        groups = detect_polling_groups(classified)
        assert len(groups) == 2

    def test_navigation_entries_are_never_grouped_even_if_repeated(self) -> None:
        # SPEC.md §11.5: polling dedup "applies only to xhr-api. Does not
        # apply to navigation or static-asset" — even identical, regularly
        # spaced repeats of the same navigation must not be collapsed.
        entries = [_nav_entry(_at(i * 30), "https://example.com/page") for i in range(4)]
        classified = classify_entries(entries)
        groups = detect_polling_groups(classified)
        assert groups == []
