"""Tests for secondeye.analysis.manifest (SPEC.md §10.2, §14 Phase 6)."""

import datetime

from secondeye.analysis.classify import Category, classify_entries
from secondeye.analysis.manifest import build_flows, build_manifest
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse

_T0 = datetime.datetime(2026, 9, 15, 14, 2, 0, tzinfo=datetime.UTC)


def _at(offset_seconds: float) -> datetime.datetime:
    return _T0 + datetime.timedelta(seconds=offset_seconds)


def _nav_entry(
    at: datetime.datetime, url: str, status: int = 200, location: str | None = None
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
            body=b"",
        ),
    )


def _xhr_entry(
    at: datetime.datetime, url: str, referer: str | None = None, body: bytes = b'{"ok":true}'
) -> HarEntry:
    headers = [HarHeader("X-Requested-With", "XMLHttpRequest"), HarHeader("Sec-Fetch-Mode", "cors")]
    if referer is not None:
        headers.append(HarHeader("Referer", referer))
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(
            method="GET", url=url, http_version="1.1", headers=tuple(headers), body=b""
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "application/json"),),
            body=body,
        ),
    )


def _static_entry(at: datetime.datetime, url: str) -> HarEntry:
    return HarEntry(
        started_at=at,
        time_ms=1.0,
        request=HarRequest(method="GET", url=url, http_version="1.1", headers=(), body=b""),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "application/javascript"),),
            body=b"",
        ),
    )


class TestBuildFlowsSimpleEntries:
    def test_single_navigation_entry_produces_one_flow(self) -> None:
        classified = classify_entries([_nav_entry(_at(0), "https://example.com/login")])
        flows = build_flows(classified)
        assert len(flows) == 1
        assert flows[0].flow_id == 1
        assert flows[0].category == Category.NAVIGATION
        assert flows[0].har_entry_indices == [0]
        assert flows[0].summary == "GET /login → 200"
        assert flows[0].redirect_chain is False

    def test_flow_ids_assigned_sequentially_in_chronological_order(self) -> None:
        entries = [
            _xhr_entry(_at(1), "https://example.com/api/b"),
            _nav_entry(_at(0), "https://example.com/login"),
        ]
        classified = classify_entries(entries)
        flows = build_flows(classified)
        assert [f.flow_id for f in flows] == [1, 2]
        assert flows[0].har_entry_indices == [1]  # login, index 1 in input list
        assert flows[1].har_entry_indices == [0]  # api/b, index 0 in input list

    def test_static_asset_entries_never_get_their_own_flow(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _static_entry(_at(0.1), "https://example.com/app.js"),
            _static_entry(_at(0.2), "https://example.com/app.css"),
        ]
        classified = classify_entries(entries)
        flows = build_flows(classified)
        assert len(flows) == 1
        assert flows[0].category == Category.NAVIGATION


class TestBuildFlowsRedirectChains:
    def test_redirect_chain_collapses_into_one_flow(self) -> None:
        entries = [
            _nav_entry(
                _at(0), "https://example.com/dashboard", status=302, location="/dashboard/home"
            ),
            _nav_entry(_at(0.1), "https://example.com/dashboard/home", status=200),
        ]
        classified = classify_entries(entries)
        flows = build_flows(classified)
        assert len(flows) == 1
        flow = flows[0]
        assert flow.redirect_chain is True
        assert flow.har_entry_indices == [0, 1]
        assert flow.summary == "GET /dashboard → 302 → GET /dashboard/home → 200"
        assert flow.redirect_hops is not None
        assert len(flow.redirect_hops) == 2
        assert flow.redirect_hops[0].har_entry_index == 0
        assert flow.redirect_hops[0].status == 302
        assert flow.redirect_hops[0].location == "/dashboard/home"
        assert flow.redirect_hops[1].har_entry_index == 1
        assert flow.redirect_hops[1].status == 200
        assert flow.redirect_hops[1].location is None


class TestBuildFlowsPollingGroups:
    def test_first_occurrence_gets_polling_metadata_and_summary_suffix(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(3)
        ]
        classified = classify_entries(entries)
        flows = build_flows(classified)
        assert len(flows) == 3

        first = flows[0]
        assert first.har_entry_indices == [0]
        assert first.polling_group is not None
        assert first.polling_group.occurrence_count == 3
        assert first.polling_group.interval_seconds == 30.0
        assert first.polling_group.collapsed_har_entry_indices == [1, 2]
        assert "polling" in first.summary
        assert "30s interval" in first.summary

    def test_subsequent_occurrences_point_to_first_via_collapsed_into(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(3)
        ]
        classified = classify_entries(entries)
        flows = build_flows(classified)
        first_flow_id = flows[0].flow_id
        assert flows[1].collapsed_into == first_flow_id
        assert flows[2].collapsed_into == first_flow_id
        # Ground truth stays complete: every occurrence still has its own flow.
        assert flows[1].har_entry_indices == [1]
        assert flows[2].har_entry_indices == [2]

    def test_break_out_flow_after_body_change_has_no_polling_metadata(self) -> None:
        entries = [
            _xhr_entry(_at(i * 30), "https://api.example.com/v2/notifications/poll")
            for i in range(3)
        ]
        entries.append(
            _xhr_entry(
                _at(3 * 30),
                "https://api.example.com/v2/notifications/poll",
                body=b'{"unread":5}',
            )
        )
        classified = classify_entries(entries)
        flows = build_flows(classified)
        assert len(flows) == 4
        breakout = flows[3]
        assert breakout.har_entry_indices == [3]
        assert breakout.polling_group is None
        assert breakout.collapsed_into is None


class TestBuildManifest:
    def test_full_manifest_structure(self) -> None:
        entries = [
            _nav_entry(_at(0), "https://example.com/login"),
            _xhr_entry(_at(0.5), "https://example.com/api/a", referer="https://example.com/login"),
            _static_entry(_at(0.6), "https://example.com/app.js"),
        ]
        classified = classify_entries(entries)
        flows = build_flows(classified)
        manifest = build_manifest(
            capture_name="auth-flow-test",
            started_at=_at(0),
            ended_at=_at(10),
            targets=["example.com"],
            target_regex=None,
            target_all=False,
            upstream="127.0.0.1:8080",
            no_upstream=False,
            classified=classified,
            flows=flows,
        )
        assert manifest["schema_version"] == "1.0"
        capture = manifest["capture"]
        assert isinstance(capture, dict)
        assert capture["name"] == "auth-flow-test"
        assert capture["duration_ms"] == 10000.0

        scope = manifest["scope"]
        assert isinstance(scope, dict)
        assert scope["targets"] == ["example.com"]
        assert scope["target_all"] is False
        assert scope["no_upstream"] is False

        stats = manifest["stats"]
        assert isinstance(stats, dict)
        assert stats["total_requests"] == 3
        by_category = stats["by_category"]
        assert isinstance(by_category, dict)
        assert by_category["navigation"] == 1
        assert by_category["xhr-api"] == 1
        assert by_category["static-asset"] == 1
        assert stats["domains_seen"] == ["example.com"]

        manifest_flows = manifest["flows"]
        assert isinstance(manifest_flows, list)
        assert len(manifest_flows) == 2  # static asset excluded

    def test_target_all_and_target_regex_reflected_in_scope(self) -> None:
        classified = classify_entries([])
        flows = build_flows(classified)
        manifest = build_manifest(
            capture_name="c",
            started_at=_at(0),
            ended_at=_at(1),
            targets=[],
            target_regex=["^dev-.*"],
            target_all=True,
            upstream=None,
            no_upstream=True,
            classified=classified,
            flows=flows,
        )
        scope = manifest["scope"]
        assert isinstance(scope, dict)
        assert scope["target_all"] is True
        assert scope["target_regex"] == ["^dev-.*"]
        assert scope["no_upstream"] is True
        assert scope["upstream"] is None
