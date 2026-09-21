"""Tests for secondeye.analysis.classify (SPEC.md §11.2, §14 Phase 6)."""

import datetime

from secondeye.analysis.classify import Category, classify_entries, classify_entry
from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse

_STARTED_AT = datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC)


def _entry(
    *,
    method: str = "GET",
    url: str = "https://example.com/page",
    request_headers: tuple[HarHeader, ...] = (),
    request_body: bytes = b"",
    status: int = 200,
    response_headers: tuple[HarHeader, ...] = (),
) -> HarEntry:
    return HarEntry(
        started_at=_STARTED_AT,
        time_ms=1.0,
        request=HarRequest(
            method=method,
            url=url,
            http_version="1.1",
            headers=request_headers,
            body=request_body,
        ),
        response=HarResponse(
            status=status,
            status_text="OK",
            http_version="1.1",
            headers=response_headers,
            body=b"",
        ),
    )


class TestNavigationClassification:
    def test_sec_fetch_mode_navigate_is_navigation(self) -> None:
        entry = _entry(request_headers=(HarHeader("Sec-Fetch-Mode", "navigate"),))
        assert classify_entry(entry) == Category.NAVIGATION

    def test_html_content_type_and_get_is_navigation_without_sec_fetch(self) -> None:
        entry = _entry(
            method="GET", response_headers=(HarHeader("Content-Type", "text/html; charset=utf-8"),)
        )
        assert classify_entry(entry) == Category.NAVIGATION

    def test_html_content_type_with_post_is_not_navigation_by_content_type_rule(self) -> None:
        entry = _entry(method="POST", response_headers=(HarHeader("Content-Type", "text/html"),))
        assert classify_entry(entry) != Category.NAVIGATION

    def test_sec_fetch_mode_navigate_wins_over_json_content_type(self) -> None:
        # SPEC.md §11.2: "Prefer Sec-Fetch-* headers where present... over
        # content-type guessing."
        entry = _entry(
            request_headers=(HarHeader("Sec-Fetch-Mode", "navigate"),),
            response_headers=(HarHeader("Content-Type", "application/json"),),
        )
        assert classify_entry(entry) == Category.NAVIGATION


class TestXhrApiClassification:
    def test_sec_fetch_mode_cors_with_x_requested_with_is_xhr_api(self) -> None:
        entry = _entry(
            request_headers=(
                HarHeader("Sec-Fetch-Mode", "cors"),
                HarHeader("X-Requested-With", "XMLHttpRequest"),
            )
        )
        assert classify_entry(entry) == Category.XHR_API

    def test_sec_fetch_mode_same_origin_with_x_requested_with_is_xhr_api(self) -> None:
        entry = _entry(
            request_headers=(
                HarHeader("Sec-Fetch-Mode", "same-origin"),
                HarHeader("X-Requested-With", "XMLHttpRequest"),
            )
        )
        assert classify_entry(entry) == Category.XHR_API

    def test_json_response_content_type_is_xhr_api(self) -> None:
        entry = _entry(response_headers=(HarHeader("Content-Type", "application/json"),))
        assert classify_entry(entry) == Category.XHR_API

    def test_xml_response_content_type_is_xhr_api(self) -> None:
        entry = _entry(response_headers=(HarHeader("Content-Type", "application/xml"),))
        assert classify_entry(entry) == Category.XHR_API

    def test_request_with_post_data_is_xhr_api(self) -> None:
        entry = _entry(method="POST", request_body=b'{"a":1}')
        assert classify_entry(entry) == Category.XHR_API

    def test_navigate_with_post_data_is_still_navigation(self) -> None:
        # Priority: Sec-Fetch-Mode: navigate beats the postData heuristic
        # (e.g. a classic <form method=post> submission).
        entry = _entry(
            method="POST",
            request_headers=(HarHeader("Sec-Fetch-Mode", "navigate"),),
            request_body=b"username=a&password=b",
        )
        assert classify_entry(entry) == Category.NAVIGATION


class TestStaticAssetClassification:
    def test_css_content_type_is_static_asset(self) -> None:
        entry = _entry(response_headers=(HarHeader("Content-Type", "text/css"),))
        assert classify_entry(entry) == Category.STATIC_ASSET

    def test_javascript_content_type_is_static_asset(self) -> None:
        entry = _entry(response_headers=(HarHeader("Content-Type", "application/javascript"),))
        assert classify_entry(entry) == Category.STATIC_ASSET

    def test_font_content_type_is_static_asset(self) -> None:
        entry = _entry(response_headers=(HarHeader("Content-Type", "font/woff2"),))
        assert classify_entry(entry) == Category.STATIC_ASSET

    def test_image_content_type_is_static_asset(self) -> None:
        entry = _entry(response_headers=(HarHeader("Content-Type", "image/png"),))
        assert classify_entry(entry) == Category.STATIC_ASSET

    def test_js_extension_is_static_asset_even_with_generic_content_type(self) -> None:
        entry = _entry(
            url="https://example.com/static/js/app.a3f9c1.js",
            response_headers=(HarHeader("Content-Type", "application/octet-stream"),),
        )
        assert classify_entry(entry) == Category.STATIC_ASSET

    def test_ico_extension_is_static_asset(self) -> None:
        entry = _entry(url="https://example.com/favicon.ico")
        assert classify_entry(entry) == Category.STATIC_ASSET


class TestOtherClassification:
    def test_unclassified_content_type_get_no_body_is_other(self) -> None:
        entry = _entry(
            method="GET",
            status=204,
            response_headers=(HarHeader("Content-Type", "application/octet-stream"),),
        )
        assert classify_entry(entry) == Category.OTHER

    def test_no_headers_at_all_is_other(self) -> None:
        entry = _entry()
        assert classify_entry(entry) == Category.OTHER


class TestClassificationConfidence:
    def test_sec_fetch_mode_navigate_is_confirmed(self) -> None:
        entries = [_entry(request_headers=(HarHeader("Sec-Fetch-Mode", "navigate"),))]
        classified = classify_entries(entries)
        assert classified[0].confirmed is True

    def test_sec_fetch_mode_cors_with_xrw_is_confirmed(self) -> None:
        entries = [
            _entry(
                request_headers=(
                    HarHeader("Sec-Fetch-Mode", "cors"),
                    HarHeader("X-Requested-With", "XMLHttpRequest"),
                )
            )
        ]
        classified = classify_entries(entries)
        assert classified[0].confirmed is True

    def test_html_content_type_fallback_is_unconfirmed(self) -> None:
        entries = [_entry(method="GET", response_headers=(HarHeader("Content-Type", "text/html"),))]
        classified = classify_entries(entries)
        assert classified[0].confirmed is False

    def test_json_content_type_fallback_is_unconfirmed(self) -> None:
        entries = [_entry(response_headers=(HarHeader("Content-Type", "application/json"),))]
        classified = classify_entries(entries)
        assert classified[0].confirmed is False

    def test_static_asset_is_unconfirmed(self) -> None:
        entries = [_entry(url="https://example.com/app.js")]
        classified = classify_entries(entries)
        assert classified[0].confirmed is False

    def test_other_category_is_unconfirmed(self) -> None:
        entries = [_entry(method="DELETE", url="https://example.com/resource")]
        classified = classify_entries(entries)
        assert classified[0].confirmed is False


class TestClassifyEntries:
    def test_assigns_sequential_indices_matching_position(self) -> None:
        entries = [
            _entry(request_headers=(HarHeader("Sec-Fetch-Mode", "navigate"),)),
            _entry(response_headers=(HarHeader("Content-Type", "application/json"),)),
            _entry(url="https://example.com/a.css"),
        ]
        classified = classify_entries(entries)
        assert [c.index for c in classified] == [0, 1, 2]
        assert [c.category for c in classified] == [
            Category.NAVIGATION,
            Category.XHR_API,
            Category.STATIC_ASSET,
        ]
        assert all(c.entry is e for c, e in zip(classified, entries, strict=True))
