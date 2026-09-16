"""Tests for secondeye.capture.har (SPEC.md §10.1, §13, §14 Phase 5/6)."""

import base64
import datetime

import h11

from secondeye.capture.har import (
    HarEntry,
    HarHeader,
    HarRequest,
    HarResponse,
    build_har_entry,
    parse_har_entry,
)


def _parsed_request(raw: bytes) -> tuple[h11.Request, bytes]:
    """Feed raw HTTP bytes through a real h11 server connection."""
    conn = h11.Connection(our_role=h11.SERVER)
    conn.receive_data(raw)
    request_event: h11.Request | None = None
    body = b""
    while True:
        event = conn.next_event()
        if isinstance(event, h11.Request):
            request_event = event
        elif isinstance(event, h11.Data):
            body += bytes(event.data)
        elif isinstance(event, h11.EndOfMessage):
            break
    assert request_event is not None
    return request_event, body


def _parsed_response(raw: bytes) -> tuple[h11.Response, bytes]:
    """Feed raw HTTP bytes through a real h11 client connection."""
    conn = h11.Connection(our_role=h11.CLIENT)
    conn.send(h11.Request(method="GET", target="/", headers=[("Host", "example.com")]))
    conn.send(h11.EndOfMessage())
    conn.receive_data(raw)
    response_event: h11.Response | None = None
    body = b""
    while True:
        event = conn.next_event()
        if isinstance(event, h11.Response):
            response_event = event
        elif isinstance(event, h11.Data):
            body += bytes(event.data)
        elif isinstance(event, h11.EndOfMessage):
            break
    assert response_event is not None
    return response_event, body


class TestBuildHarEntry:
    def test_constructs_entry_matching_real_request_and_response(self) -> None:
        json_body = b'{"username":"a","password":1}'
        request_event, request_body = _parsed_request(
            b"POST /api/v1/auth/login HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(json_body)).encode("ascii") + b"\r\n"
            b"\r\n" + json_body
        )
        response_event, response_body = _parsed_response(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 15\r\n"
            b"\r\n"
            b'{"token":"abc"}'
        )
        started_at = datetime.datetime(2026, 9, 15, 14, 2, 34, tzinfo=datetime.UTC)

        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=response_body,
            url="https://example.com/api/v1/auth/login",
            started_at=started_at,
            time_ms=42.5,
        )

        assert entry.started_at == started_at
        assert entry.time_ms == 42.5
        assert entry.request.method == "POST"
        assert entry.request.url == "https://example.com/api/v1/auth/login"
        assert entry.request.http_version == "1.1"
        assert entry.request.body == request_body
        assert ("Content-Type", "application/json") in [
            (h.name, h.value) for h in entry.request.headers
        ]
        assert entry.response.status == 200
        assert entry.response.status_text == "OK"
        assert entry.response.body == response_body

    def test_request_with_no_body_has_no_post_data_in_har_dict(self) -> None:
        request_event, request_body = _parsed_request(
            b"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        response_event, response_body = _parsed_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=response_body,
            url="https://example.com/page",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        assert "postData" not in entry.request.to_har_dict()

    def test_request_with_body_includes_post_data_in_har_dict(self) -> None:
        json_body = b'{"a":"b"}'
        request_event, request_body = _parsed_request(
            b"POST /submit HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(json_body)).encode("ascii") + b"\r\n"
            b"\r\n" + json_body
        )
        response_event, response_body = _parsed_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=response_body,
            url="https://example.com/submit",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        post_data = entry.request.to_har_dict()["postData"]
        assert isinstance(post_data, dict)
        assert post_data["mimeType"] == "application/json"
        assert post_data["text"] == request_body.decode("ascii")

    def test_har_dict_full_structure_is_json_shaped(self) -> None:
        request_event, request_body = _parsed_request(
            b"GET /page?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        response_event, response_body = _parsed_response(
            b"HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\n\r\n"
        )
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=response_body,
            url="https://example.com/page?x=1",
            started_at=datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC),
            time_ms=12.0,
        )
        har_dict = entry.to_har_dict()
        assert har_dict["startedDateTime"] == "2026-09-15T14:02:11Z"
        assert har_dict["time"] == 12.0
        assert isinstance(har_dict["request"], dict)
        assert isinstance(har_dict["response"], dict)
        response_dict = har_dict["response"]
        assert response_dict["status"] == 302
        assert response_dict["redirectURL"] == "/other"

    def test_response_content_reflects_body_and_content_type(self) -> None:
        request_event, request_body = _parsed_request(
            b"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        response_event, response_body = _parsed_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>"
        )
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=response_body,
            url="https://example.com/page",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        content = entry.response.to_har_dict()["content"]
        assert isinstance(content, dict)
        assert content["mimeType"] == "text/html"
        assert content["text"] == "<html></html>"
        assert content["size"] == 13


class TestBinaryBodyFullFidelity:
    """SPEC.md §10.1: raw.har is "full-fidelity ground truth... no redaction,
    no truncation." A naive utf-8-decode-with-replace would silently corrupt
    non-UTF-8 bytes (images, protobuf, etc.) — this must round-trip exactly.
    """

    def test_non_utf8_response_body_round_trips_exactly_via_base64(self) -> None:
        binary_body = bytes(range(256))  # guaranteed invalid UTF-8 somewhere
        request_event, request_body = _parsed_request(
            b"GET /image.png HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        response_event, _ = _parsed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=binary_body,
            url="https://example.com/image.png",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        content = entry.response.to_har_dict()["content"]
        assert isinstance(content, dict)
        assert content["encoding"] == "base64"
        assert base64.b64decode(content["text"]) == binary_body

    def test_utf8_response_body_has_no_encoding_field(self) -> None:
        request_event, request_body = _parsed_request(
            b"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        response_event, _ = _parsed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=b"plain text body",
            url="https://example.com/page",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        content = entry.response.to_har_dict()["content"]
        assert isinstance(content, dict)
        assert "encoding" not in content

    def test_non_utf8_request_body_round_trips_exactly_via_base64(self) -> None:
        binary_body = bytes(range(256))
        header_bytes = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 256\r\n\r\n"
        request_event, request_body = _parsed_request(header_bytes + binary_body)
        response_event, _ = _parsed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=b"",
            url="https://example.com/upload",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        post_data = entry.request.to_har_dict()["postData"]
        assert isinstance(post_data, dict)
        assert post_data["encoding"] == "base64"
        assert base64.b64decode(post_data["text"]) == binary_body


class TestParseHarEntryRoundTrip:
    def test_round_trips_utf8_bodies_exactly(self) -> None:
        original = HarEntry(
            started_at=datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC),
            time_ms=42.5,
            request=HarRequest(
                method="POST",
                url="https://example.com/api/login",
                http_version="1.1",
                headers=(HarHeader("Content-Type", "application/json"),),
                body=b'{"a":1}',
            ),
            response=HarResponse(
                status=200,
                status_text="OK",
                http_version="1.1",
                headers=(HarHeader("Content-Type", "application/json"),),
                body=b'{"token":"abc"}',
            ),
        )
        round_tripped = parse_har_entry(original.to_har_dict())
        assert round_tripped == original

    def test_round_trips_binary_bodies_exactly(self) -> None:
        binary_body = bytes(range(256))
        original = HarEntry(
            started_at=datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC),
            time_ms=1.0,
            request=HarRequest(
                method="GET",
                url="https://example.com/image.png",
                http_version="1.1",
                headers=(HarHeader("Host", "example.com"),),
                body=b"",
            ),
            response=HarResponse(
                status=200,
                status_text="OK",
                http_version="1.1",
                headers=(HarHeader("Content-Type", "image/png"),),
                body=binary_body,
            ),
        )
        round_tripped = parse_har_entry(original.to_har_dict())
        assert round_tripped == original

    def test_round_trips_empty_bodies(self) -> None:
        original = HarEntry(
            started_at=datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC),
            time_ms=1.0,
            request=HarRequest(
                method="GET",
                url="https://example.com/page",
                http_version="1.1",
                headers=(HarHeader("Host", "example.com"),),
                body=b"",
            ),
            response=HarResponse(
                status=204,
                status_text="No Content",
                http_version="1.1",
                headers=(),
                body=b"",
            ),
        )
        round_tripped = parse_har_entry(original.to_har_dict())
        assert round_tripped == original

    def test_round_trip_via_json_serialization(self) -> None:
        import json

        original = HarEntry(
            started_at=datetime.datetime(2026, 9, 15, 14, 2, 11, tzinfo=datetime.UTC),
            time_ms=1.5,
            request=HarRequest(
                method="GET",
                url="https://example.com/page?x=1",
                http_version="1.1",
                headers=(HarHeader("Host", "example.com"),),
                body=b"",
            ),
            response=HarResponse(
                status=302,
                status_text="Found",
                http_version="1.1",
                headers=(HarHeader("Location", "/other"),),
                body=b"",
            ),
        )
        serialized = json.dumps(original.to_har_dict())
        round_tripped = parse_har_entry(json.loads(serialized))
        assert round_tripped == original


class TestHeaderCaseInsensitiveLookup:
    def test_content_type_lookup_is_case_insensitive(self) -> None:
        request_event, request_body = _parsed_request(
            b"POST /x HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"content-type: application/xml\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"<a/>\n"
        )
        response_event, response_body = _parsed_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        entry = build_har_entry(
            request_event=request_event,
            request_body=request_body,
            response_event=response_event,
            response_body=response_body,
            url="https://example.com/x",
            started_at=datetime.datetime.now(datetime.UTC),
            time_ms=1.0,
        )
        post_data = entry.request.to_har_dict()["postData"]
        assert isinstance(post_data, dict)
        assert post_data["mimeType"] == "application/xml"
