"""HAR entry construction from parsed request/response pairs (SPEC.md §10.1, §13).

Builds HAR ("HTTP Archive") entry objects from h11-parsed HTTP/1.1
request/response pairs. Pure data construction — no I/O, no capture
lifecycle awareness (recording/manager.py and capture/buffer.py, both
later phases, own writing these to disk).
"""

from __future__ import annotations

import base64
import datetime
from collections.abc import Iterable
from dataclasses import dataclass

import h11

__all__ = [
    "HarEntry",
    "HarHeader",
    "HarRequest",
    "HarResponse",
    "build_har_entry",
    "header_value",
    "parse_har_entry",
]


@dataclass(frozen=True)
class HarHeader:
    """A single HTTP header name/value pair, HAR-shaped.

    Attributes:
        name: The header name, in its original wire case.
        value: The header value.
    """

    name: str
    value: str


@dataclass(frozen=True)
class HarRequest:
    """The request half of a HAR entry.

    Attributes:
        method: The HTTP method.
        url: The full request URL (scheme + authority + target).
        http_version: The HTTP version, e.g. "1.1".
        headers: The request headers, in original wire order/case.
        body: The full request body, if any.
    """

    method: str
    url: str
    http_version: str
    headers: tuple[HarHeader, ...]
    body: bytes

    def to_har_dict(self) -> dict[str, object]:
        """Render as a HAR ``entries[].request`` object."""
        entry: dict[str, object] = {
            "method": self.method,
            "url": self.url,
            "httpVersion": f"HTTP/{self.http_version}",
            "headers": [{"name": h.name, "value": h.value} for h in self.headers],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(self.body),
        }
        if self.body:
            post_data: dict[str, object] = {
                "mimeType": header_value(self.headers, "content-type")
                or "application/octet-stream",
            }
            post_data.update(_encode_body(self.body))
            entry["postData"] = post_data
        return entry


@dataclass(frozen=True)
class HarResponse:
    """The response half of a HAR entry.

    Attributes:
        status: The HTTP status code.
        status_text: The HTTP status reason phrase.
        http_version: The HTTP version, e.g. "1.1".
        headers: The response headers, in original wire order/case.
        body: The full response body.
    """

    status: int
    status_text: str
    http_version: str
    headers: tuple[HarHeader, ...]
    body: bytes

    def to_har_dict(self) -> dict[str, object]:
        """Render as a HAR ``entries[].response`` object."""
        content: dict[str, object] = {
            "size": len(self.body),
            "mimeType": header_value(self.headers, "content-type") or "application/octet-stream",
        }
        content.update(_encode_body(self.body))
        return {
            "status": self.status,
            "statusText": self.status_text,
            "httpVersion": f"HTTP/{self.http_version}",
            "headers": [{"name": h.name, "value": h.value} for h in self.headers],
            "cookies": [],
            "content": content,
            "redirectURL": header_value(self.headers, "location") or "",
            "headersSize": -1,
            "bodySize": len(self.body),
        }


@dataclass(frozen=True)
class HarEntry:
    """One complete HAR entry: a request/response pair with timing.

    Attributes:
        started_at: When the request began.
        time_ms: Total elapsed time for the request/response cycle, in ms.
        request: The request half.
        response: The response half.
    """

    started_at: datetime.datetime
    time_ms: float
    request: HarRequest
    response: HarResponse

    def to_har_dict(self) -> dict[str, object]:
        """Render as a HAR ``log.entries[]`` object."""
        started_iso = self.started_at.astimezone(datetime.UTC).isoformat()
        if started_iso.endswith("+00:00"):
            started_iso = started_iso[: -len("+00:00")] + "Z"
        return {
            "startedDateTime": started_iso,
            "time": self.time_ms,
            "request": self.request.to_har_dict(),
            "response": self.response.to_har_dict(),
            "cache": {},
            "timings": {"send": 0, "wait": self.time_ms, "receive": 0},
        }


def header_value(headers: tuple[HarHeader, ...], name: str) -> str | None:
    """Case-insensitive lookup of a header's value by name.

    Args:
        headers: Headers to search.
        name: The header name to look up (case-insensitive).

    Returns:
        The first matching header's value, or None if not present.
    """
    lname = name.lower()
    for header in headers:
        if header.name.lower() == lname:
            return header.value
    return None


def _decode_headers(raw_items: Iterable[tuple[bytes, bytes]]) -> tuple[HarHeader, ...]:
    return tuple(
        HarHeader(name=name.decode("latin-1"), value=value.decode("latin-1"))
        for name, value in raw_items
    )


def _encode_body(body: bytes) -> dict[str, object]:
    """Encode a body for HAR JSON storage, preserving exact bytes (SPEC.md §10.1).

    UTF-8-decodable bodies are stored as plain text (the common, readable
    case). Anything else (images, protobuf, arbitrary binary payloads) is
    base64-encoded with an explicit "encoding" field, per the standard HAR
    convention — never lossily decoded with errors="replace", which would
    silently corrupt non-text bodies and violate "full-fidelity ground
    truth, no redaction, no truncation."

    Returns:
        {"text": ...} for UTF-8 bodies, or {"text": ..., "encoding": "base64"}
        otherwise.
    """
    try:
        return {"text": body.decode("utf-8")}
    except UnicodeDecodeError:
        return {"text": base64.b64encode(body).decode("ascii"), "encoding": "base64"}


def _decode_body(data: dict[str, object] | None) -> bytes:
    """Reverse of _encode_body, for reading a HAR dict back into bytes."""
    if data is None:
        return b""
    text = data.get("text")
    if not isinstance(text, str):
        return b""
    if data.get("encoding") == "base64":
        return base64.b64decode(text)
    return text.encode("utf-8")


def build_har_entry(
    *,
    request_event: h11.Request,
    request_body: bytes,
    response_event: h11.Response | h11.InformationalResponse,
    response_body: bytes,
    url: str,
    started_at: datetime.datetime,
    time_ms: float,
) -> HarEntry:
    """Construct a HarEntry from a completed h11 request/response cycle.

    Args:
        request_event: The parsed h11.Request event from the client.
        request_body: The fully-accumulated request body bytes.
        response_event: The parsed h11.Response (or h11.InformationalResponse
            for a 101 Switching Protocols upgrade, SPEC.md §0) event from
            upstream/destination.
        response_body: The fully-accumulated response body bytes.
        url: The full URL the request was made to (scheme+authority+target).
            h11 only sees the request target (e.g. "/path"); the caller
            reconstructs the full URL from the SNI/Host and scheme.
        started_at: When the request began.
        time_ms: Total elapsed time for the request/response cycle, in ms.

    Returns:
        A HarEntry combining the request and response into HAR-entry shape.
    """
    request = HarRequest(
        method=request_event.method.decode("ascii"),
        url=url,
        http_version=request_event.http_version.decode("ascii"),
        headers=_decode_headers(request_event.headers.raw_items()),
        body=request_body,
    )
    response = HarResponse(
        status=response_event.status_code,
        status_text=response_event.reason.decode("latin-1"),
        http_version=response_event.http_version.decode("ascii"),
        headers=_decode_headers(response_event.headers.raw_items()),
        body=response_body,
    )
    return HarEntry(started_at=started_at, time_ms=time_ms, request=request, response=response)


def parse_har_entry(data: dict[str, object]) -> HarEntry:
    """Parse a HAR ``log.entries[]``-shaped dict back into a HarEntry.

    The inverse of ``HarEntry.to_har_dict()`` — used when reading a capture's
    buffered JSONL (or raw.har) back into structured form, e.g. for the
    analysis pipeline (SPEC.md §11.1) or capture/buffer.py.

    Args:
        data: A dict as produced by ``HarEntry.to_har_dict()``.

    Returns:
        The reconstructed HarEntry, with body bytes restored exactly
        (including non-UTF-8 bodies stored as base64).
    """
    request_data = data["request"]
    response_data = data["response"]
    assert isinstance(request_data, dict)
    assert isinstance(response_data, dict)

    request_headers = _parse_headers(request_data["headers"])
    response_headers = _parse_headers(response_data["headers"])

    post_data = request_data.get("postData")
    request = HarRequest(
        method=str(request_data["method"]),
        url=str(request_data["url"]),
        http_version=str(request_data["httpVersion"]).removeprefix("HTTP/"),
        headers=request_headers,
        body=_decode_body(post_data if isinstance(post_data, dict) else None),
    )

    content = response_data.get("content")
    status_value = response_data["status"]
    assert isinstance(status_value, int)
    response = HarResponse(
        status=status_value,
        status_text=str(response_data["statusText"]),
        http_version=str(response_data["httpVersion"]).removeprefix("HTTP/"),
        headers=response_headers,
        body=_decode_body(content if isinstance(content, dict) else None),
    )

    started_at = datetime.datetime.fromisoformat(
        str(data["startedDateTime"]).replace("Z", "+00:00")
    )
    time_value = data["time"]
    assert isinstance(time_value, int | float)

    return HarEntry(
        started_at=started_at, time_ms=float(time_value), request=request, response=response
    )


def _parse_headers(raw: object) -> tuple[HarHeader, ...]:
    assert isinstance(raw, list)
    return tuple(HarHeader(name=str(h["name"]), value=str(h["value"])) for h in raw)
