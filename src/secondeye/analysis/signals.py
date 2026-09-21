"""Cheap per-capture derived signals (SPEC.md §11.8).

Descriptive-statistics outlier detection and header/cookie-based fingerprint
heuristics, surfaced in ANALYSIS.md (analysis/render.py). Every function
here scans the capture once and returns a lookup keyed by raw.har entry
index — no cross-entry correlation, matching the module-boundary convention
that compute lives here and rendering lives in render.py (CLAUDE.md).
"""

from __future__ import annotations

import json
import re
import statistics
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from secondeye.analysis.classify import Category, ClassifiedEntry
from secondeye.capture.har import header_value

__all__ = [
    "AuthMechanismSummary",
    "DebugPageHint",
    "EndpointSummary",
    "OutlierInfo",
    "ParameterNameSummary",
    "SecretFinding",
    "SecurityHeaderPosture",
    "StackHint",
    "StatusCodeSummary",
    "compute_auth_mechanisms",
    "compute_debug_page_hints",
    "compute_distinct_endpoints",
    "compute_parameter_names",
    "compute_secret_findings",
    "compute_security_header_posture",
    "compute_size_outliers",
    "compute_stack_hints",
    "compute_status_code_rollup",
    "compute_timing_outliers",
]

_MIN_SAMPLE_SIZE = 5
_TIMING_OUTLIER_MULTIPLE = 5.0
_SIZE_OUTLIER_MULTIPLE = 10.0
_TRACKED_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)
_COOKIE_NAME_HINTS = {
    "jsessionid": "Java/Tomcat",
    "phpsessid": "PHP",
    "laravel_session": "Laravel",
    "asp.net_sessionid": "ASP.NET",
    "connect.sid": "Node.js/Express",
    "django_sessionid": "Django",
}
_DEBUG_PAGE_SIGNATURES = (
    ("Django", "You're seeing this because you have DEBUG = True"),
    ("Django", "django.core.handlers.exception"),
    ("Flask/Werkzeug", "Werkzeug Debugger"),
    ("Flask/Werkzeug", "Traceback (most recent call last)"),
    ("Rails", "ActionController::RoutingError"),
    ("Rails", "Rails.root"),
    ("ASP.NET", "Server Error in '/' Application"),
    ("ASP.NET", "Stack Trace:"),
    ("PHP", "Fatal error:"),
)
_SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
)
_AUTH_SCHEME_LABELS = {
    "bearer": "Bearer token",
    "basic": "Basic auth",
    "digest": "Digest auth",
}
_AUTH_KIND_ORDER = ("Bearer token", "Basic auth", "Digest auth", "session cookie")


@dataclass(frozen=True)
class OutlierInfo:
    """A single entry's value versus the capture's median (SPEC.md §11.8).

    Attributes:
        value: This entry's raw value (milliseconds, or response bytes).
        median: The capture's median value across all considered entries.
        multiple: value / median, rounded to one decimal place.
    """

    value: float
    median: float
    multiple: float


@dataclass(frozen=True)
class SecurityHeaderPosture:
    """How consistently a security-relevant response header was observed.

    Attributes:
        header_name: The header's canonical name, e.g. "Strict-Transport-Security".
        present_count: How many considered responses included this header.
        total_count: Total responses considered (static-asset entries excluded).
    """

    header_name: str
    present_count: int
    total_count: int


@dataclass(frozen=True)
class StackHint:
    """A guessed technology-stack signal derived from response headers/cookies.

    Attributes:
        value: The human-readable guess, e.g. "Java/Tomcat" or "nginx/1.25.0".
        source: Where it came from, e.g. "Server header" or "cookie name jsessionid".
    """

    value: str
    source: str


@dataclass(frozen=True)
class DebugPageHint:
    """A framework debug/error page fingerprint matched in a response body.

    Attributes:
        framework: The framework the fingerprint is associated with, e.g. "Django".
        signature: The literal substring that matched. This is always one of
            this codebase's own fixed signatures (never attacker-controlled
            text), so it needs no escaping when rendered.
    """

    framework: str
    signature: str


@dataclass(frozen=True)
class SecretFinding:
    """A credential-shaped pattern matched in a response body.

    Rendered unredacted (SPEC.md §0's full-fidelity-capture, no-redaction
    stance) — this tool records traffic for an authorized security
    assessment, and withholding an actually-observed secret from the
    operator would defeat the tool's purpose.

    Attributes:
        kind: The pattern's label, e.g. "AWS access key".
        value: The exact matched substring. Every _SECRET_PATTERNS regex
            uses a charset that excludes markdown-significant characters
            (backticks, newlines) by construction, so this value is safe
            to render without going through render.py's _inline_safe() —
            unlike a freely-typed query parameter name/value.
    """

    kind: str
    value: str


@dataclass(frozen=True)
class EndpointSummary:
    """A distinct (method, path) pair observed in the capture.

    Attributes:
        method: The HTTP method, e.g. "GET".
        path: The URL path only — no query string, scheme, or host.
    """

    method: str
    path: str


@dataclass(frozen=True)
class AuthMechanismSummary:
    """An observed authentication mechanism and how often it appeared.

    Attributes:
        kind: A human-readable mechanism label, e.g. "Bearer token" or
            "session cookie".
        request_count: How many requests carried this mechanism.
    """

    kind: str
    request_count: int


@dataclass(frozen=True)
class StatusCodeSummary:
    """How many non-static-asset responses returned a given status code.

    Attributes:
        status: The HTTP status code.
        count: How many responses returned it.
    """

    status: int
    count: int


@dataclass(frozen=True)
class ParameterNameSummary:
    """A distinct parameter NAME observed in query strings or JSON request
    bodies — never the value (SPEC.md §11.9's IDOR-candidate use case).

    Attributes:
        name: The parameter name.
        source: "query" or "body".
        occurrence_count: How many entries carried this (name, source) pair.
    """

    name: str
    source: str
    occurrence_count: int


def compute_distinct_endpoints(classified: list[ClassifiedEntry]) -> list[EndpointSummary]:
    """Aggregate distinct (method, path) pairs touched during the capture.

    Static-asset entries are excluded (SPEC.md §11.9) — endpoint mapping
    is about application surface, not asset requests.

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        Deduplicated EndpointSummary entries, first-seen order.
    """
    seen: set[tuple[str, str]] = set()
    endpoints: list[EndpointSummary] = []
    for c in classified:
        if c.category == Category.STATIC_ASSET:
            continue
        path = urlsplit(c.entry.request.url).path
        key = (c.entry.request.method, path)
        if key not in seen:
            seen.add(key)
            endpoints.append(EndpointSummary(method=c.entry.request.method, path=path))
    return endpoints


def compute_auth_mechanisms(classified: list[ClassifiedEntry]) -> list[AuthMechanismSummary]:
    """Aggregate observed authentication mechanisms (SPEC.md §11.9).

    Never surfaces the actual token or cookie value anywhere — only the
    mechanism kind and how many requests used it.

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        One AuthMechanismSummary per observed kind, in a fixed order
        (Bearer, Basic, Digest, session cookie); kinds with zero
        occurrences are omitted. Static-asset entries are excluded.
    """
    counts: dict[str, int] = {}
    for c in classified:
        if c.category == Category.STATIC_ASSET:
            continue
        auth_header = header_value(c.entry.request.headers, "authorization")
        if auth_header:
            scheme = auth_header.split(" ", 1)[0].strip().lower()
            label = _AUTH_SCHEME_LABELS.get(scheme)
            if label:
                counts[label] = counts.get(label, 0) + 1
        if header_value(c.entry.request.headers, "cookie") is not None:
            counts["session cookie"] = counts.get("session cookie", 0) + 1
    return [
        AuthMechanismSummary(kind=kind, request_count=counts[kind])
        for kind in _AUTH_KIND_ORDER
        if kind in counts
    ]


def compute_status_code_rollup(classified: list[ClassifiedEntry]) -> list[StatusCodeSummary]:
    """Aggregate response status codes across the capture (SPEC.md §11.9).

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        One StatusCodeSummary per distinct status code, sorted ascending
        by status code. Static-asset entries are excluded.
    """
    counts: dict[int, int] = {}
    for c in classified:
        if c.category == Category.STATIC_ASSET:
            continue
        status = c.entry.response.status
        counts[status] = counts.get(status, 0) + 1
    return [StatusCodeSummary(status=s, count=counts[s]) for s in sorted(counts)]


def compute_parameter_names(classified: list[ClassifiedEntry]) -> list[ParameterNameSummary]:
    """Aggregate distinct query-string and JSON-body top-level parameter
    names across the capture, to spot IDOR-candidate parameters like
    user_id or order_id (SPEC.md §11.9). Never surfaces parameter values.

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        Deduplicated ParameterNameSummary entries: query names (first-seen
        order) followed by body names (first-seen order). Static-asset
        entries are excluded.
    """
    query_counts: dict[str, int] = {}
    query_order: list[str] = []
    body_counts: dict[str, int] = {}
    body_order: list[str] = []

    for c in classified:
        if c.category == Category.STATIC_ASSET:
            continue

        query = urlsplit(c.entry.request.url).query
        for name in parse_qs(query):
            if name not in query_counts:
                query_order.append(name)
            query_counts[name] = query_counts.get(name, 0) + 1

        content_type = header_value(c.entry.request.headers, "content-type") or ""
        if "json" in content_type.lower() and c.entry.request.body:
            try:
                parsed = json.loads(c.entry.request.body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(parsed, dict):
                for name in parsed:
                    if name not in body_counts:
                        body_order.append(name)
                    body_counts[name] = body_counts.get(name, 0) + 1

    return [
        ParameterNameSummary(name=n, source="query", occurrence_count=query_counts[n])
        for n in query_order
    ] + [
        ParameterNameSummary(name=n, source="body", occurrence_count=body_counts[n])
        for n in body_order
    ]


def compute_timing_outliers(
    classified: list[ClassifiedEntry], *, threshold_multiple: float = _TIMING_OUTLIER_MULTIPLE
) -> dict[int, OutlierInfo]:
    """Flag entries whose response time is far above the capture's median.

    Static-asset entries are excluded from both the baseline median and
    flagging — their size/timing variance is expected and not meaningful
    signal (SPEC.md §11.8).

    Args:
        classified: All of the capture's entries, classified.
        threshold_multiple: How many times the median an entry's time_ms
            must reach to be flagged. Default 5.0.

    Returns:
        {har_entry_index: OutlierInfo}, only for flagged entries. Empty if
        fewer than 5 non-static-asset entries exist (too small a sample
        for a meaningful median).
    """
    candidates = [c for c in classified if c.category != Category.STATIC_ASSET]
    return _compute_outliers(
        candidates, value_fn=lambda c: c.entry.time_ms, threshold_multiple=threshold_multiple
    )


def compute_size_outliers(
    classified: list[ClassifiedEntry], *, threshold_multiple: float = _SIZE_OUTLIER_MULTIPLE
) -> dict[int, OutlierInfo]:
    """Flag entries whose response body is far larger than the capture's median.

    Static-asset entries are excluded — see compute_timing_outliers.

    Args:
        classified: All of the capture's entries, classified.
        threshold_multiple: How many times the median an entry's response
            body size must reach to be flagged. Default 10.0.

    Returns:
        {har_entry_index: OutlierInfo}, only for flagged entries. Empty if
        fewer than 5 non-static-asset entries exist.
    """
    candidates = [c for c in classified if c.category != Category.STATIC_ASSET]
    return _compute_outliers(
        candidates,
        value_fn=lambda c: float(len(c.entry.response.body)),
        threshold_multiple=threshold_multiple,
    )


def compute_security_header_posture(
    classified: list[ClassifiedEntry],
) -> list[SecurityHeaderPosture]:
    """Aggregate presence of well-known security response headers (SPEC.md §11.8).

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        One SecurityHeaderPosture per tracked header, in
        _TRACKED_SECURITY_HEADERS order. Empty list if there are no
        non-static-asset entries.
    """
    candidates = [c for c in classified if c.category != Category.STATIC_ASSET]
    if not candidates:
        return []
    return [
        SecurityHeaderPosture(
            header_name=name,
            present_count=sum(
                1 for c in candidates if header_value(c.entry.response.headers, name) is not None
            ),
            total_count=len(candidates),
        )
        for name in _TRACKED_SECURITY_HEADERS
    ]


def compute_stack_hints(classified: list[ClassifiedEntry]) -> list[StackHint]:
    """Guess backend technology from Server/X-Powered-By headers and cookie names.

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        Deduplicated StackHints, in first-observed order.
    """
    seen: set[tuple[str, str]] = set()
    hints: list[StackHint] = []
    for c in classified:
        for header_name, source_label in (
            ("server", "Server header"),
            ("x-powered-by", "X-Powered-By header"),
        ):
            value = header_value(c.entry.response.headers, header_name)
            key = (source_label, value or "")
            if value and key not in seen:
                seen.add(key)
                hints.append(StackHint(value=value, source=source_label))
        for header in c.entry.response.headers:
            if header.name.lower() != "set-cookie":
                continue
            cookie_name = header.value.split("=", 1)[0].strip().lower()
            guess = _COOKIE_NAME_HINTS.get(cookie_name)
            source = f"cookie name {cookie_name}"
            key = (source, guess or "")
            if guess and key not in seen:
                seen.add(key)
                hints.append(StackHint(value=guess, source=source))
    return hints


def _decode_for_scan(body: bytes) -> str:
    """Best-effort UTF-8 decode for substring/regex scanning only.

    Never raises — invalid bytes are replaced, not rejected, since this is
    only used for pattern matching, not display. Rendering (render.py) has
    its own separate decode path (_decode_for_display) with different
    fallback behavior for actual document output.
    """
    return body.decode("utf-8", errors="replace")


def compute_debug_page_hints(classified: list[ClassifiedEntry]) -> dict[int, DebugPageHint]:
    """Flag entries whose response body matches a known framework
    debug/error page fingerprint (SPEC.md §11.10).

    A fixed signature table, same shape as _COOKIE_NAME_HINTS — not a
    general stack-trace/error-page heuristic (that would have much higher
    false-positive risk on APIs that legitimately return structured error
    JSON). Static-asset entries are excluded.

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        {har_entry_index: DebugPageHint}, only for entries whose response
        body matched. If multiple signatures match the same body, the
        first match in _DEBUG_PAGE_SIGNATURES order wins.
    """
    hints: dict[int, DebugPageHint] = {}
    for c in classified:
        if c.category == Category.STATIC_ASSET:
            continue
        if not c.entry.response.body:
            continue
        body_text = _decode_for_scan(c.entry.response.body)
        for framework, signature in _DEBUG_PAGE_SIGNATURES:
            if signature in body_text:
                hints[c.index] = DebugPageHint(framework=framework, signature=signature)
                break
    return hints


def compute_secret_findings(classified: list[ClassifiedEntry]) -> dict[int, list[SecretFinding]]:
    """Scan response bodies for credential-shaped patterns (SPEC.md §11.10).

    Response bodies only — request-side credentials are already covered
    by compute_auth_mechanisms, which deliberately never surfaces the
    value; this function does, for values a *target application* exposed
    in its own response, which is the actual finding an operator needs to
    see. Static-asset entries are excluded.

    Args:
        classified: All of the capture's entries, classified.

    Returns:
        {har_entry_index: [SecretFinding, ...]}, only for entries with at
        least one match. A body can match more than one pattern.
    """
    findings: dict[int, list[SecretFinding]] = {}
    for c in classified:
        if c.category == Category.STATIC_ASSET:
            continue
        if not c.entry.response.body:
            continue
        body_text = _decode_for_scan(c.entry.response.body)
        matches: list[SecretFinding] = []
        for kind, pattern in _SECRET_PATTERNS:
            match = pattern.search(body_text)
            if match:
                matches.append(SecretFinding(kind=kind, value=match.group(0)))
        if matches:
            findings[c.index] = matches
    return findings


def _compute_outliers(
    classified: list[ClassifiedEntry],
    *,
    value_fn: Callable[[ClassifiedEntry], float],
    threshold_multiple: float,
) -> dict[int, OutlierInfo]:
    if len(classified) < _MIN_SAMPLE_SIZE:
        return {}
    values = [value_fn(c) for c in classified]
    median = statistics.median(values)
    if median <= 0:
        return {}
    outliers: dict[int, OutlierInfo] = {}
    for c, value in zip(classified, values, strict=True):
        multiple = value / median
        if multiple >= threshold_multiple:
            outliers[c.index] = OutlierInfo(value=value, median=median, multiple=round(multiple, 1))
    return outliers
