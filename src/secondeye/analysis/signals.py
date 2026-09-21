"""Cheap per-capture derived signals (SPEC.md §11.8).

Descriptive-statistics outlier detection and header/cookie-based fingerprint
heuristics, surfaced in ANALYSIS.md (analysis/render.py). Every function
here scans the capture once and returns a lookup keyed by raw.har entry
index — no cross-entry correlation, matching the module-boundary convention
that compute lives here and rendering lives in render.py (CLAUDE.md).
"""

from __future__ import annotations

import statistics
from collections.abc import Callable
from dataclasses import dataclass

from secondeye.analysis.classify import Category, ClassifiedEntry
from secondeye.capture.har import header_value

__all__ = [
    "OutlierInfo",
    "SecurityHeaderPosture",
    "StackHint",
    "compute_security_header_posture",
    "compute_size_outliers",
    "compute_stack_hints",
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
