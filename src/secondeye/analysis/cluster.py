"""Flow clustering, redirect-chain detection, and polling deduplication
(SPEC.md §11.3, §11.4, §11.5).
"""

from __future__ import annotations

import datetime
import json
import statistics
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from secondeye.analysis.classify import Category, ClassifiedEntry
from secondeye.capture.har import header_value

__all__ = [
    "Cluster",
    "PollingGroup",
    "RedirectChain",
    "cluster_entries",
    "detect_polling_groups",
    "detect_redirect_chains",
]

_POLLING_MIN_OCCURRENCES = 3
_POLLING_INTERVAL_TOLERANCE = 0.2


@dataclass
class Cluster:
    """One logical operator action: an anchor entry plus related follow-ons
    (SPEC.md §11.3).

    Attributes:
        anchor: The entry that started this cluster (a navigation entry, or
            the first entry of a new cluster otherwise).
        members: Entries joined to this cluster after the anchor, in the
            order they were added.
    """

    anchor: ClassifiedEntry
    members: list[ClassifiedEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._referer = _cluster_referer(self.anchor)
        self._last_activity = self.anchor.entry.started_at

    @property
    def referer(self) -> str | None:
        """The Referer/Origin value new members must share to join."""
        return self._referer

    @property
    def last_activity(self) -> datetime.datetime:
        """Timestamp of the most recently added entry (or the anchor's)."""
        return self._last_activity

    def add(self, classified: ClassifiedEntry) -> None:
        """Join an entry to this cluster."""
        self.members.append(classified)
        self._last_activity = classified.entry.started_at


def _cluster_referer(anchor: ClassifiedEntry) -> str | None:
    if anchor.category == Category.NAVIGATION:
        return anchor.entry.request.url
    return header_value(anchor.entry.request.headers, "referer")


def cluster_entries(entries: list[ClassifiedEntry], window_ms: int = 2000) -> list[Cluster]:
    """Group classified entries into clusters (SPEC.md §11.3).

    Primary rule: requests sharing the same Referer/Origin, within a
    rolling time window of each other. A navigation entry always starts a
    new cluster; a gap exceeding the window closes the current cluster
    even if the next request shares the same Referer.

    Args:
        entries: Classified entries, in any order.
        window_ms: Rolling time window, in milliseconds.

    Returns:
        Clusters in chronological order of their anchor.
    """
    window = datetime.timedelta(milliseconds=window_ms)
    clusters: list[Cluster] = []
    current: Cluster | None = None
    for classified in sorted(entries, key=lambda c: c.entry.started_at):
        if classified.category == Category.NAVIGATION:
            current = Cluster(anchor=classified)
            clusters.append(current)
            continue

        entry_referer = header_value(classified.entry.request.headers, "referer")
        if (
            current is not None
            and (classified.entry.started_at - current.last_activity) <= window
            and entry_referer == current.referer
        ):
            current.add(classified)
        else:
            current = Cluster(anchor=classified)
            clusters.append(current)
    return clusters


@dataclass(frozen=True)
class RedirectChain:
    """A sequence of navigation entries linked by 3xx Location headers
    (SPEC.md §11.4).

    Attributes:
        hops: The chain's entries in order, from the initial redirect to
            the final (non-redirect) response.
    """

    hops: list[ClassifiedEntry]


def detect_redirect_chains(entries: list[ClassifiedEntry]) -> dict[int, RedirectChain]:
    """Detect redirect chains among navigation entries (SPEC.md §11.4).

    Args:
        entries: Classified entries, in any order.

    Returns:
        A mapping from the chain's starting entry's index to its
        RedirectChain. Entries that are hops[1:] of some chain are not
        themselves keys — callers should treat those indices as consumed
        by the chain they belong to.
    """
    nav_entries = sorted(
        (c for c in entries if c.category == Category.NAVIGATION),
        key=lambda c: c.entry.started_at,
    )
    chains: dict[int, RedirectChain] = {}
    consumed: set[int] = set()

    for i, candidate in enumerate(nav_entries):
        if candidate.index in consumed:
            continue
        if not _is_redirect_status(candidate.entry.response.status):
            continue

        hops = [candidate]
        current = candidate
        j = i + 1
        while j < len(nav_entries) and _is_redirect_status(current.entry.response.status):
            location = header_value(current.entry.response.headers, "location")
            if location is None:
                break
            next_url = urljoin(current.entry.request.url, location)
            next_candidate = nav_entries[j]
            if next_candidate.entry.request.url != next_url:
                break
            hops.append(next_candidate)
            consumed.add(next_candidate.index)
            current = next_candidate
            j += 1

        if len(hops) > 1:
            chains[candidate.index] = RedirectChain(hops=hops)

    return chains


def _is_redirect_status(status: int) -> bool:
    return 300 <= status < 400


@dataclass(frozen=True)
class PollingGroup:
    """A detected run of repeated, regularly-spaced xhr-api requests
    (SPEC.md §11.5).

    Attributes:
        first_index: Index of the first (kept, fully-rendered) occurrence.
        occurrence_indices: Indices of every occurrence in the group, in
            chronological order, including the first.
        interval_seconds: The median interval between occurrences.
    """

    first_index: int
    occurrence_indices: list[int]
    interval_seconds: float


def detect_polling_groups(entries: list[ClassifiedEntry]) -> list[PollingGroup]:
    """Detect polling groups among xhr-api entries (SPEC.md §11.5).

    Applied across the entire capture (not per-cluster). Repeated request
    signatures — identical (method, path, referer) tuples — occurring 3+
    times with roughly consistent intervals (within ±20% of the median
    gap) form a group. Any occurrence whose response body differs
    meaningfully from the group's first occurrence ends that run (and may
    start a new one), since a state change is signal, not noise.

    Args:
        entries: Classified entries, in any order.

    Returns:
        Detected polling groups, each with 3+ occurrences.
    """
    xhr_entries = sorted(
        (c for c in entries if c.category == Category.XHR_API),
        key=lambda c: c.entry.started_at,
    )

    by_signature: dict[tuple[str, str, str | None], list[ClassifiedEntry]] = {}
    for classified in xhr_entries:
        signature = (
            classified.entry.request.method,
            urlsplit(classified.entry.request.url).path,
            header_value(classified.entry.request.headers, "referer"),
        )
        by_signature.setdefault(signature, []).append(classified)

    groups: list[PollingGroup] = []
    for occurrences in by_signature.values():
        run: list[ClassifiedEntry] = []
        for occurrence in occurrences:
            if run and not _bodies_match(
                run[0].entry.response.body, occurrence.entry.response.body
            ):
                _finalize_run(run, groups)
                run = [occurrence]
            else:
                run.append(occurrence)
        _finalize_run(run, groups)

    groups.sort(key=lambda g: g.first_index)
    return groups


def _bodies_match(a: bytes, b: bytes) -> bool:
    try:
        return json.loads(a) == json.loads(b)  # type: ignore[no-any-return]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return a == b


def _finalize_run(run: list[ClassifiedEntry], groups: list[PollingGroup]) -> None:
    if len(run) < _POLLING_MIN_OCCURRENCES:
        return
    timestamps = [c.entry.started_at for c in run]
    gaps = [(timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]
    median_gap = statistics.median(gaps)
    if median_gap <= 0:
        return
    if not all(abs(gap - median_gap) <= _POLLING_INTERVAL_TOLERANCE * median_gap for gap in gaps):
        return
    groups.append(
        PollingGroup(
            first_index=run[0].index,
            occurrence_indices=[c.index for c in run],
            interval_seconds=median_gap,
        )
    )
