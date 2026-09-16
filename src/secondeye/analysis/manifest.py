"""Flow construction and manifest.json assembly (SPEC.md §10.2, §11.1).

``build_flows()`` is the single source of truth for flow numbering and
summary text — SPEC.md §10.2 notes "flows[].summary is the same string
used as the ANALYSIS.md header for that flow — generated once, used in
both places." recording/manager.py calls it once and hands the resulting
``list[Flow]`` to both this module's ``build_manifest()`` and
analysis/render.py, rather than each independently recomputing it.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from urllib.parse import urlsplit

from secondeye.analysis.classify import Category, ClassifiedEntry
from secondeye.analysis.cluster import (
    PollingGroup,
    RedirectChain,
    detect_polling_groups,
    detect_redirect_chains,
)
from secondeye.capture.har import HarEntry, header_value

__all__ = [
    "Flow",
    "PollingGroupInfo",
    "RedirectHop",
    "build_flows",
    "build_manifest",
]

_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class RedirectHop:
    """One hop of a redirect chain (SPEC.md §10.2).

    Attributes:
        har_entry_index: Index into raw.har's log.entries[].
        url: The URL requested at this hop.
        status: The response status at this hop.
        location: The Location header value, if this hop redirected further.
    """

    har_entry_index: int
    url: str
    status: int
    location: str | None

    def to_manifest_dict(self) -> dict[str, object]:
        """Render as a manifest.json ``redirect_hops[]`` object."""
        d: dict[str, object] = {
            "har_entry_index": self.har_entry_index,
            "url": self.url,
            "status": self.status,
        }
        if self.location is not None:
            d["location"] = self.location
        return d


@dataclass(frozen=True)
class PollingGroupInfo:
    """Polling metadata attached to a group's first-occurrence flow
    (SPEC.md §10.2, §11.5).

    Attributes:
        occurrence_count: Total occurrences in the group, including the first.
        interval_seconds: The detected polling interval.
        collapsed_har_entry_indices: raw.har indices of every suppressed
            (non-first) occurrence, in full — not truncated (manifest.json
            is ground truth; ANALYSIS.md's rendered note is what caps the
            displayed list, per SPEC.md §11.5).
    """

    occurrence_count: int
    interval_seconds: float
    collapsed_har_entry_indices: list[int]

    def to_manifest_dict(self) -> dict[str, object]:
        """Render as a manifest.json ``flows[].polling_group`` object."""
        return {
            "occurrence_count": self.occurrence_count,
            "interval_seconds": self.interval_seconds,
            "collapsed_har_entry_indices": self.collapsed_har_entry_indices,
        }


@dataclass(frozen=True)
class Flow:
    """One narrative unit: a single request/response pair, a collapsed
    redirect chain, or one occurrence of a polling group (SPEC.md §10.2).

    Attributes:
        flow_id: Sequential id, assigned in chronological order. Every
            qualifying entry (i.e. not static-asset) gets one, even
            occurrences later marked collapsed_into another flow — ground
            truth is always complete.
        started_at: When the flow's first entry began.
        category: The flow's traffic category.
        har_entry_indices: raw.har indices this flow covers (more than one
            only for a redirect chain).
        redirect_chain: Whether this flow is a collapsed redirect chain.
        summary: The one-line summary shared verbatim with ANALYSIS.md.
        redirect_hops: Per-hop detail, only set when redirect_chain is True.
        polling_group: Set only on a polling group's first-occurrence flow.
        collapsed_into: Set only on a polling group's suppressed
            (non-first) occurrences, pointing at the first occurrence's
            flow_id.
    """

    flow_id: int
    started_at: datetime.datetime
    category: Category
    har_entry_indices: list[int]
    redirect_chain: bool
    summary: str
    redirect_hops: list[RedirectHop] | None = None
    polling_group: PollingGroupInfo | None = None
    collapsed_into: int | None = None

    def to_manifest_dict(self) -> dict[str, object]:
        """Render as a manifest.json ``flows[]`` object."""
        d: dict[str, object] = {
            "flow_id": self.flow_id,
            "started_at": _iso(self.started_at),
            "category": self.category.value,
            "har_entry_indices": self.har_entry_indices,
            "redirect_chain": self.redirect_chain,
            "summary": self.summary,
        }
        if self.redirect_hops is not None:
            d["redirect_hops"] = [h.to_manifest_dict() for h in self.redirect_hops]
        if self.polling_group is not None:
            d["polling_group"] = self.polling_group.to_manifest_dict()
        if self.collapsed_into is not None:
            d["collapsed_into"] = self.collapsed_into
        return d


def build_flows(classified: list[ClassifiedEntry]) -> list[Flow]:
    """Build the flows[] list from classified entries (SPEC.md §11.1 pipeline).

    Args:
        classified: All of a capture's entries, classified (any order).

    Returns:
        Flows in chronological (flow_id) order. static-asset entries never
        get their own flow (they're summarized at render time as part of
        their parent navigation's asset count); every other entry does,
        including polling occurrences later marked collapsed_into.
    """
    redirect_chains = detect_redirect_chains(classified)
    polling_groups = detect_polling_groups(classified)

    chain_consumed_indices = {
        hop.index for chain in redirect_chains.values() for hop in chain.hops[1:]
    }
    first_occurrence_group: dict[int, PollingGroup] = {g.first_index: g for g in polling_groups}
    collapsed_occurrence_group: dict[int, PollingGroup] = {
        idx: g for g in polling_groups for idx in g.occurrence_indices[1:]
    }

    sorted_entries = sorted(classified, key=lambda c: c.entry.started_at)

    flows: list[Flow] = []
    flow_id_by_index: dict[int, int] = {}
    next_flow_id = 1

    for classified_entry in sorted_entries:
        idx = classified_entry.index
        if classified_entry.category == Category.STATIC_ASSET:
            continue
        if idx in chain_consumed_indices:
            continue

        flow_id = next_flow_id
        next_flow_id += 1
        flow_id_by_index[idx] = flow_id

        if idx in redirect_chains:
            flows.append(_build_chain_flow(flow_id, redirect_chains[idx]))
        elif idx in first_occurrence_group:
            flows.append(
                _build_polling_first_flow(flow_id, classified_entry, first_occurrence_group[idx])
            )
        elif idx in collapsed_occurrence_group:
            group = collapsed_occurrence_group[idx]
            flows.append(
                _build_simple_flow(
                    flow_id, classified_entry, collapsed_into=flow_id_by_index[group.first_index]
                )
            )
        else:
            flows.append(_build_simple_flow(flow_id, classified_entry))

    return flows


def build_manifest(
    *,
    capture_name: str,
    started_at: datetime.datetime,
    ended_at: datetime.datetime,
    targets: list[str],
    target_regex: list[str] | None,
    capture_all: bool,
    upstream: str | None,
    no_upstream: bool,
    classified: list[ClassifiedEntry],
    flows: list[Flow],
) -> dict[str, object]:
    """Assemble the full manifest.json structure (SPEC.md §10.2).

    Args:
        capture_name: The capture's --name label.
        started_at: When the capture started.
        ended_at: When the capture ended.
        targets: Configured --target values.
        target_regex: Configured --target-regex values, if any.
        capture_all: Whether --capture-all was set.
        upstream: "host:port" of the configured upstream, if not no_upstream.
        no_upstream: Whether --no-upstream was set.
        classified: All of the capture's entries, classified.
        flows: This capture's flows, from build_flows() (called once and
            shared with analysis/render.py — see module docstring).

    Returns:
        A JSON-serializable dict matching manifest.json's schema.
    """
    return {
        "schema_version": _SCHEMA_VERSION,
        "capture": {
            "name": capture_name,
            "started_at": _iso(started_at),
            "ended_at": _iso(ended_at),
            "duration_ms": (ended_at - started_at).total_seconds() * 1000,
        },
        "scope": {
            "targets": targets,
            "target_regex": target_regex,
            "capture_all": capture_all,
            "upstream": upstream,
            "no_upstream": no_upstream,
        },
        "stats": _build_stats(classified),
        "flows": [f.to_manifest_dict() for f in flows],
    }


def _build_stats(classified: list[ClassifiedEntry]) -> dict[str, object]:
    by_category: dict[str, int] = {category.value: 0 for category in Category}
    total_bytes = 0
    domains: set[str] = set()
    for c in classified:
        by_category[c.category.value] += 1
        total_bytes += len(c.entry.request.body) + len(c.entry.response.body)
        hostname = urlsplit(c.entry.request.url).hostname
        if hostname:
            domains.add(hostname)
    return {
        "total_requests": len(classified),
        "by_category": by_category,
        "total_bytes_transferred": total_bytes,
        "domains_seen": sorted(domains),
    }


def _build_chain_flow(flow_id: int, chain: RedirectChain) -> Flow:
    hops = chain.hops
    redirect_hops = [
        RedirectHop(
            har_entry_index=hop.index,
            url=hop.entry.request.url,
            status=hop.entry.response.status,
            location=(
                header_value(hop.entry.response.headers, "location") if i < len(hops) - 1 else None
            ),
        )
        for i, hop in enumerate(hops)
    ]
    return Flow(
        flow_id=flow_id,
        started_at=hops[0].entry.started_at,
        category=hops[0].category,
        har_entry_indices=[hop.index for hop in hops],
        redirect_chain=True,
        redirect_hops=redirect_hops,
        summary=_summary_for_chain(hops),
    )


def _build_polling_first_flow(
    flow_id: int, classified_entry: ClassifiedEntry, group: PollingGroup
) -> Flow:
    base_summary = _summary_for_entry(classified_entry.entry)
    summary = f"{base_summary} (polling, {_format_interval(group.interval_seconds)} interval)"
    return Flow(
        flow_id=flow_id,
        started_at=classified_entry.entry.started_at,
        category=classified_entry.category,
        har_entry_indices=[classified_entry.index],
        redirect_chain=False,
        summary=summary,
        polling_group=PollingGroupInfo(
            occurrence_count=len(group.occurrence_indices),
            interval_seconds=group.interval_seconds,
            collapsed_har_entry_indices=group.occurrence_indices[1:],
        ),
    )


def _build_simple_flow(
    flow_id: int, classified_entry: ClassifiedEntry, *, collapsed_into: int | None = None
) -> Flow:
    return Flow(
        flow_id=flow_id,
        started_at=classified_entry.entry.started_at,
        category=classified_entry.category,
        har_entry_indices=[classified_entry.index],
        redirect_chain=False,
        summary=_summary_for_entry(classified_entry.entry),
        collapsed_into=collapsed_into,
    )


def _summary_for_entry(entry: HarEntry) -> str:
    return f"{entry.request.method} {_path_and_query(entry.request.url)} → {entry.response.status}"


def _summary_for_chain(hops: list[ClassifiedEntry]) -> str:
    parts: list[str] = []
    for hop in hops:
        parts.append(f"{hop.entry.request.method} {_path_and_query(hop.entry.request.url)}")
        parts.append(str(hop.entry.response.status))
    return " → ".join(parts)


def _path_and_query(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path


def _format_interval(seconds: float) -> str:
    rounded = round(seconds)
    if abs(seconds - rounded) < 0.05:
        return f"{rounded}s"
    return f"{seconds:.1f}s"


def _iso(value: datetime.datetime) -> str:
    text = value.astimezone(datetime.UTC).isoformat()
    if text.endswith("+00:00"):
        text = text[: -len("+00:00")] + "Z"
    return text
