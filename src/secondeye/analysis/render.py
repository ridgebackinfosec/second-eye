"""ANALYSIS.md markdown generation (SPEC.md §11.6, §11.7, Appendix A).

Renders the same ``list[Flow]`` build_flows() produces for manifest.json —
``flow.summary`` is reused verbatim as each section's header text, per
SPEC.md §10.2's "generated once, used in both places."
"""

from __future__ import annotations

import datetime
import json

from secondeye.analysis.classify import Category, ClassifiedEntry
from secondeye.analysis.cluster import Cluster, cluster_entries
from secondeye.analysis.manifest import Flow
from secondeye.analysis.signals import (
    OutlierInfo,
    compute_auth_mechanisms,
    compute_distinct_endpoints,
    compute_security_header_posture,
    compute_size_outliers,
    compute_stack_hints,
    compute_timing_outliers,
)
from secondeye.capture.har import HarEntry, HarHeader, header_value

__all__ = ["render_analysis_md"]

_NAVIGATION_TRUNCATE_CHARS = 2000
_OTHER_INLINE_MAX_BYTES = 500
_ASSET_KIND_ORDER = ("JS", "CSS", "font", "image", "other")
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def render_analysis_md(
    *,
    capture_name: str,
    targets: list[str],
    started_at: datetime.datetime,
    ended_at: datetime.datetime,
    classified: list[ClassifiedEntry],
    flows: list[Flow],
) -> str:
    """Render a complete ANALYSIS.md document (SPEC.md §11.7).

    Args:
        capture_name: The capture's --name label.
        targets: Configured --target values, for the header block.
        started_at: When the capture started.
        ended_at: When the capture ended.
        classified: All of the capture's entries, classified.
        flows: This capture's flows, from build_flows() (called once and
            shared with analysis/manifest.py — see that module's docstring).

    Returns:
        The full ANALYSIS.md markdown text.
    """
    entry_by_index = {c.index: c.entry for c in classified}
    confirmed_by_index = {c.index: c.confirmed for c in classified}
    clusters = cluster_entries(classified)
    cluster_by_anchor_index = {c.anchor.index: c for c in clusters}
    timing_outliers = compute_timing_outliers(classified)
    size_outliers = compute_size_outliers(classified)

    narrative_flows = [f for f in flows if f.collapsed_into is None]

    lines: list[str] = []
    lines.extend(
        _render_header(
            capture_name=capture_name,
            targets=targets,
            started_at=started_at,
            ended_at=ended_at,
            classified=classified,
        )
    )
    lines.extend(_render_summary(classified))
    lines.extend(_render_capture_signals(classified))
    lines.extend(_render_toc(narrative_flows, entry_by_index, confirmed_by_index))

    for flow in narrative_flows:
        lines.append("")
        lines.extend(
            _render_flow(
                flow,
                entry_by_index,
                cluster_by_anchor_index,
                timing_outliers=timing_outliers,
                size_outliers=size_outliers,
                confirmed_by_index=confirmed_by_index,
            )
        )
        lines.append("")
        lines.append("---")

    lines.append("")
    lines.append(
        f"*End of capture. {len(classified)} total requests across "
        f"{len(narrative_flows)} narrative flows (static-asset noise and repeated "
        "polling collapsed per flow-rendering rules).*"
    )
    return "\n".join(lines)


def _render_header(
    *,
    capture_name: str,
    targets: list[str],
    started_at: datetime.datetime,
    ended_at: datetime.datetime,
    classified: list[ClassifiedEntry],
) -> list[str]:
    by_category: dict[str, int] = {c.value: 0 for c in Category}
    for c in classified:
        by_category[c.category.value] += 1
    counts_str = ", ".join(
        f"{by_category[c.value]} {c.value}" for c in Category if by_category[c.value]
    )
    return [
        "# Second-Eye Capture Analysis",
        "",
        f"**Capture:** {capture_name}",
        f"**Target(s):** {', '.join(targets)}",
        f"**Capture window:** {_iso(started_at)} → {_iso(ended_at)}",
        f"**Total requests:** {len(classified)} ({counts_str})",
        "**Full fidelity data:** raw.har (this document is a derived summary)",
        "",
        "---",
    ]


def _render_summary(classified: list[ClassifiedEntry]) -> list[str]:
    endpoints = compute_distinct_endpoints(classified)
    mechanisms = compute_auth_mechanisms(classified)
    if not endpoints and not mechanisms:
        return []
    lines = ["", "## Summary", ""]
    if endpoints:
        lines.append("**Endpoints touched:**")
        for e in endpoints:
            lines.append(f"- {e.method} {e.path}")
        lines.append("")
    if mechanisms:
        lines.append("**Auth mechanisms observed:**")
        for m in mechanisms:
            lines.append(f"- {m.kind}: {m.request_count} request(s)")
    return lines


def _render_capture_signals(classified: list[ClassifiedEntry]) -> list[str]:
    posture = compute_security_header_posture(classified)
    hints = compute_stack_hints(classified)
    if not posture and not hints:
        return []
    lines = ["", "## Capture Signals", ""]
    if posture:
        lines.append("**Security headers observed:**")
        for p in posture:
            lines.append(
                f"- {p.header_name}: present on {p.present_count}/{p.total_count} responses"
            )
        lines.append("")
    if hints:
        lines.append("**Stack fingerprint hints:**")
        for hint in hints:
            lines.append(f"- `{hint.value[:200]}` ({hint.source})")
    return lines


def _render_toc(
    narrative_flows: list[Flow],
    entry_by_index: dict[int, HarEntry],
    confirmed_by_index: dict[int, bool],
) -> list[str]:
    if not narrative_flows:
        return []
    lines = ["", "## Contents", ""]
    for flow in narrative_flows:
        heading_text = _flow_heading_text(flow, entry_by_index, confirmed_by_index)
        lines.append(f"- [{heading_text}](#{_anchor_slug(heading_text)})")
    return lines


def _anchor_slug(heading_text: str) -> str:
    """Best-effort approximation of GitHub-flavored markdown's heading-anchor
    slugification, tuned for this renderer's actual '## Flow N — ...'
    heading shapes (not a fully general GFM-slug implementation).
    """
    lowered = heading_text.lower()
    kept = "".join(ch for ch in lowered if ch.isalnum() or ch in " -_")
    return kept.replace(" ", "-")


def _flow_heading_text(
    flow: Flow, entry_by_index: dict[int, HarEntry], confirmed_by_index: dict[int, bool]
) -> str:
    time_str = flow.started_at.strftime("%H:%M:%S")
    header_suffix = flow.category.value
    if flow.redirect_chain:
        header_suffix += ", redirect chain"
    elif flow.category == Category.XHR_API:
        primary = entry_by_index[flow.har_entry_indices[0]]
        referer = header_value(primary.request.headers, "referer")
        if referer:
            header_suffix += f", referer: {_path_and_query(referer)}"
    heading = f"Flow {flow.flow_id} — {time_str} ({header_suffix})"
    if not confirmed_by_index.get(flow.har_entry_indices[0], True):
        heading += " *(guessed)*"
    return heading


def _render_flow(
    flow: Flow,
    entry_by_index: dict[int, HarEntry],
    cluster_by_anchor_index: dict[int, Cluster],
    timing_outliers: dict[int, OutlierInfo],
    size_outliers: dict[int, OutlierInfo],
    confirmed_by_index: dict[int, bool],
) -> list[str]:
    heading_text = _flow_heading_text(flow, entry_by_index, confirmed_by_index)
    lines = [f"## {heading_text}", ""]

    if flow.redirect_chain:
        lines.extend(_render_redirect_chain(flow, entry_by_index))
    elif flow.category == Category.NAVIGATION:
        lines.extend(_render_navigation(flow, entry_by_index))
    elif flow.category == Category.XHR_API:
        lines.extend(_render_xhr_api(flow, entry_by_index))
    else:
        lines.extend(_render_other(flow, entry_by_index))

    if flow.category == Category.NAVIGATION:
        cluster = cluster_by_anchor_index.get(flow.har_entry_indices[0])
        if cluster is not None:
            asset_line = _render_assets_summary(cluster)
            if asset_line:
                lines.append("")
                lines.append(asset_line)

    if flow.polling_group is not None:
        lines.append("")
        lines.extend(_render_polling_note(flow, entry_by_index))

    outlier_note = _render_outlier_note(flow, timing_outliers, size_outliers)
    if outlier_note is not None:
        lines.append("")
        lines.append(outlier_note)

    lines.append("")
    lines.append(f"*(har_entry_index: {flow.har_entry_indices[0]})*")

    return lines


def _render_navigation(flow: Flow, entry_by_index: dict[int, HarEntry]) -> list[str]:
    entry = entry_by_index[flow.har_entry_indices[0]]
    content_type = _content_type(entry.response.headers)
    lines = [_status_line(entry, content_type)]
    lines.extend(
        _render_truncated_body(
            entry.response.body,
            flow.har_entry_indices[0],
            summary_label="Response body",
        )
    )
    return lines


def _render_redirect_chain(flow: Flow, entry_by_index: dict[int, HarEntry]) -> list[str]:
    hops = flow.redirect_hops
    assert hops is not None
    parts: list[str] = []
    for i, hop in enumerate(hops):
        entry = entry_by_index[hop.har_entry_index]
        if i == 0:
            parts.append(f"{_method_label(entry.request.method)} {entry.request.url}")
        else:
            parts.append(_path_and_query(entry.request.url))
        parts.append(f"`{hop.status}`")
    lines = [" → ".join(parts), ""]

    lines.append("<details>")
    lines.append("<summary>Redirect chain detail</summary>")
    lines.append("")
    lines.append("| Hop | URL | Status | Location |")
    lines.append("|---|---|---|---|")
    for i, hop in enumerate(hops):
        entry = entry_by_index[hop.har_entry_index]
        location = hop.location or "—"
        lines.append(
            f"| {i + 1} | {_path_and_query(entry.request.url)} | {hop.status} | {location} |"
        )
    lines.append("")
    lines.append("</details>")

    final_entry = entry_by_index[hops[-1].har_entry_index]
    lines.extend(
        _render_truncated_body(
            final_entry.response.body,
            hops[-1].har_entry_index,
            summary_label="Final response body",
        )
    )
    return lines


def _render_truncated_body(body: bytes, har_entry_index: int, *, summary_label: str) -> list[str]:
    if not body:
        return []
    text, truncated = _decode_truncated(body, _NAVIGATION_TRUNCATE_CHARS)
    lines = [""]
    if truncated:
        lines.append("<details>")
        lines.append(
            f"<summary>{summary_label} (truncated, {len(body)} bytes total, "
            f"see raw.har entry #{har_entry_index})</summary>"
        )
        lines.append("")
        lines.append("```html")
        lines.append(text)
        lines.append("```")
        lines.append("</details>")
    else:
        lines.append("```html")
        lines.append(text)
        lines.append("```")
    return lines


def _render_xhr_api(flow: Flow, entry_by_index: dict[int, HarEntry]) -> list[str]:
    entry = entry_by_index[flow.har_entry_indices[0]]
    content_type = _content_type(entry.response.headers)
    lines = [_status_line(entry, content_type)]

    if entry.request.headers:
        lines.append("")
        lines.append("Request headers:")
        lines.append("```")
        lines.extend(f"{h.name}: {h.value}" for h in entry.request.headers)
        lines.append("```")

    if entry.request.body:
        lines.append("")
        lines.append("Request body:")
        lines.append(_code_block(entry.request.body, _content_type(entry.request.headers)))

    if entry.response.body:
        lines.append("")
        lines.append("Response body:")
        lines.append(_code_block(entry.response.body, content_type))

    return lines


def _render_other(flow: Flow, entry_by_index: dict[int, HarEntry]) -> list[str]:
    entry = entry_by_index[flow.har_entry_indices[0]]
    lines = [
        f"{_method_label(entry.request.method)} {entry.request.url} → `{entry.response.status}`"
    ]
    if entry.response.body and len(entry.response.body) < _OTHER_INLINE_MAX_BYTES:
        lines.append("")
        lines.append("```")
        lines.append(_decode_for_display(entry.response.body))
        lines.append("```")
    return lines


def _render_polling_note(flow: Flow, entry_by_index: dict[int, HarEntry]) -> list[str]:
    group = flow.polling_group
    assert group is not None
    collapsed = group.collapsed_har_entry_indices
    interval_seconds = round(group.interval_seconds)

    shown = collapsed[:3]
    times = [entry_by_index[idx].started_at.strftime("%H:%M:%S") for idx in shown]
    idx_refs = ", ".join(f"#{idx}" for idx in shown)

    note = (
        f"**Note:** identical request observed again at {_join_with_and(times)} — "
        f"appears to be a {interval_seconds}-second polling interval. Subsequent "
        f"occurrences omitted from this narrative; see raw.har entries {idx_refs}."
    )
    if len(collapsed) > 3:
        note += f" ...and {len(collapsed) - 3} more occurrences through end of capture."
    return [note]


def _render_outlier_note(
    flow: Flow, timing_outliers: dict[int, OutlierInfo], size_outliers: dict[int, OutlierInfo]
) -> str | None:
    primary_index = flow.har_entry_indices[0]
    notes: list[str] = []
    timing = timing_outliers.get(primary_index)
    if timing is not None:
        notes.append(
            f"response time {round(timing.value)}ms — ~{timing.multiple:g}x the capture's "
            f"median ({round(timing.median)}ms)"
        )
    size = size_outliers.get(primary_index)
    if size is not None:
        notes.append(
            f"response body {_format_bytes_precise(int(size.value))} — ~{size.multiple:g}x the "
            f"capture's median ({_format_bytes_precise(int(size.median))})"
        )
    if not notes:
        return None
    return f"**Note:** {'; '.join(notes)}."


def _render_assets_summary(cluster: Cluster) -> str | None:
    assets = [m for m in cluster.members if m.category == Category.STATIC_ASSET]
    if not assets:
        return None
    kind_counts: dict[str, int] = {}
    total_bytes = 0
    for asset in assets:
        kind = _asset_kind(asset.entry)
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        total_bytes += len(asset.entry.response.body)
    breakdown = ", ".join(
        f"{kind_counts[kind]}x {kind}" for kind in _ASSET_KIND_ORDER if kind in kind_counts
    )
    return (
        f"**Assets loaded ({len(assets)}):** collapsed — {breakdown}, "
        f"{_format_bytes(total_bytes)} total"
    )


def _asset_kind(entry: HarEntry) -> str:
    content_type = _content_type(entry.response.headers)
    path = entry.request.url.lower()
    if content_type == "application/javascript" or path.endswith(".js"):
        return "JS"
    if content_type == "text/css" or path.endswith(".css"):
        return "CSS"
    if content_type.startswith("font/") or path.endswith(".woff2"):
        return "font"
    if content_type.startswith("image/") or path.endswith((".png", ".svg", ".jpg", ".ico")):
        return "image"
    return "other"


def _content_type(headers: tuple[HarHeader, ...]) -> str:
    value = header_value(headers, "content-type")
    return (value or "").split(";", 1)[0].strip()


def _method_label(method: str) -> str:
    label = f"**{method}**"
    if method.upper() in _STATE_CHANGING_METHODS:
        label += " *(state-changing)*"
    return label


def _status_line(entry: HarEntry, content_type: str) -> str:
    return (
        f"{_method_label(entry.request.method)} {entry.request.url} "
        f"→ `{entry.response.status}` `{content_type}`"
    )


def _code_block(body: bytes, content_type: str) -> str:
    lang = "json" if "json" in content_type.lower() else ""
    text = _format_body_text(body, content_type)
    return f"```{lang}\n{text}\n```"


def _format_body_text(body: bytes, content_type: str) -> str:
    if "json" in content_type.lower():
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        else:
            return json.dumps(parsed, indent=2)
    return _decode_for_display(body)


def _decode_for_display(body: bytes) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return f"<binary data, {len(body)} bytes>"


def _decode_truncated(body: bytes, max_chars: int) -> tuple[str, bool]:
    text = _decode_for_display(body)
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def _join_with_and(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _format_bytes(n: int) -> str:
    return f"{max(1, round(n / 1024))}KB" if n else "0KB"


def _format_bytes_precise(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    return _format_bytes(n)


def _path_and_query(url: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path


def _iso(value: datetime.datetime) -> str:
    text = value.astimezone(datetime.UTC).isoformat()
    if text.endswith("+00:00"):
        text = text[: -len("+00:00")] + "Z"
    return text
