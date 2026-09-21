"""Per-entry classification (SPEC.md §11.2).

Prefers Sec-Fetch-* headers where present (sent by default in modern
Chromium/Firefox) over content-type guessing, per SPEC.md §11.2.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from secondeye.capture.har import HarEntry, header_value

__all__ = ["Category", "ClassifiedEntry", "classify_entries", "classify_entry"]

_STATIC_ASSET_CONTENT_TYPES = frozenset({"text/css", "application/javascript"})
_STATIC_ASSET_EXTENSIONS = (".js", ".css", ".woff2", ".png", ".svg", ".jpg", ".ico")


class Category(StrEnum):
    """A HAR entry's traffic category (SPEC.md §11.2)."""

    NAVIGATION = "navigation"
    XHR_API = "xhr-api"
    STATIC_ASSET = "static-asset"
    OTHER = "other"


@dataclass(frozen=True)
class ClassifiedEntry:
    """A HarEntry paired with its position in raw.har and its category.

    Attributes:
        index: Position in raw.har's log.entries[] array.
        entry: The classified HarEntry.
        category: The classification result.
        confirmed: True if Sec-Fetch-* headers positively determined the
            category; False if classification fell back to content-type/
            extension heuristics (SPEC.md §11.2's "prefer Sec-Fetch-*
            headers" note — this flag records which path was taken).
    """

    index: int
    entry: HarEntry
    category: Category
    confirmed: bool


def classify_entry(entry: HarEntry) -> Category:
    """Classify a single HAR entry (SPEC.md §11.2's detection table).

    Args:
        entry: The entry to classify.

    Returns:
        The entry's traffic category.
    """
    category, _confirmed = _classify_entry_detailed(entry)
    return category


def _classify_entry_detailed(entry: HarEntry) -> tuple[Category, bool]:
    """Classify a single HAR entry and report classification confidence.

    Args:
        entry: The entry to classify.

    Returns:
        (category, confirmed) — confirmed is True only when Sec-Fetch-*
        headers positively determined the category; False when
        classification fell back to content-type/extension heuristics
        (SPEC.md §11.9).
    """
    sec_fetch_mode = header_value(entry.request.headers, "sec-fetch-mode")
    if sec_fetch_mode == "navigate":
        return Category.NAVIGATION, True
    if sec_fetch_mode in ("cors", "same-origin") and (
        header_value(entry.request.headers, "x-requested-with") is not None
    ):
        return Category.XHR_API, True

    content_type = header_value(entry.response.headers, "content-type") or ""
    content_type_base = content_type.split(";", 1)[0].strip().lower()

    if content_type_base.startswith("text/html") and entry.request.method == "GET":
        return Category.NAVIGATION, False

    if content_type_base in ("application/json", "application/xml") or entry.request.body:
        return Category.XHR_API, False

    if _is_static_asset_content_type(content_type_base) or _has_static_asset_extension(
        entry.request.url
    ):
        return Category.STATIC_ASSET, False

    return Category.OTHER, False


def classify_entries(entries: list[HarEntry]) -> list[ClassifiedEntry]:
    """Classify a full raw.har entries list, preserving index/order.

    Args:
        entries: Entries in raw.har's log.entries[] order.

    Returns:
        One ClassifiedEntry per input entry, in the same order.
    """
    result: list[ClassifiedEntry] = []
    for i, entry in enumerate(entries):
        category, confirmed = _classify_entry_detailed(entry)
        result.append(ClassifiedEntry(index=i, entry=entry, category=category, confirmed=confirmed))
    return result


def _is_static_asset_content_type(content_type_base: str) -> bool:
    if content_type_base in _STATIC_ASSET_CONTENT_TYPES:
        return True
    return content_type_base.startswith("font/") or content_type_base.startswith("image/")


def _has_static_asset_extension(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(_STATIC_ASSET_EXTENSIONS)
