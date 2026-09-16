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
    """

    index: int
    entry: HarEntry
    category: Category


def classify_entry(entry: HarEntry) -> Category:
    """Classify a single HAR entry (SPEC.md §11.2's detection table).

    Args:
        entry: The entry to classify.

    Returns:
        The entry's traffic category.
    """
    sec_fetch_mode = header_value(entry.request.headers, "sec-fetch-mode")
    if sec_fetch_mode == "navigate":
        return Category.NAVIGATION
    if sec_fetch_mode in ("cors", "same-origin") and (
        header_value(entry.request.headers, "x-requested-with") is not None
    ):
        return Category.XHR_API

    content_type = header_value(entry.response.headers, "content-type") or ""
    content_type_base = content_type.split(";", 1)[0].strip().lower()

    if content_type_base.startswith("text/html") and entry.request.method == "GET":
        return Category.NAVIGATION

    if content_type_base in ("application/json", "application/xml") or entry.request.body:
        return Category.XHR_API

    if _is_static_asset_content_type(content_type_base) or _has_static_asset_extension(
        entry.request.url
    ):
        return Category.STATIC_ASSET

    return Category.OTHER


def classify_entries(entries: list[HarEntry]) -> list[ClassifiedEntry]:
    """Classify a full raw.har entries list, preserving index/order.

    Args:
        entries: Entries in raw.har's log.entries[] order.

    Returns:
        One ClassifiedEntry per input entry, in the same order.
    """
    return [
        ClassifiedEntry(index=i, entry=entry, category=classify_entry(entry))
        for i, entry in enumerate(entries)
    ]


def _is_static_asset_content_type(content_type_base: str) -> bool:
    if content_type_base in _STATIC_ASSET_CONTENT_TYPES:
        return True
    return content_type_base.startswith("font/") or content_type_base.startswith("image/")


def _has_static_asset_extension(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(_STATIC_ASSET_EXTENSIONS)
