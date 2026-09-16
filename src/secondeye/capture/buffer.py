"""Incremental JSONL capture buffer (SPEC.md §6.3).

Append-only: one line per completed request/response pair, flushed
(and fsynced) to disk as each pair completes rather than batched in
memory — this bounds memory usage to roughly what's currently in-flight
and gives a natural recovery path if the daemon crashes mid-capture.

TODO (not required for v1, SPEC.md §6.3): a ``secondeye capture recover
<path>`` subcommand reading a leftover JSONL from a crashed daemon is a
natural, cheap follow-on given this design.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from secondeye.capture.har import HarEntry, parse_har_entry

__all__ = ["CaptureBuffer", "read_buffer"]


class CaptureBuffer:
    """An append-only JSONL buffer for one active capture."""

    def __init__(self, path: Path) -> None:
        """Open (creating parent directories as needed) the buffer file for appending.

        Args:
            path: Where to write the JSONL buffer.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("a", encoding="utf-8")

    async def append(self, entry: HarEntry) -> None:
        """Append one entry, flushed and fsynced before returning.

        Args:
            entry: The completed request/response pair to record.
        """
        await asyncio.to_thread(self._append_sync, entry)

    def _append_sync(self, entry: HarEntry) -> None:
        line = json.dumps(entry.to_har_dict(), ensure_ascii=False)
        self._file.write(line + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())

    def close(self) -> None:
        """Close the underlying file handle."""
        self._file.close()


def read_buffer(path: Path) -> list[HarEntry]:
    """Read a JSONL buffer back into structured entries, in original order.

    Args:
        path: Path to a buffer file written by CaptureBuffer.

    Returns:
        The buffered entries, in the order they were appended.
    """
    entries: list[HarEntry] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            entries.append(parse_har_entry(json.loads(stripped)))
    return entries
