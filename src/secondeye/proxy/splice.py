"""Blind bidirectional relay for out-of-scope connections (SPEC.md §4.1, §4.2).

Out-of-scope connections get zero cert operations and zero inspection: the
buffered ClientHello bytes are replayed to the destination verbatim
(buffer-and-replay, SPEC.md §4.2), then raw bytes are relayed in both
directions, untouched, until either side closes.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

__all__ = ["RemoteConnector", "blind_relay", "splice"]

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536

RemoteConnector = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


async def splice(
    reader_a: asyncio.StreamReader,
    writer_a: asyncio.StreamWriter,
    reader_b: asyncio.StreamReader,
    writer_b: asyncio.StreamWriter,
) -> None:
    """Relay raw bytes bidirectionally between two connected stream pairs.

    Returns as soon as either side closes or errors, cancelling the other
    direction's pump and closing both writers so neither peer is left
    hanging.

    Args:
        reader_a: Reader for the first connection (e.g. the client).
        writer_a: Writer for the first connection.
        reader_b: Reader for the second connection (e.g. the destination).
        writer_b: Writer for the second connection.
    """

    async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(_CHUNK_SIZE)
                if not data:
                    return
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            return

    task_a_to_b = asyncio.ensure_future(pump(reader_a, writer_b))
    task_b_to_a = asyncio.ensure_future(pump(reader_b, writer_a))
    try:
        await asyncio.wait({task_a_to_b, task_b_to_a}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (task_a_to_b, task_b_to_a):
            if not task.done():
                task.cancel()
        await asyncio.gather(task_a_to_b, task_b_to_a, return_exceptions=True)
        for writer in (writer_a, writer_b):
            if not writer.is_closing():
                writer.close()


async def blind_relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    host: str,
    port: int,
    connect_remote: RemoteConnector,
    prebuffered: bytes = b"",
) -> None:
    """Connect to a destination and blindly relay bytes with the client.

    Args:
        client_reader: Reader for the client's CONNECT tunnel.
        client_writer: Writer for the client's CONNECT tunnel.
        host: Destination host to connect to (SPEC.md §4.5; not scope-decided
            here — the caller has already classified this connection as
            out-of-scope).
        port: Destination port to connect to, exactly as given in the
            CONNECT request (never hardcoded to 443, SPEC.md §4.5).
        connect_remote: Async callable establishing the outbound connection.
            Injected so the caller controls upstream-vs-direct routing.
        prebuffered: Bytes already read from the client (the buffered
            ClientHello) that must be replayed to the destination first
            (SPEC.md §4.2).
    """
    remote_reader, remote_writer = await connect_remote(host, port)
    if prebuffered:
        remote_writer.write(prebuffered)
        await remote_writer.drain()
    await splice(client_reader, client_writer, remote_reader, remote_writer)
