"""Shared, transport-agnostic HTTP/1.1 request/response cycle via h11.

Used by both proxy/intercept.py (client leg is TLS, over _TlsMemoryBioStream)
and proxy/plain_http.py (client leg is cleartext, over a thin asyncio.Stream*
adapter) — the h11 mechanics (parsing, forwarding, 101/keep-alive handling)
are identical either way, so they live here once rather than being
duplicated per transport. Not a phase module in its own right (SPEC.md §13
doesn't name it) — an internal implementation detail shared by two phase
modules, hence the leading underscore.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

import h11

__all__ = [
    "AsyncStream",
    "WEBSOCKET_SWITCHING_PROTOCOLS",
    "forward_and_receive",
    "raw_passthrough",
    "read_request",
    "write_response",
]

_UPSTREAM_READ_CHUNK = 65536
WEBSOCKET_SWITCHING_PROTOCOLS = 101


class AsyncStream(Protocol):
    """The minimal async read/write shape both client-leg transports share."""

    async def read(self, n: int = ...) -> bytes: ...

    async def write(self, data: bytes) -> None: ...


async def read_request(
    stream: AsyncStream, conn: h11.Connection
) -> tuple[h11.Request | None, bytes, bool]:
    """Read one full request off a client stream via h11.

    Args:
        stream: The client-facing stream (decrypted TLS or cleartext).
        conn: An h11.Connection with our_role=h11.SERVER.

    Returns:
        (request_event, body, ok). ok is False when the client closed the
        connection cleanly (a normal end to a keep-alive session) or sent
        malformed HTTP — either way, nothing more can be read.
    """
    request_event: h11.Request | None = None
    body = b""
    while True:
        try:
            event = conn.next_event()
        except h11.RemoteProtocolError:
            return None, b"", False

        if event is h11.NEED_DATA:
            try:
                chunk = await stream.read()
            except OSError:
                return None, b"", False
            conn.receive_data(chunk)
            continue
        if isinstance(event, h11.ConnectionClosed):
            return None, b"", False
        if isinstance(event, h11.Request):
            request_event = event
        elif isinstance(event, h11.Data):
            body += bytes(event.data)
        elif isinstance(event, h11.EndOfMessage):
            break
    return request_event, body, True


async def forward_and_receive(
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    request_event: h11.Request,
    request_body: bytes,
) -> tuple[h11.Response | h11.InformationalResponse, bytes, bytes]:
    """Re-send a parsed client request to upstream and parse its response.

    Args:
        upstream_reader: Reader for the upstream/destination connection.
        upstream_writer: Writer for the upstream/destination connection.
        request_event: The parsed h11.Request from the client leg.
        request_body: The fully-accumulated request body from the client.

    Returns:
        (response_event, response_body, trailing_data). trailing_data is
        non-empty only after a 101 response: h11 may have over-read bytes
        that arrived bundled with it (e.g. the first WebSocket frame sent
        immediately after the upgrade) into its receive buffer, which
        aren't retrievable through next_event() once switched protocols —
        only through Connection.trailing_data.

    Raises:
        h11.RemoteProtocolError: If upstream never sends a usable response.
    """
    upstream_conn = h11.Connection(our_role=h11.CLIENT)
    outgoing_request = h11.Request(
        method=request_event.method,
        target=request_event.target,
        headers=request_event.headers.raw_items(),
        http_version=request_event.http_version,
    )
    _send(upstream_conn, upstream_writer, outgoing_request)
    if request_body:
        _send(upstream_conn, upstream_writer, h11.Data(data=request_body))
    _send(upstream_conn, upstream_writer, h11.EndOfMessage())
    await upstream_writer.drain()

    response_event: h11.Response | h11.InformationalResponse | None = None
    body = b""
    while True:
        event = upstream_conn.next_event()
        if event is h11.NEED_DATA:
            chunk = await upstream_reader.read(_UPSTREAM_READ_CHUNK)
            upstream_conn.receive_data(chunk)
            continue
        if event is h11.PAUSED:
            # Only reachable after a 101 Switching Protocols response: h11
            # treats that as the end of normal HTTP framing entirely, and
            # never emits an EndOfMessage for it.
            break
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == WEBSOCKET_SWITCHING_PROTOCOLS:
                response_event = event
                break
            continue  # e.g. 100 Continue: not the final response
        if isinstance(event, h11.Response):
            response_event = event
        elif isinstance(event, h11.Data):
            body += bytes(event.data)
        elif isinstance(event, h11.EndOfMessage | h11.ConnectionClosed):
            break
    if response_event is None:
        raise h11.RemoteProtocolError("upstream closed the connection before sending a response")
    trailing_data, _closed = upstream_conn.trailing_data
    return response_event, body, trailing_data


def _send(conn: h11.Connection, writer: asyncio.StreamWriter, event: h11.Event) -> None:
    data = conn.send(event)
    if data:
        writer.write(data)


async def write_response(
    stream: AsyncStream,
    conn: h11.Connection,
    response_event: h11.Response | h11.InformationalResponse,
    body: bytes,
) -> None:
    """Send a parsed response back out over the client stream via h11.

    Args:
        stream: The client-facing stream (decrypted TLS or cleartext).
        conn: The same h11.Connection (our_role=h11.SERVER) read_request used.
        response_event: The response to relay to the client.
        body: The response body to relay to the client.
    """
    data = conn.send(response_event)
    if data:
        await stream.write(data)
    if isinstance(response_event, h11.InformationalResponse):
        # A 101 switches h11 straight to SWITCHED_PROTOCOL; it accepts no
        # further Data/EndOfMessage sends for this "response".
        return
    if body:
        data = conn.send(h11.Data(data=body))
        if data:
            await stream.write(data)
    data = conn.send(h11.EndOfMessage())
    if data:
        await stream.write(data)


async def raw_passthrough(
    client_stream: AsyncStream,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    *,
    client_to_upstream_prebuffered: bytes = b"",
    upstream_to_client_prebuffered: bytes = b"",
) -> None:
    """Blindly relay bytes after a WebSocket upgrade (SPEC.md §0).

    Args:
        client_stream: The client's (now-switched-protocol) stream.
        upstream_reader: Reader for the upstream/destination connection.
        upstream_writer: Writer for the upstream/destination connection.
        client_to_upstream_prebuffered: Bytes the client already sent that
            were over-read into the h11 Connection's buffer alongside its
            request and must be replayed to upstream first (h11's
            trailing_data — see forward_and_receive).
        upstream_to_client_prebuffered: The same, in the other direction,
            for bytes upstream sent bundled with its 101 response.

    A minimal, self-contained cousin of proxy/splice.py's
    cancel-on-first-complete pattern — kept separate because AsyncStream
    isn't an asyncio.StreamReader/Writer, so it can't be passed through
    splice()'s type signature.
    """
    if upstream_to_client_prebuffered:
        await client_stream.write(upstream_to_client_prebuffered)
    if client_to_upstream_prebuffered:
        upstream_writer.write(client_to_upstream_prebuffered)
        await upstream_writer.drain()

    async def pump_client_to_upstream() -> None:
        try:
            while True:
                data = await client_stream.read()
                if not data:
                    return
                upstream_writer.write(data)
                await upstream_writer.drain()
        except OSError:
            return

    async def pump_upstream_to_client() -> None:
        try:
            while True:
                data = await upstream_reader.read(_UPSTREAM_READ_CHUNK)
                if not data:
                    return
                await client_stream.write(data)
        except OSError:
            return

    task_a = asyncio.ensure_future(pump_client_to_upstream())
    task_b = asyncio.ensure_future(pump_upstream_to_client())
    try:
        await asyncio.wait({task_a, task_b}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (task_a, task_b):
            if not task.done():
                task.cancel()
        await asyncio.gather(task_a, task_b, return_exceptions=True)
        if not upstream_writer.is_closing():
            upstream_writer.close()
