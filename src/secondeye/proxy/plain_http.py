"""Plain HTTP (absolute-URI, non-CONNECT) proxying for in-scope requests
(SPEC.md §4.4).

Explicit proxies receive plain HTTP requests with an absolute-form URI
directly in the request line — no CONNECT, no TLS, no SNI peek, no cert
generation needed, simpler than the HTTPS path. But a single keep-alive
connection to this proxy can carry requests to *different* hosts one after
another (unlike CONNECT, which pins the tunnel to one destination for its
lifetime), so the scope decision happens per request here, not once at
connection-accept time the way proxy/listener.py does it for CONNECT.

Reuses proxy/_http_cycle.py for the actual h11 request/response mechanics —
identical to proxy/intercept.py's, just over a cleartext stream instead of
a TLS one — rather than being forced through intercept.py's TLS-specific
logic (SPEC.md §4.4's explicit instruction).
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import h11

from secondeye.capture.har import HarEntry, build_har_entry
from secondeye.exceptions import UpstreamConnectionError
from secondeye.proxy._http_cycle import forward_and_receive, read_request, write_response
from secondeye.proxy.upstream import UpstreamConnector
from secondeye.scope.matcher import ScopeMatcher

__all__ = ["PlainHttpHandler"]

logger = logging.getLogger(__name__)

_DEFAULT_HTTP_PORT = 80

RecordCallback = Callable[[HarEntry], Awaitable[None]]


class _PlainStream:
    """Adapts a plain asyncio (reader, writer) pair to _http_cycle.AsyncStream."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, n: int = 65536) -> bytes:
        return await self._reader.read(n)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()


class PlainHttpHandler:
    """Handles non-CONNECT (absolute-URI) requests (SPEC.md §4.4)."""

    def __init__(
        self,
        *,
        scope_matcher: ScopeMatcher,
        target_all: bool,
        upstream_connector: UpstreamConnector,
        on_entry_recorded: RecordCallback,
    ) -> None:
        """Wire up the pieces this handler orchestrates.

        Args:
            scope_matcher: Compiled --target/--target-regex scope.
            target_all: Bypass scope matching entirely (SPEC.md §3.4).
            upstream_connector: Establishes the outbound leg per request.
            on_entry_recorded: Invoked with each completed in-scope
                HarEntry. The real implementation (recording/manager.py)
                is a later phase; this module only depends on the
                callback shape.
        """
        self._scope_matcher = scope_matcher
        self._target_all = target_all
        self._upstream_connector = upstream_connector
        self._on_entry_recorded = on_entry_recorded

    async def __call__(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        prebuffered: bytes,
    ) -> None:
        """Handle one plain-HTTP client connection (matches listener.PlainHttpHandler).

        Args:
            client_reader: Reader for the client's plain-HTTP connection.
            client_writer: Writer for the client's plain-HTTP connection.
            prebuffered: The first request's request-line-plus-headers
                bytes, already consumed by proxy/listener.py while telling
                this request apart from CONNECT.
        """
        stream = _PlainStream(client_reader, client_writer)
        conn = h11.Connection(our_role=h11.SERVER)
        conn.receive_data(prebuffered)
        try:
            await self._serve_requests(stream, conn)
        except Exception:
            logger.exception("unhandled exception handling plain-HTTP connection")
        finally:
            if not client_writer.is_closing():
                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except OSError:
                    pass

    async def _serve_requests(self, stream: _PlainStream, conn: h11.Connection) -> None:
        while True:
            request_event, request_body, ok = await read_request(stream, conn)
            if not ok or request_event is None:
                return

            parsed = _parse_absolute_target(request_event)
            if parsed is None:
                logger.warning(
                    "dropping plain-HTTP connection: non-absolute-URI target %r",
                    request_event.target,
                )
                return
            host, port, path = parsed

            in_scope = self._target_all or self._scope_matcher.match(host).matched

            started_at = datetime.datetime.now(datetime.UTC)
            start_perf = time.monotonic()

            outgoing_request = request_event
            if self._upstream_connector.no_upstream:
                # Talking directly to the origin server: rewrite to
                # origin-form, the conventional/safe target shape.
                outgoing_request = h11.Request(
                    method=request_event.method,
                    target=path,
                    headers=request_event.headers.raw_items(),
                    http_version=request_event.http_version,
                )

            try:
                (
                    upstream_reader,
                    upstream_writer,
                ) = await self._upstream_connector.connect_plain_http(host, port)
            except UpstreamConnectionError as exc:
                logger.error("upstream/destination unreachable for %s:%d: %s", host, port, exc)
                await _send_bad_gateway(stream, conn)
                return

            try:
                response_event, response_body, _trailing = await forward_and_receive(
                    upstream_reader, upstream_writer, outgoing_request, request_body
                )
            except (h11.RemoteProtocolError, OSError) as exc:
                logger.error("upstream/destination response error for %s:%d: %s", host, port, exc)
                upstream_writer.close()
                await _send_bad_gateway(stream, conn)
                return

            time_ms = (time.monotonic() - start_perf) * 1000

            if in_scope:
                url = _build_url(host, port, path)
                entry = build_har_entry(
                    request_event=request_event,
                    request_body=request_body,
                    response_event=response_event,
                    response_body=response_body,
                    url=url,
                    started_at=started_at,
                    time_ms=time_ms,
                )
                await self._on_entry_recorded(entry)

            await write_response(stream, conn, response_event, response_body)
            upstream_writer.close()

            if conn.our_state is h11.MUST_CLOSE or conn.their_state is h11.MUST_CLOSE:
                return
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                return


def _parse_absolute_target(request_event: h11.Request) -> tuple[str, int, str] | None:
    """Parse an absolute-URI request target into (host, port, path).

    Args:
        request_event: The parsed h11.Request from the client.

    Returns:
        (host, port, path_plus_query), or None if the target isn't a valid
        absolute http:// URI (SPEC.md §4.4 describes absolute-URI as the
        expected shape for this code path).
    """
    target = request_event.target.decode("ascii", errors="replace")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or not parsed.hostname:
        return None
    port = parsed.port or _DEFAULT_HTTP_PORT
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return parsed.hostname, port, path


def _build_url(host: str, port: int, path: str) -> str:
    authority = host if port == _DEFAULT_HTTP_PORT else f"{host}:{port}"
    return f"http://{authority}{path}"


async def _send_bad_gateway(stream: _PlainStream, conn: h11.Connection) -> None:
    body = b"secondeye: upstream/destination unreachable\n"
    response = h11.Response(
        status_code=502,
        headers=[("Content-Length", str(len(body))), ("Connection", "close")],
    )
    try:
        await write_response(stream, conn, response, body)
    except OSError:
        pass
