"""TLS termination and HTTP/1.1 proxying for in-scope connections
(SPEC.md §4.1, §4.6, §4.9, §5.2, §5.3, §10.1).

The client's ClientHello bytes have already been consumed by
proxy/listener.py's SNI peek (SPEC.md §4.2's buffer-and-replay), so this
module can't use ``asyncio.loop.start_tls()`` to terminate TLS — that API
expects to read the ClientHello itself from the transport, and those bytes
are gone from the socket by the time control reaches here. Instead
``_TlsMemoryBioStream`` drives the handshake manually via ``ssl.MemoryBIO``,
seeded with the prebuffered bytes, pumping ciphertext to/from the raw
connection as the handshake and subsequent application data require it.

Once TLS is up, each request/response cycle is handled by
proxy/_http_cycle.py (parsed from the client via h11, re-sent to the
upstream/destination, and the completed pair handed to capture/har.py to
build a HarEntry and to an injected ``on_entry_recorded`` callback —
recording/manager.py, a later phase, is the real implementation; this
module only depends on the callback shape). HTTP/1.1 keep-alive is
supported (h11's own state machine drives it) so a single TLS connection
can carry many requests, matching how real browsers behave. A 101
Switching Protocols response (WebSocket upgrade) ends h11 parsing per its
own state machine and switches to raw passthrough — SPEC.md §0 requires
WebSocket frames to pass through, not be recorded/analyzed.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import ssl
import time
from collections.abc import Awaitable, Callable

import h11

from secondeye.capture.har import HarEntry, build_har_entry
from secondeye.exceptions import CertGenerationError, UpstreamConnectionError
from secondeye.proxy._http_cycle import (
    WEBSOCKET_SWITCHING_PROTOCOLS,
    forward_and_receive,
    raw_passthrough,
    read_request,
    write_response,
)
from secondeye.proxy.upstream import UpstreamConnector
from secondeye.tls.leaf import LeafCertificateStore

__all__ = ["InterceptHandler"]

logger = logging.getLogger(__name__)

_TLS_READ_CHUNK = 65536

RecordCallback = Callable[[HarEntry], Awaitable[None]]


class _TlsMemoryBioStream:
    """Drives a server-side TLS session over a raw stream pair whose
    ClientHello bytes may already be partially consumed.

    Uses ssl.MemoryBIO directly rather than asyncio's transport-level TLS
    support, since the latter can't resume a handshake from pre-read bytes
    (SPEC.md §4.2's buffer-and-replay is exactly that situation).
    """

    def __init__(
        self,
        raw_reader: asyncio.StreamReader,
        raw_writer: asyncio.StreamWriter,
        ssl_context: ssl.SSLContext,
        prebuffered: bytes,
    ) -> None:
        self._raw_reader = raw_reader
        self._raw_writer = raw_writer
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._sslobj = ssl_context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        if prebuffered:
            self._incoming.write(prebuffered)

    async def do_handshake(self) -> None:
        """Complete the TLS handshake, pumping ciphertext as needed."""
        while True:
            try:
                self._sslobj.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._pump_outgoing()
                await self._feed_more_input()
        await self._pump_outgoing()

    async def read(self, n: int = _TLS_READ_CHUNK) -> bytes:
        """Read up to n bytes of decrypted application data (b"" on EOF)."""
        while True:
            try:
                return bytes(self._sslobj.read(n))
            except ssl.SSLWantReadError:
                await self._pump_outgoing()
                await self._feed_more_input()

    async def write(self, data: bytes) -> None:
        """Encrypt and send data, draining ciphertext to the raw writer."""
        while data:
            try:
                sent = self._sslobj.write(data)
            except ssl.SSLWantReadError:
                await self._pump_outgoing()
                await self._feed_more_input()
                continue
            data = data[sent:]
        await self._pump_outgoing()

    async def close(self) -> None:
        """Best-effort clean shutdown, then close the underlying connection."""
        try:
            self._sslobj.unwrap()
        except (ssl.SSLError, OSError):
            pass
        try:
            await self._pump_outgoing()
        except OSError:
            pass
        if not self._raw_writer.is_closing():
            self._raw_writer.close()
            try:
                await self._raw_writer.wait_closed()
            except OSError:
                pass

    async def _pump_outgoing(self) -> None:
        data = self._outgoing.read()
        if data:
            self._raw_writer.write(data)
            await self._raw_writer.drain()

    async def _feed_more_input(self) -> None:
        data = await self._raw_reader.read(_TLS_READ_CHUNK)
        if not data:
            self._incoming.write_eof()
        else:
            self._incoming.write(data)


class InterceptHandler:
    """Terminates TLS, parses HTTP/1.1 via h11, forwards, and records
    (SPEC.md §4.1's in-scope path).
    """

    def __init__(
        self,
        *,
        leaf_store: LeafCertificateStore,
        upstream_connector: UpstreamConnector,
        on_entry_recorded: RecordCallback,
    ) -> None:
        """Wire up the pieces this handler orchestrates.

        Args:
            leaf_store: Generates/caches CA-signed leaf certs per SNI.
            upstream_connector: Establishes the re-encrypted outbound leg.
            on_entry_recorded: Invoked with each completed HarEntry. The
                real implementation (recording/manager.py) is a later
                phase; this module only depends on the callback shape.
        """
        self._leaf_store = leaf_store
        self._upstream_connector = upstream_connector
        self._on_entry_recorded = on_entry_recorded

    async def __call__(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        sni: str,
        port: int,
        prebuffered: bytes,
    ) -> None:
        """Handle one in-scope CONNECT tunnel (matches listener.InScopeHandler).

        Args:
            client_reader: Reader for the client's CONNECT tunnel.
            client_writer: Writer for the client's CONNECT tunnel.
            sni: The SNI (or CONNECT target host) the client presented.
            port: The destination port, exactly as given in CONNECT
                (SPEC.md §4.5 — never hardcoded to 443).
            prebuffered: ClientHello bytes already consumed by the SNI peek.
        """
        try:
            ssl_context = await asyncio.to_thread(self._leaf_store.get_context, sni)
        except CertGenerationError:
            logger.error("dropping connection: leaf cert generation failed for %s", sni)
            await _close_quietly(client_writer)
            return

        tls_stream = _TlsMemoryBioStream(client_reader, client_writer, ssl_context, prebuffered)
        try:
            await tls_stream.do_handshake()
        except (ssl.SSLError, OSError) as exc:
            logger.error("TLS handshake with client failed for %s: %s", sni, exc)
            # asyncio only closes the transport for us if client_connected_cb
            # is cancelled or raises — a clean early return here would
            # otherwise leak the connection until GC happens to collect it.
            await tls_stream.close()
            return

        try:
            await self._serve_requests(tls_stream, sni, port)
        except Exception:
            logger.exception("unhandled exception intercepting connection to %s:%d", sni, port)
        finally:
            await tls_stream.close()

    async def _serve_requests(self, tls_stream: _TlsMemoryBioStream, sni: str, port: int) -> None:
        conn = h11.Connection(our_role=h11.SERVER)
        while True:
            request_event, request_body, ok = await read_request(tls_stream, conn)
            if not ok or request_event is None:
                return

            started_at = datetime.datetime.now(datetime.UTC)
            start_perf = time.monotonic()

            try:
                upstream_reader, upstream_writer = await self._upstream_connector.connect_tls(
                    sni, port
                )
            except UpstreamConnectionError as exc:
                logger.error("upstream/destination unreachable for %s:%d: %s", sni, port, exc)
                await _send_bad_gateway(tls_stream, conn)
                return

            try:
                response_event, response_body, upstream_trailing = await forward_and_receive(
                    upstream_reader, upstream_writer, request_event, request_body
                )
            except (h11.RemoteProtocolError, OSError) as exc:
                logger.error("upstream/destination response error for %s:%d: %s", sni, port, exc)
                upstream_writer.close()
                await _send_bad_gateway(tls_stream, conn)
                return

            time_ms = (time.monotonic() - start_perf) * 1000
            target = request_event.target.decode("ascii", errors="replace")
            url = f"https://{sni}{target}"
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

            await write_response(tls_stream, conn, response_event, response_body)

            if response_event.status_code == WEBSOCKET_SWITCHING_PROTOCOLS:
                logger.debug("WebSocket upgrade for %s:%d; switching to raw passthrough", sni, port)
                client_trailing, _client_closed = conn.trailing_data
                await raw_passthrough(
                    tls_stream,
                    upstream_reader,
                    upstream_writer,
                    client_to_upstream_prebuffered=client_trailing,
                    upstream_to_client_prebuffered=upstream_trailing,
                )
                return

            upstream_writer.close()

            if conn.our_state is h11.MUST_CLOSE or conn.their_state is h11.MUST_CLOSE:
                return
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                return


async def _send_bad_gateway(tls_stream: _TlsMemoryBioStream, conn: h11.Connection) -> None:
    body = b"secondeye: upstream/destination unreachable\n"
    response = h11.Response(
        status_code=502,
        headers=[("Content-Length", str(len(body))), ("Connection", "close")],
    )
    try:
        await write_response(tls_stream, conn, response, body)
    except (ssl.SSLError, OSError):
        pass


async def _close_quietly(writer: asyncio.StreamWriter) -> None:
    if writer.is_closing():
        return
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
