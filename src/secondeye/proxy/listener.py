"""CONNECT listener: SNI-gated scope decision, loopback enforcement, max-connections
(SPEC.md §4.1, §4.5, §4.7, §4.8).

Plain HTTP (absolute-URI, non-CONNECT) requests are a real, required code
path but a separate one (SPEC.md §4.4): no SNI peek, no cert generation, no
scope decision here (a keep-alive plain-HTTP connection to this proxy can
carry requests to different hosts one after another, so per-request scope
decisions belong to proxy/plain_http.py, not this listener). This module
only reads the request line far enough to tell CONNECT from everything
else, then either runs the CONNECT-specific flow itself or hands off the
already-consumed bytes to the injected plain-HTTP handler.

Routing a connection once it's known to be in-scope (proxy/intercept.py) and
reaching the destination for the out-of-scope blind-relay path
(proxy/upstream.py's Burp-chaining vs. --no-upstream direct connect) are
both injected dependencies (``on_in_scope`` / ``connect_remote``) rather
than hardcoded here, so this listener stays testable against the transport
concerns it actually owns; daemon.py/cli.py (a later phase) wires in the
real implementations.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Callable

from secondeye.exceptions import ConfigError, UpstreamConnectionError
from secondeye.proxy.sni import SniOutcome, parse_client_hello
from secondeye.proxy.splice import RemoteConnector, blind_relay
from secondeye.scope.matcher import ScopeMatcher

__all__ = ["InScopeHandler", "PlainHttpHandler", "ProxyListener", "ensure_loopback"]

logger = logging.getLogger(__name__)

_CONNECT_REQUEST_TIMEOUT = 10.0
_CLIENT_HELLO_READ_TIMEOUT = 10.0
_CLIENT_HELLO_READ_CHUNK = 4096

InScopeHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter, str, int, bytes], Awaitable[None]
]
PlainHttpHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter, bytes], Awaitable[None]]


def ensure_loopback(host: str) -> None:
    """Raise ConfigError unless host is a loopback IP literal (SPEC.md §4.7).

    Args:
        host: The configured --listen host.

    Raises:
        ConfigError: If host is not a valid loopback IP literal. No override
            exists for this check — it is a security invariant, not a
            configuration preference.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ConfigError(
            f"--listen host {host!r} must be a loopback IP literal (127.0.0.1 or ::1)"
        ) from exc
    if not addr.is_loopback:
        raise ConfigError(f"--listen host {host!r} is not loopback (127.0.0.1 or ::1)")


class ProxyListener:
    """Accepts CONNECT tunnels, peeks SNI, and routes by scope (SPEC.md §4.1).

    In-scope connections (matched target/regex, or --capture-all) are
    handed to an injected handler. Out-of-scope connections are blindly
    relayed via proxy/splice.py with zero TLS/cert operations.
    """

    def __init__(
        self,
        *,
        listen_host: str,
        listen_port: int,
        scope_matcher: ScopeMatcher,
        capture_all: bool,
        max_connections: int,
        connect_remote: RemoteConnector,
        on_in_scope: InScopeHandler,
        on_plain_http: PlainHttpHandler,
    ) -> None:
        """Validate configuration and prepare the listener (not yet bound).

        Args:
            listen_host: Bind host; must be loopback (SPEC.md §4.7).
            listen_port: Bind port (0 for an OS-assigned ephemeral port).
            scope_matcher: Compiled --target/--target-regex scope.
            capture_all: Bypass scope matching entirely (SPEC.md §3.4).
            max_connections: Hard cap on concurrent connections (SPEC.md §4.8).
            connect_remote: Async callable establishing an outbound
                connection for the out-of-scope blind-relay path.
            on_in_scope: Async callable invoked for in-scope CONNECT
                connections, given the client stream pair, the SNI (or
                CONNECT target host if no SNI was presented and
                --capture-all is set), the destination port, and the
                buffered ClientHello bytes.
            on_plain_http: Async callable invoked for non-CONNECT
                (absolute-URI) requests, given the client stream pair and
                the request-line-plus-headers bytes already consumed while
                telling this request apart from CONNECT (SPEC.md §4.4).

        Raises:
            ConfigError: If listen_host is not loopback.
        """
        ensure_loopback(listen_host)
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._scope_matcher = scope_matcher
        self._capture_all = capture_all
        self._max_connections = max_connections
        self._connect_remote = connect_remote
        self._on_in_scope = on_in_scope
        self._on_plain_http = on_plain_http
        self._server: asyncio.Server | None = None
        self._active_connections = 0
        self._logged_domains: set[str] = set()

    @property
    def active_connections(self) -> int:
        """Current count of connections being actively handled."""
        return self._active_connections

    @property
    def bound_port(self) -> int:
        """The OS-assigned port the listener is bound to.

        Raises:
            RuntimeError: If the listener has not been started yet.
        """
        if self._server is None:
            raise RuntimeError("listener has not been started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        """Bind the listener and begin accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_connection, self._listen_host, self._listen_port
        )

    async def stop(self) -> None:
        """Stop accepting new connections and wait for the listener to close."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")

        if self._active_connections >= self._max_connections:
            logger.warning(
                "max-connections limit (%d) reached; rejecting connection from %s",
                self._max_connections,
                peername,
            )
            await _close_quietly(writer)
            return

        self._active_connections += 1
        logger.info("connection established from %s", peername)
        try:
            await self._process_connection(reader, writer, peername)
        except Exception:
            logger.exception("unhandled exception handling connection from %s", peername)
        finally:
            self._active_connections -= 1
            await _close_quietly(writer)
            logger.info("connection closed from %s", peername)

    async def _process_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peername: object,
    ) -> None:
        parsed = await _read_request_line(reader)
        if parsed is None:
            logger.warning("dropping connection from %s: unreadable/oversized request", peername)
            return

        method, host, port, raw_request = parsed
        if method != "CONNECT":
            await self._on_plain_http(reader, writer, raw_request)
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        buffer = bytearray()
        while True:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(_CLIENT_HELLO_READ_CHUNK), _CLIENT_HELLO_READ_TIMEOUT
                )
            except (TimeoutError, OSError):
                logger.warning(
                    "dropping CONNECT %s:%d from %s: timed out waiting for ClientHello",
                    host,
                    port,
                    peername,
                )
                return
            if not chunk:
                logger.warning(
                    "dropping CONNECT %s:%d from %s: closed before ClientHello completed",
                    host,
                    port,
                    peername,
                )
                return
            buffer.extend(chunk)
            result = parse_client_hello(bytes(buffer))
            if result.outcome is not SniOutcome.INCOMPLETE:
                break

        if result.outcome is SniOutcome.MALFORMED:
            logger.warning(
                "dropping CONNECT %s:%d from %s: malformed ClientHello", host, port, peername
            )
            return

        sni = result.sni
        prebuffered = bytes(buffer)
        in_scope = self._capture_all or (sni is not None and self._scope_matcher.match(sni).matched)

        logger.debug(
            "CONNECT %s:%d from %s: sni=%s in_scope=%s", host, port, peername, sni, in_scope
        )

        if in_scope:
            domain_label = sni if sni is not None else host
            if domain_label not in self._logged_domains:
                self._logged_domains.add(domain_label)
                logger.info("first-sight scope match: %s", domain_label)
            await self._on_in_scope(reader, writer, domain_label, port, prebuffered)
            return

        try:
            await blind_relay(
                reader, writer, host, port, self._connect_remote, prebuffered=prebuffered
            )
        except (OSError, UpstreamConnectionError) as exc:
            logger.error("upstream/destination unreachable for %s:%d: %s", host, port, exc)


async def _close_quietly(writer: asyncio.StreamWriter) -> None:
    if writer.is_closing():
        return
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


async def _read_request_line(
    reader: asyncio.StreamReader,
) -> tuple[str, str, int, bytes] | None:
    """Read an HTTP request line and (CONNECT-only) parse its host:port target.

    Args:
        reader: The client connection's stream reader.

    Returns:
        (method, host, port, raw) for a CONNECT request, (method, target, 0,
        raw) for any other method — raw is the exact request-line-plus-headers
        bytes consumed, handed to the plain-HTTP handler so it doesn't need
        to re-read what's already been taken off the socket — or None if the
        request couldn't be read (timeout, oversized, connection closed) or
        a CONNECT target didn't parse as host:port.
    """
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _CONNECT_REQUEST_TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, OSError):
        return None

    request_line = raw.split(b"\r\n", 1)[0]
    parts = request_line.split(b" ")
    if len(parts) < 2:
        return None

    method = parts[0].decode("ascii", errors="replace")
    target = parts[1].decode("ascii", errors="replace")

    if method != "CONNECT":
        return method, target, 0, raw

    host, sep, port_str = target.rpartition(":")
    if not sep:
        return None
    try:
        port = int(port_str)
    except ValueError:
        return None
    return method, host, port, raw
