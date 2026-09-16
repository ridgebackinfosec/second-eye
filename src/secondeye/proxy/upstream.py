"""Upstream/destination connection establishment and TLS trust logic
(SPEC.md §2, §4.1, §5.1).

Two routing modes, fixed for the daemon's lifetime:
  - Upstream (Burp/ZAP): every outbound connection first tunnels through
    the configured --upstream host:port via an HTTP CONNECT handshake.
  - Direct (--no-upstream): every outbound connection goes straight to the
    real destination, with full system trust store validation on the
    resulting TLS leg — no override flag exists for this leg (SPEC.md §5.1).

Two connection shapes, chosen per-connection by the caller:
  - Raw (connect_raw): no TLS operations at all — used for the out-of-scope
    blind-relay path (proxy/splice.py), matching the "zero cert ops"
    requirement for traffic secondeye never inspects.
  - TLS-wrapped (connect_tls): used for the in-scope path
    (proxy/intercept.py) once it has decrypted and parsed a request and
    needs to re-encrypt and forward it.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path

from secondeye.exceptions import ConfigError, UpstreamConnectionError

__all__ = ["UpstreamConnector", "validate_upstream_config"]

logger = logging.getLogger(__name__)

_CONNECT_RESPONSE_TIMEOUT = 10.0


def validate_upstream_config(
    *, upstream_ca: Path | None, upstream_insecure: bool, no_upstream: bool
) -> None:
    """Validate daemon-startup upstream trust configuration (SPEC.md §2).

    Args:
        upstream_ca: Path to the upstream proxy's CA cert, if provided.
        upstream_insecure: Whether TLS verification on the upstream leg is
            explicitly disabled.
        no_upstream: Whether the daemon is configured to skip the upstream
            proxy and connect directly to destinations.

    Raises:
        ConfigError: If upstream_ca and upstream_insecure are both set
            (ambiguous intent), or if neither is set and no_upstream is
            False (no way to establish trust for the upstream leg).
    """
    if upstream_ca is not None and upstream_insecure:
        raise ConfigError("--upstream-ca and --upstream-insecure are mutually exclusive")
    if not no_upstream and upstream_ca is None and not upstream_insecure:
        raise ConfigError("one of --upstream-ca, --upstream-insecure, or --no-upstream is required")


class UpstreamConnector:
    """Establishes outbound connections honoring --upstream/--no-upstream routing."""

    def __init__(
        self,
        *,
        upstream_host: str | None,
        upstream_port: int | None,
        no_upstream: bool,
        upstream_ca: Path | None = None,
        upstream_insecure: bool = False,
    ) -> None:
        """Validate and store upstream routing/trust configuration.

        Args:
            upstream_host: The upstream proxy's host, required unless
                no_upstream.
            upstream_port: The upstream proxy's port, required unless
                no_upstream.
            no_upstream: Whether to skip the upstream proxy entirely.
            upstream_ca: Path to the upstream proxy's CA cert (PEM).
            upstream_insecure: Whether to skip TLS verification on the
                upstream leg.

        Raises:
            ConfigError: If the trust configuration is invalid (see
                validate_upstream_config), or upstream_host/upstream_port
                are missing while no_upstream is False.
        """
        validate_upstream_config(
            upstream_ca=upstream_ca, upstream_insecure=upstream_insecure, no_upstream=no_upstream
        )
        if not no_upstream and (upstream_host is None or upstream_port is None):
            raise ConfigError("upstream_host and upstream_port are required unless no_upstream")
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._no_upstream = no_upstream
        self._upstream_ca = upstream_ca
        self._upstream_insecure = upstream_insecure

    @property
    def no_upstream(self) -> bool:
        """Whether this connector routes directly, bypassing the upstream proxy."""
        return self._no_upstream

    async def connect_plain_http(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish a connection for the plain-HTTP (absolute-URI) path.

        Unlike connect_raw/connect_tls, this never issues a CONNECT
        handshake: plain HTTP proxying doesn't use one — the client's
        request itself (kept in absolute-URI form when forwarded to an
        upstream proxy, SPEC.md §4.4) is what tells the next hop where to
        route it.

        Args:
            host: The destination host (from the request's absolute-URI).
            port: The destination port.

        Returns:
            A connected (reader, writer) pair: directly to (host, port) if
            no_upstream, otherwise a plain TCP connection to the upstream
            proxy itself (not the destination) for the caller to send an
            absolute-URI-targeted request over.

        Raises:
            UpstreamConnectionError: If the connection could not be
                established.
        """
        if self._no_upstream:
            return await _open_direct(host, port)
        return await _open_direct(self._require_upstream_host(), self._require_upstream_port())

    async def connect_raw(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish a raw (unencrypted) connection for the blind-relay path.

        Args:
            host: The destination host (from the CONNECT target).
            port: The destination port.

        Returns:
            A connected (reader, writer) pair: directly to (host, port) if
            no_upstream, otherwise tunneled through the upstream proxy via
            CONNECT.

        Raises:
            UpstreamConnectionError: If the connection could not be
                established.
        """
        if self._no_upstream:
            return await _open_direct(host, port)
        return await _open_via_upstream_tunnel(
            self._require_upstream_host(), self._require_upstream_port(), host, port
        )

    async def connect_tls(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish a TLS-wrapped connection for the in-scope re-encrypt path.

        Args:
            host: The destination host, used as the outbound SNI.
            port: The destination port.

        Returns:
            A connected, TLS-wrapped (reader, writer) pair: direct to
            (host, port) with full system trust store validation if
            no_upstream (SPEC.md §5.1 — no override exists for this leg);
            otherwise tunneled through the upstream proxy via CONNECT and
            then upgraded to TLS in place, validated per --upstream-ca or
            --upstream-insecure.

        Raises:
            UpstreamConnectionError: If the connection or TLS handshake
                could not be established.
        """
        if self._no_upstream:
            context = ssl.create_default_context()
            return await _open_direct(host, port, tls_context=context, server_hostname=host)

        reader, writer = await _open_via_upstream_tunnel(
            self._require_upstream_host(), self._require_upstream_port(), host, port
        )
        context = _build_upstream_tls_context(self._upstream_ca, self._upstream_insecure)
        try:
            await writer.start_tls(context, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            writer.close()
            raise UpstreamConnectionError(
                f"TLS handshake with upstream tunnel to {host}:{port} failed: {exc}"
            ) from exc
        return reader, writer

    def _require_upstream_host(self) -> str:
        if self._upstream_host is None:
            raise ConfigError("upstream_host is required when no_upstream is False")
        return self._upstream_host

    def _require_upstream_port(self) -> int:
        if self._upstream_port is None:
            raise ConfigError("upstream_port is required when no_upstream is False")
        return self._upstream_port


async def _open_direct(
    host: str,
    port: int,
    *,
    tls_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        return await asyncio.open_connection(
            host, port, ssl=tls_context, server_hostname=server_hostname
        )
    except (OSError, ssl.SSLError) as exc:
        raise UpstreamConnectionError(
            f"failed to connect directly to {host}:{port}: {exc}"
        ) from exc


async def _open_via_upstream_tunnel(
    upstream_host: str, upstream_port: int, dest_host: str, dest_port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        reader, writer = await asyncio.open_connection(upstream_host, upstream_port)
    except OSError as exc:
        raise UpstreamConnectionError(
            f"failed to connect to upstream {upstream_host}:{upstream_port}: {exc}"
        ) from exc

    request = f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\n\r\n"
    writer.write(request.encode("ascii"))
    try:
        await writer.drain()
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _CONNECT_RESPONSE_TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, OSError) as exc:
        writer.close()
        raise UpstreamConnectionError(
            f"upstream {upstream_host}:{upstream_port} did not establish a CONNECT tunnel "
            f"to {dest_host}:{dest_port}: {exc}"
        ) from exc

    status_line = raw.split(b"\r\n", 1)[0]
    if not status_line.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
        writer.close()
        raise UpstreamConnectionError(
            f"upstream {upstream_host}:{upstream_port} refused CONNECT to "
            f"{dest_host}:{dest_port}: {status_line!r}"
        )
    return reader, writer


def _build_upstream_tls_context(
    upstream_ca: Path | None, upstream_insecure: bool
) -> ssl.SSLContext:
    if upstream_insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if upstream_ca is not None:
        return ssl.create_default_context(cafile=str(upstream_ca))
    raise ConfigError("no upstream trust configuration available")  # pragma: no cover
