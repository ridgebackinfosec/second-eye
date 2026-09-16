"""Tests for secondeye.proxy.upstream (SPEC.md §2, §4.1, §5.1, §14 Phase 5)."""

import asyncio
import ssl
from pathlib import Path

import pytest

from secondeye.exceptions import ConfigError, UpstreamConnectionError
from secondeye.proxy.upstream import UpstreamConnector, validate_upstream_config
from secondeye.tls.ca import load_or_create_ca
from secondeye.tls.leaf import LeafCertificateStore


class TestValidateUpstreamConfig:
    def test_both_ca_and_insecure_set_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            validate_upstream_config(
                upstream_ca=tmp_path / "ca.pem", upstream_insecure=True, no_upstream=False
            )

    def test_neither_set_and_not_no_upstream_raises(self) -> None:
        with pytest.raises(ConfigError):
            validate_upstream_config(upstream_ca=None, upstream_insecure=False, no_upstream=False)

    def test_ca_only_is_valid(self, tmp_path: Path) -> None:
        validate_upstream_config(
            upstream_ca=tmp_path / "ca.pem", upstream_insecure=False, no_upstream=False
        )

    def test_insecure_only_is_valid(self) -> None:
        validate_upstream_config(upstream_ca=None, upstream_insecure=True, no_upstream=False)

    def test_no_upstream_allows_neither(self) -> None:
        validate_upstream_config(upstream_ca=None, upstream_insecure=False, no_upstream=True)


class TestUpstreamConnectorConstruction:
    def test_missing_upstream_host_when_not_no_upstream_raises(self) -> None:
        with pytest.raises(ConfigError):
            UpstreamConnector(
                upstream_host=None,
                upstream_port=None,
                no_upstream=False,
                upstream_insecure=True,
            )

    def test_no_upstream_mode_does_not_require_host(self) -> None:
        UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)


async def _echo_server() -> tuple[asyncio.Server, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(1024)
        writer.write(b"ECHO:" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _fake_upstream_server(
    accept_status: bytes = b"HTTP/1.1 200 Connection Established\r\n\r\n",
    tls_context: ssl.SSLContext | None = None,
) -> tuple[asyncio.Server, int]:
    """A minimal CONNECT-speaking test double standing in for Burp/ZAP.

    Accepts a CONNECT request, replies with accept_status, and then either
    echoes plain bytes (tls_context=None) or upgrades to TLS server-side
    and echoes decrypted bytes (tls_context set) — simulating Burp either
    passing a tunnel through raw or MITM-intercepting it.
    """

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(accept_status)
        await writer.drain()
        if not accept_status.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
            writer.close()
            return
        if tls_context is not None:
            await writer.start_tls(tls_context)
        data = await reader.read(1024)
        writer.write(b"ECHO:" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class TestConnectPlainHttp:
    async def test_direct_mode_connects_straight_to_destination(self) -> None:
        dest_server, dest_port = await _echo_server()
        try:
            connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)
            assert connector.no_upstream is True
            reader, writer = await connector.connect_plain_http("127.0.0.1", dest_port)
            writer.write(b"hi")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b"ECHO:hi"
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()

    async def test_upstream_mode_connects_to_upstream_not_destination_with_no_connect_handshake(
        self,
    ) -> None:
        # Plain HTTP proxying never issues a CONNECT — the absolute-URI
        # request line itself tells the upstream where to route it, so the
        # connector just hands back a plain connection to the upstream
        # proxy's own address.
        upstream_server, upstream_port = await _echo_server()
        try:
            connector = UpstreamConnector(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                no_upstream=False,
                upstream_insecure=True,
            )
            assert connector.no_upstream is False
            reader, writer = await connector.connect_plain_http("dest.example", 80)
            writer.write(b"GET http://dest.example/page HTTP/1.1\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data.startswith(b"ECHO:GET http://dest.example/page")
            writer.close()
        finally:
            upstream_server.close()
            await upstream_server.wait_closed()


class TestConnectRawDirectMode:
    async def test_connects_directly_to_destination(self) -> None:
        dest_server, dest_port = await _echo_server()
        try:
            connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)
            reader, writer = await connector.connect_raw("127.0.0.1", dest_port)
            writer.write(b"hi")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b"ECHO:hi"
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()

    async def test_unreachable_destination_raises_upstream_connection_error(self) -> None:
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)
        with pytest.raises(UpstreamConnectionError):
            await connector.connect_raw("127.0.0.1", 1)  # port 1: nothing listens


class TestConnectRawUpstreamTunnelMode:
    async def test_tunnels_through_upstream_via_connect(self) -> None:
        fake_upstream, upstream_port = await _fake_upstream_server()
        try:
            connector = UpstreamConnector(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                no_upstream=False,
                upstream_insecure=True,
            )
            reader, writer = await connector.connect_raw("dest.example", 8443)
            writer.write(b"through-the-tunnel")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b"ECHO:through-the-tunnel"
            writer.close()
        finally:
            fake_upstream.close()
            await fake_upstream.wait_closed()

    async def test_upstream_refusing_connect_raises(self) -> None:
        fake_upstream, upstream_port = await _fake_upstream_server(
            accept_status=b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
        )
        try:
            connector = UpstreamConnector(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                no_upstream=False,
                upstream_insecure=True,
            )
            with pytest.raises(UpstreamConnectionError):
                await connector.connect_raw("dest.example", 8443)
        finally:
            fake_upstream.close()
            await fake_upstream.wait_closed()

    async def test_unreachable_upstream_raises(self) -> None:
        connector = UpstreamConnector(
            upstream_host="127.0.0.1", upstream_port=1, no_upstream=False, upstream_insecure=True
        )
        with pytest.raises(UpstreamConnectionError):
            await connector.connect_raw("dest.example", 8443)


class TestConnectTlsDirectModeFullTrustValidation:
    async def test_untrusted_self_signed_destination_fails_validation(self, tmp_path: Path) -> None:
        # Proves --no-upstream really does full system trust store
        # validation (SPEC.md §5.1: "no override flag exists for this leg")
        # rather than silently accepting our own self-signed test CA.
        ca = load_or_create_ca(tmp_path)
        store = LeafCertificateStore(ca)
        dest_ctx = store.get_context("untrusted-dest.example")

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        dest_server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=dest_ctx)
        dest_port = dest_server.sockets[0].getsockname()[1]
        try:
            connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)
            with pytest.raises(UpstreamConnectionError):
                await connector.connect_tls("untrusted-dest.example", dest_port)
        finally:
            dest_server.close()
            await dest_server.wait_closed()


class TestConnectTlsUpstreamTunnelMode:
    async def test_upstream_ca_trusts_matching_ca(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        store = LeafCertificateStore(ca)
        tls_ctx = store.get_context("dest.example")
        fake_upstream, upstream_port = await _fake_upstream_server(tls_context=tls_ctx)
        try:
            connector = UpstreamConnector(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                no_upstream=False,
                upstream_ca=ca.cert_path,
            )
            reader, writer = await connector.connect_tls("dest.example", 8443)
            writer.write(b"secure-hello")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b"ECHO:secure-hello"
            writer.close()
        finally:
            fake_upstream.close()
            await fake_upstream.wait_closed()

    async def test_upstream_ca_rejects_wrong_ca(self, tmp_path: Path) -> None:
        real_ca_dir = tmp_path / "real"
        wrong_ca_dir = tmp_path / "wrong"
        real_ca = load_or_create_ca(real_ca_dir)
        wrong_ca = load_or_create_ca(wrong_ca_dir)
        store = LeafCertificateStore(real_ca)
        tls_ctx = store.get_context("dest.example")
        fake_upstream, upstream_port = await _fake_upstream_server(tls_context=tls_ctx)
        try:
            connector = UpstreamConnector(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                no_upstream=False,
                upstream_ca=wrong_ca.cert_path,
            )
            with pytest.raises(UpstreamConnectionError):
                await connector.connect_tls("dest.example", 8443)
        finally:
            fake_upstream.close()
            await fake_upstream.wait_closed()

    async def test_upstream_insecure_accepts_any_cert(self, tmp_path: Path) -> None:
        some_ca = load_or_create_ca(tmp_path)
        store = LeafCertificateStore(some_ca)
        tls_ctx = store.get_context("dest.example")
        fake_upstream, upstream_port = await _fake_upstream_server(tls_context=tls_ctx)
        try:
            connector = UpstreamConnector(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                no_upstream=False,
                upstream_insecure=True,
            )
            reader, writer = await connector.connect_tls("dest.example", 8443)
            writer.write(b"insecure-hello")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b"ECHO:insecure-hello"
            writer.close()
        finally:
            fake_upstream.close()
            await fake_upstream.wait_closed()
