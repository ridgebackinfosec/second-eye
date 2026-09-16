"""Tests for secondeye.proxy.intercept (SPEC.md §4.1, §4.6, §4.9, §5.2, §5.3, §14 Phase 5).

These tests drive InterceptHandler with a *real* client TLS connection
(Python's ssl module, standing in for a browser) against a real upstream
destination server, over real loopback sockets — no mocked crypto. The
buffer-and-replay constraint (SPEC.md §4.2) is reproduced exactly as
listener.py does it: a raw asyncio server reads a few bytes of the
ClientHello itself before handing off to InterceptHandler with the
already-consumed bytes passed in as ``prebuffered``.
"""

import asyncio
import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from secondeye.capture.har import HarEntry
from secondeye.exceptions import CertGenerationError
from secondeye.proxy.intercept import InterceptHandler
from secondeye.proxy.upstream import UpstreamConnector
from secondeye.tls.ca import load_or_create_ca
from secondeye.tls.leaf import LeafCertificateStore

_CURL_MISSING = shutil.which("curl") is None


async def _start_plaintext_http_destination(
    responses: list[bytes] | None = None,
) -> tuple[asyncio.Server, int, list[bytes]]:
    """A minimal HTTP/1.1 server standing in for the real destination.

    Records raw request bytes it receives and replies with each entry of
    `responses` in turn (repeating the last one), so tests can verify what
    InterceptHandler actually forwarded.
    """
    received: list[bytes] = []
    responses = responses or [
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
    ]
    # InterceptHandler opens a fresh upstream connection per request cycle
    # (no upstream-side connection pooling), so each accepted connection
    # here serves exactly one request/response — the response index
    # advances across connections, not within one.
    next_response_index = [0]

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(65536)
        if not data:
            writer.close()
            return
        received.append(data)
        index = min(next_response_index[0], len(responses) - 1)
        next_response_index[0] += 1
        writer.write(responses[index])
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, received


async def _start_intercepting_listener(
    handler: InterceptHandler, sni_hint: str
) -> tuple[asyncio.Server, int]:
    """A minimal stand-in for proxy/listener.py's CONNECT+SNI-peek dance.

    Reads a small prefix of the client's TLS bytes (reproducing the
    buffer-and-replay split), then hands off to InterceptHandler exactly
    as the real listener would for an in-scope connection.
    """

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        prebuffered = await reader.read(5)  # just the TLS record header, like a tiny SNI peek
        # port is irrelevant to the handler's own logic except as what it
        # passes to the upstream connector.
        await handler(reader, writer, sni_hint, 8443, prebuffered)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _client_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class TestEndToEndRequestResponseAndHar:
    async def test_client_gets_response_leaf_cert_and_har_entry_matches(
        self, tmp_path: Path
    ) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination(
            [
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 15\r\n"
                b"\r\n"
                b'{"token":"abc"}'
            ]
        )

        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_tls(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_tls = fake_connect_tls  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = InterceptHandler(
            leaf_store=leaf_store,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "api.example.com"
        )

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
            client_ctx = _client_ssl_context()
            await writer.start_tls(client_ctx, server_hostname="api.example.com")

            leaf_cert_bin = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            assert leaf_cert_bin is not None

            request = (
                b"POST /api/v1/auth/login HTTP/1.1\r\n"
                b"Host: api.example.com\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 15\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b'{"a":"b","c":1}'
            )
            writer.write(request)
            await writer.drain()

            response = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                if not chunk:
                    break
                response += chunk
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            intercept_server.close()
            await intercept_server.wait_closed()

        assert b'{"token":"abc"}' in response
        assert b"200" in response.split(b"\r\n", 1)[0]

        assert len(received) == 1
        assert received[0].startswith(b"POST /api/v1/auth/login HTTP/1.1")
        assert b'{"a":"b","c":1}' in received[0]

        assert len(recorded) == 1
        entry = recorded[0]
        assert entry.request.method == "POST"
        assert entry.request.url == "https://api.example.com/api/v1/auth/login"
        assert entry.request.body == b'{"a":"b","c":1}'
        assert entry.response.status == 200
        assert entry.response.body == b'{"token":"abc"}'


class TestKeepAliveMultipleRequests:
    async def test_multiple_requests_over_one_tls_connection_all_recorded(
        self, tmp_path: Path
    ) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination(
            [
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none",
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo",
            ]
        )
        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_tls(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_tls = fake_connect_tls  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "keepalive.example.com"
        )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
            await writer.start_tls(_client_ssl_context(), server_hostname="keepalive.example.com")

            for _ in range(2):
                writer.write(b"GET /page HTTP/1.1\r\nHost: keepalive.example.com\r\n\r\n")
                await writer.drain()

            responses = b""
            while len(responses) < len(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 200 OK\r\n"
                b"Content-Length: 3\r\n\r\ntwo"
            ):
                chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                if not chunk:
                    break
                responses += chunk
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            intercept_server.close()
            await intercept_server.wait_closed()

        assert b"one" in responses
        assert b"two" in responses
        assert len(recorded) == 2


class TestTlsHandshakeFailure:
    async def test_garbage_after_prebuffered_bytes_fails_handshake_without_crashing(
        self, tmp_path: Path
    ) -> None:
        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def on_entry_recorded(entry: HarEntry) -> None:
            raise AssertionError("should never record")

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "bad-handshake.example.com"
        )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
            writer.write(b"not a real TLS ClientHello continuation at all, just garbage")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b""
            writer.close()
        finally:
            intercept_server.close()
            await intercept_server.wait_closed()


class TestUpstreamFailures:
    async def test_upstream_unreachable_returns_502_without_crashing(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def on_entry_recorded(entry: HarEntry) -> None:
            raise AssertionError("should never record")

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "unreachable.example.com"
        )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
            await writer.start_tls(_client_ssl_context(), server_hostname="unreachable.example.com")
            writer.write(b"GET / HTTP/1.1\r\nHost: unreachable.example.com\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            intercept_server.close()
            await intercept_server.wait_closed()

        assert response.startswith(b"HTTP/1.1 502")

    async def test_upstream_sends_malformed_response_returns_502(self, tmp_path: Path) -> None:
        async def handle_dest(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(65536)
            writer.write(b"NOT EVEN CLOSE TO A VALID HTTP RESPONSE\r\n\r\n")
            await writer.drain()
            writer.close()

        dest_server = await asyncio.start_server(handle_dest, "127.0.0.1", 0)
        dest_port = dest_server.sockets[0].getsockname()[1]

        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_tls(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_tls = fake_connect_tls  # type: ignore[method-assign]

        async def on_entry_recorded(entry: HarEntry) -> None:
            raise AssertionError("should never record")

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "malformed-response.example.com"
        )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
            await writer.start_tls(
                _client_ssl_context(), server_hostname="malformed-response.example.com"
            )
            writer.write(b"GET / HTTP/1.1\r\nHost: malformed-response.example.com\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            intercept_server.close()
            await intercept_server.wait_closed()

        assert response.startswith(b"HTTP/1.1 502")


class TestCertGenerationFailure:
    async def test_cert_generation_failure_drops_connection_without_crashing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)

        def _boom(sni: str) -> ssl.SSLContext:
            raise CertGenerationError(f"simulated failure for {sni}")

        monkeypatch.setattr(leaf_store, "get_context", _boom)

        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def on_entry_recorded(entry: HarEntry) -> None:
            raise AssertionError("should never record anything")

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "broken-cert.example.com"
        )
        try:
            with caplog.at_level(logging.ERROR, logger="secondeye.proxy.intercept"):
                reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
                writer.write(b"anything")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=5)
                assert data == b""
                writer.close()

            assert any("cert" in r.message.lower() for r in caplog.records)
        finally:
            intercept_server.close()
            await intercept_server.wait_closed()


class TestWebSocketUpgradePassthrough:
    async def test_101_response_recorded_then_raw_frames_passed_through_unrecorded(
        self, tmp_path: Path
    ) -> None:
        # SPEC.md §0: WebSocket frames on in-scope domains are passed
        # through but not recorded/analyzed. The upgrade handshake itself
        # is a normal HTTP request/response and is recorded; what comes
        # after is not.
        ws_frame_from_server = b"\x81\x05hello"  # a real (unparsed) WS text frame
        ws_frame_from_client = b"\x81\x85\x00\x00\x00\x00world"  # masked WS frame

        received: list[bytes] = []

        async def handle_dest(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            handshake = await reader.read(65536)
            received.append(handshake)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"\r\n"
            )
            await writer.drain()
            writer.write(ws_frame_from_server)
            await writer.drain()
            frame = await reader.read(65536)
            received.append(frame)
            writer.close()

        dest_server = await asyncio.start_server(handle_dest, "127.0.0.1", 0)
        dest_port = dest_server.sockets[0].getsockname()[1]

        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_tls(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_tls = fake_connect_tls  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )
        intercept_server, intercept_port = await _start_intercepting_listener(
            handler, "ws.example.com"
        )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", intercept_port)
            await writer.start_tls(_client_ssl_context(), server_hostname="ws.example.com")

            writer.write(
                b"GET /socket HTTP/1.1\r\n"
                b"Host: ws.example.com\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n"
                b"\r\n"
            )
            await writer.drain()

            # The 101 response and the first WS frame may arrive in the
            # same TCP read (TCP is a byte stream, not message-framed), so
            # accumulate until both expected parts are in hand rather than
            # assuming they land in separate read() calls.
            expected_prefix = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n\r\n"
            )
            buffer = b""
            while len(buffer) < len(expected_prefix) + len(ws_frame_from_server):
                chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                assert chunk, "connection closed before upgrade response + frame arrived"
                buffer += chunk
            assert buffer.startswith(expected_prefix)
            frame_from_server = buffer[len(expected_prefix) :]
            assert frame_from_server == ws_frame_from_server

            writer.write(ws_frame_from_client)
            await writer.drain()

            for _ in range(50):
                if len(received) >= 2:
                    break
                await asyncio.sleep(0.02)
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            intercept_server.close()
            await intercept_server.wait_closed()

        # The upgrade handshake itself was recorded as a normal HAR entry...
        assert len(recorded) == 1
        assert recorded[0].response.status == 101
        # ...but the raw frame that came after was not touched/parsed.
        assert received[1] == ws_frame_from_client


class TestConnectToNonStandardPort:
    @pytest.mark.skipif(_CURL_MISSING, reason="curl binary not available")
    async def test_real_curl_through_proxy_style_flow_to_non_443_port(self, tmp_path: Path) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination(
            [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]
        )
        assert dest_port != 443

        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        seen_ports: list[int] = []

        async def fake_connect_tls(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            seen_ports.append(port)
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_tls = fake_connect_tls  # type: ignore[method-assign]

        async def on_entry_recorded(entry: HarEntry) -> None:
            pass

        handler = InterceptHandler(
            leaf_store=leaf_store, upstream_connector=connector, on_entry_recorded=on_entry_recorded
        )

        # This time the "listener" honors a non-443 CONNECT target port,
        # exactly like the real proxy/listener.py does (SPEC.md §4.5).
        non_standard_port = 8443

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            prebuffered = await reader.read(5)
            await handler(reader, writer, "nonstandard.example.com", non_standard_port, prebuffered)

        intercept_server = await asyncio.start_server(handle, "127.0.0.1", 0)
        intercept_port = intercept_server.sockets[0].getsockname()[1]

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "curl",
                    "-s",
                    "-k",
                    "--resolve",
                    f"nonstandard.example.com:{intercept_port}:127.0.0.1",
                    f"https://nonstandard.example.com:{intercept_port}/",
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            intercept_server.close()
            await intercept_server.wait_closed()

        assert result.returncode == 0, result.stderr
        assert result.stdout == b"ok"
        assert seen_ports == [non_standard_port]
