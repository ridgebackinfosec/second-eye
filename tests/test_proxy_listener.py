"""Tests for secondeye.proxy.listener (SPEC.md §4.1, §4.5, §4.7, §4.8, §14 Phase 4).

The out-of-scope end-to-end test uses a real curl subprocess through a real
asyncio listener to a real local TLS destination server, per the literal
acceptance criteria text in SPEC.md §14 Phase 4: "real client (curl -x)
through the proxy to an out-of-scope HTTPS domain succeeds with zero
decryption, confirmed by no leaf cert generated for that SNI during the
run." "No leaf cert generated" is verified by asserting the in-scope
handler (the only code path in this phase that could reach cert
generation, since proxy/intercept.py doesn't exist until Phase 5) is never
invoked for that connection.
"""

import asyncio
import logging
import shutil
import subprocess
from pathlib import Path

import pytest

from secondeye.exceptions import ConfigError
from secondeye.proxy import listener as listener_module
from secondeye.proxy.listener import ProxyListener, _read_request_line, ensure_loopback
from secondeye.scope.matcher import ScopeMatcher
from secondeye.tls.ca import load_or_create_ca
from secondeye.tls.leaf import LeafCertificateStore

_FIXTURES = Path(__file__).parent / "fixtures"
_OPENSSL_MISSING = shutil.which("openssl") is None
_CURL_MISSING = shutil.which("curl") is None


def _load_fixture(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


class TestEnsureLoopback:
    @pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
    def test_accepts_loopback_addresses(self, host: str) -> None:
        ensure_loopback(host)  # must not raise

    @pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::", "10.0.0.1"])
    def test_rejects_non_loopback_ip_literals(self, host: str) -> None:
        with pytest.raises(ConfigError):
            ensure_loopback(host)

    def test_rejects_non_ip_literal(self) -> None:
        with pytest.raises(ConfigError):
            ensure_loopback("example.com")


class TestBoundPortBeforeStart:
    def test_raises_runtime_error_if_not_started(self) -> None:
        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        with pytest.raises(RuntimeError):
            _ = listener.bound_port


class TestReadRequestLineEdgeCases:
    async def test_request_line_with_fewer_than_two_parts_is_none(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"JUSTONEWORD\r\n\r\n")
        reader.feed_eof()
        assert await _read_request_line(reader) is None

    async def test_connect_target_without_colon_is_none(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"CONNECT nohostport HTTP/1.1\r\n\r\n")
        reader.feed_eof()
        assert await _read_request_line(reader) is None

    async def test_connect_target_with_non_numeric_port_is_none(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"CONNECT example.com:notaport HTTP/1.1\r\n\r\n")
        reader.feed_eof()
        assert await _read_request_line(reader) is None


class TestProxyListenerConstruction:
    async def test_constructor_validates_loopback_before_binding(self) -> None:
        with pytest.raises(ConfigError):
            ProxyListener(
                listen_host="0.0.0.0",
                listen_port=0,
                scope_matcher=ScopeMatcher(),
                target_all=False,
                max_connections=10,
                connect_remote=_unused_connector,
                on_in_scope=_unused_handler,
                on_plain_http=_unused_plain_http_handler,
            )


class TestSecondInstanceGuard:
    async def test_second_listener_on_same_port_raises_config_error(self) -> None:
        first = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await first.start()
        try:
            second = ProxyListener(
                listen_host="127.0.0.1",
                listen_port=first.bound_port,
                scope_matcher=ScopeMatcher(),
                target_all=False,
                max_connections=10,
                connect_remote=_unused_connector,
                on_in_scope=_unused_handler,
                on_plain_http=_unused_plain_http_handler,
            )
            with pytest.raises(ConfigError):
                await second.start()
        finally:
            await first.stop()


async def _unused_connector(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    raise AssertionError("connect_remote should not have been called")


async def _unused_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    sni: str,
    port: int,
    prebuffered: bytes,
) -> None:
    raise AssertionError("on_in_scope should not have been called")


async def _unused_plain_http_handler(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, raw_request: bytes
) -> None:
    raise AssertionError("on_plain_http should not have been called")


async def _open_connect_tunnel(
    proxy_port: int, target_host: str, target_port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n\r\n"
    writer.write(request.encode("ascii"))
    await writer.drain()
    response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    assert response.startswith(b"HTTP/1.1 200")
    return reader, writer


class TestConnectRoutingUnit:
    async def test_in_scope_connection_invokes_handler_with_sni_and_buffer(self) -> None:
        calls: list[tuple[str, int, bytes]] = []

        async def on_in_scope(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            sni: str,
            port: int,
            prebuffered: bytes,
        ) -> None:
            calls.append((sni, port, prebuffered))
            writer.close()

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["sni-test.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=on_in_scope,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            client_hello = _load_fixture("clienthello_curl.bin")
            reader, writer = await _open_connect_tunnel(
                listener.bound_port, "sni-test.example", 8443
            )
            writer.write(client_hello)
            await writer.drain()
            for _ in range(50):
                if calls:
                    break
                await asyncio.sleep(0.02)
            writer.close()
        finally:
            await listener.stop()

        assert calls == [("sni-test.example", 8443, client_hello)]

    async def test_out_of_scope_connection_uses_blind_relay(self) -> None:
        connector_calls: list[tuple[str, int]] = []

        async def fake_connect(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            connector_calls.append((host, port))
            raise ConnectionRefusedError("test double: no real destination")

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["totally-different.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=fake_connect,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            client_hello = _load_fixture("clienthello_curl.bin")
            reader, writer = await _open_connect_tunnel(
                listener.bound_port, "sni-test.example", 8443
            )
            writer.write(client_hello)
            await writer.drain()
            for _ in range(50):
                if connector_calls:
                    break
                await asyncio.sleep(0.02)
            writer.close()
        finally:
            await listener.stop()

        assert connector_calls == [("sni-test.example", 8443)]

    async def test_target_all_routes_no_sni_connection_in_scope_using_connect_host(
        self,
    ) -> None:
        calls: list[tuple[str, int, bytes]] = []

        async def on_in_scope(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            sni: str,
            port: int,
            prebuffered: bytes,
        ) -> None:
            calls.append((sni, port, prebuffered))
            writer.close()

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(),
            target_all=True,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=on_in_scope,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            client_hello = _load_fixture("clienthello_no_sni.bin")
            reader, writer = await _open_connect_tunnel(
                listener.bound_port, "no-sni-target.example", 443
            )
            writer.write(client_hello)
            await writer.drain()
            for _ in range(50):
                if calls:
                    break
                await asyncio.sleep(0.02)
            writer.close()
        finally:
            await listener.stop()

        assert calls == [("no-sni-target.example", 443, client_hello)]

    async def test_no_sni_without_target_all_is_out_of_scope(self) -> None:
        connector_calls: list[tuple[str, int]] = []

        async def fake_connect(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            connector_calls.append((host, port))
            raise ConnectionRefusedError("test double: no real destination")

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["irrelevant.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=fake_connect,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            client_hello = _load_fixture("clienthello_no_sni.bin")
            reader, writer = await _open_connect_tunnel(
                listener.bound_port, "no-sni-target.example", 443
            )
            writer.write(client_hello)
            await writer.drain()
            for _ in range(50):
                if connector_calls:
                    break
                await asyncio.sleep(0.02)
            writer.close()
        finally:
            await listener.stop()

        assert connector_calls == [("no-sni-target.example", 443)]

    async def test_malformed_clienthello_after_connect_drops_connection(self) -> None:
        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["irrelevant.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            reader, writer = await _open_connect_tunnel(
                listener.bound_port, "irrelevant.example", 443
            )
            writer.write(b"NOT A TLS CLIENTHELLO AT ALL, JUST GARBAGE BYTES")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b""
            writer.close()
        finally:
            await listener.stop()

    async def test_non_connect_request_dispatches_to_plain_http_handler(self) -> None:
        calls: list[bytes] = []

        async def on_plain_http(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter, raw_request: bytes
        ) -> None:
            calls.append(raw_request)
            writer.close()

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=_unused_handler,
            on_plain_http=on_plain_http,
        )
        await listener.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.bound_port)
            request = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            writer.write(request)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b""
            writer.close()

            assert calls == [request]

            # The daemon must still be alive and accepting connections.
            reader2, writer2 = await _open_connect_tunnel(
                listener.bound_port, "irrelevant.example", 443
            )
            writer2.close()
        finally:
            await listener.stop()


class TestUnhandledExceptionSurvival:
    async def test_unhandled_exception_in_handler_is_logged_and_daemon_survives(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        async def exploding_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            sni: str,
            port: int,
            prebuffered: bytes,
        ) -> None:
            raise ValueError("boom: simulated bug in the in-scope handler")

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["sni-test.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=exploding_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            client_hello = _load_fixture("clienthello_curl.bin")
            with caplog.at_level(logging.ERROR, logger="secondeye.proxy.listener"):
                reader, writer = await _open_connect_tunnel(
                    listener.bound_port, "sni-test.example", 8443
                )
                writer.write(client_hello)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=5)
                assert data == b""
                writer.close()

            assert any("unhandled exception" in r.message for r in caplog.records)

            # The daemon itself must still be alive and accepting connections.
            reader2, writer2 = await _open_connect_tunnel(
                listener.bound_port, "irrelevant.example", 443
            )
            writer2.close()
        finally:
            await listener.stop()


class TestClientHelloReadTimeout:
    async def test_times_out_and_drops_connection_if_client_hello_never_arrives(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(listener_module, "_CLIENT_HELLO_READ_TIMEOUT", 0.2)

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            with caplog.at_level(logging.WARNING, logger="secondeye.proxy.listener"):
                reader, writer = await _open_connect_tunnel(
                    listener.bound_port, "irrelevant.example", 443
                )
                data = await asyncio.wait_for(reader.read(1024), timeout=5)
                assert data == b""
                writer.close()

            assert any("timed out" in r.message for r in caplog.records)
        finally:
            await listener.stop()


class TestFirstSightScopeLogging:
    async def test_logs_first_sight_scope_match_once_per_domain(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        async def on_in_scope(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            sni: str,
            port: int,
            prebuffered: bytes,
        ) -> None:
            writer.close()

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["sni-test.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=_unused_connector,
            on_in_scope=on_in_scope,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        client_hello = _load_fixture("clienthello_curl.bin")
        try:
            with caplog.at_level(logging.INFO, logger="secondeye.proxy.listener"):
                for _ in range(2):
                    reader, writer = await _open_connect_tunnel(
                        listener.bound_port, "sni-test.example", 8443
                    )
                    writer.write(client_hello)
                    await writer.drain()
                    await asyncio.sleep(0.05)
                    writer.close()
        finally:
            await listener.stop()

        first_sight_records = [r for r in caplog.records if "first-sight" in r.message]
        assert len(first_sight_records) == 1


class TestMaxConnections:
    async def test_rejects_connections_beyond_cap(self, caplog: pytest.LogCaptureFixture) -> None:
        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(),
            target_all=False,
            max_connections=1,
            connect_remote=_unused_connector,
            on_in_scope=_unused_handler,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()
        try:
            _reader1, writer1 = await asyncio.open_connection("127.0.0.1", listener.bound_port)

            for _ in range(50):
                if listener.active_connections >= 1:
                    break
                await asyncio.sleep(0.02)
            assert listener.active_connections == 1

            with caplog.at_level(logging.WARNING, logger="secondeye.proxy.listener"):
                reader2, writer2 = await asyncio.open_connection("127.0.0.1", listener.bound_port)
                data = await asyncio.wait_for(reader2.read(1024), timeout=5)
                assert data == b""
                writer2.close()

            assert any("max-connections" in r.message for r in caplog.records)
            writer1.close()
        finally:
            await listener.stop()


class TestEndToEndOutOfScopeBlindRelayWithRealCurl:
    @pytest.mark.skipif(_CURL_MISSING, reason="curl binary not available")
    @pytest.mark.skipif(_OPENSSL_MISSING, reason="openssl binary not available")
    async def test_curl_through_proxy_to_out_of_scope_domain_gets_zero_decryption(
        self, tmp_path: Path
    ) -> None:
        ca = load_or_create_ca(tmp_path)
        leaf_store = LeafCertificateStore(ca)
        dest_hostname = "out-of-scope.example"
        dest_context = leaf_store.get_context(dest_hostname)

        response_body = b"hello from the real destination"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(response_body)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n" + response_body
        )

        dest_server_ready = asyncio.Event()

        async def handle_dest_client(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(65536)
            writer.write(http_response)
            await writer.drain()
            writer.close()

        dest_server = await asyncio.start_server(
            handle_dest_client, "127.0.0.1", 0, ssl=dest_context
        )
        dest_port = dest_server.sockets[0].getsockname()[1]
        dest_server_ready.set()

        in_scope_calls: list[str] = []

        async def on_in_scope(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            sni: str,
            port: int,
            prebuffered: bytes,
        ) -> None:
            in_scope_calls.append(sni)
            writer.close()

        async def direct_connect(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            # Stands in for the eventual --no-upstream direct connector
            # (proxy/upstream.py, Phase 5); ignores the CONNECT target host
            # so this test doesn't depend on real DNS for a fake domain.
            return await asyncio.open_connection("127.0.0.1", dest_port)

        listener = ProxyListener(
            listen_host="127.0.0.1",
            listen_port=0,
            scope_matcher=ScopeMatcher(targets=["some-other-domain.example"]),
            target_all=False,
            max_connections=10,
            connect_remote=direct_connect,
            on_in_scope=on_in_scope,
            on_plain_http=_unused_plain_http_handler,
        )
        await listener.start()

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "curl",
                    "-s",
                    "-k",
                    "-x",
                    f"127.0.0.1:{listener.bound_port}",
                    f"https://{dest_hostname}:{dest_port}/",
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            await listener.stop()

        assert result.returncode == 0, result.stderr
        assert result.stdout == response_body
        assert in_scope_calls == []
