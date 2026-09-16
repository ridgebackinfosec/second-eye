"""Tests for secondeye.proxy.plain_http (SPEC.md §4.4, §14 Phase 5).

SPEC.md §4.4: plain HTTP (absolute-URI, non-CONNECT) requests are a real,
required code path, handled without any SNI peek or cert generation —
simpler than the HTTPS path, but genuinely different in one respect: since
there's no CONNECT tunnel pinning the connection to one destination, a
single keep-alive plain-HTTP connection to this proxy can carry requests to
different hosts one after another, so the scope decision happens per
request, not once at connection-accept time.
"""

import asyncio

from secondeye.capture.har import HarEntry
from secondeye.proxy.plain_http import PlainHttpHandler
from secondeye.proxy.upstream import UpstreamConnector
from secondeye.scope.matcher import ScopeMatcher


async def _start_plaintext_http_destination(
    responses: list[bytes] | None = None,
) -> tuple[asyncio.Server, int, list[bytes]]:
    received: list[bytes] = []
    responses = responses or [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]
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


async def _open_plain_http_listener(handler: PlainHttpHandler) -> tuple[asyncio.Server, int]:
    """Reproduces listener.py's plain-HTTP dispatch: read the request line
    and headers, then hand those already-consumed bytes to the handler.
    """

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        raw = await reader.readuntil(b"\r\n\r\n")
        await handler(reader, writer, raw)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class TestInScopeRequestRecordedAndForwardedDirect:
    async def test_direct_mode_forwards_origin_form_and_records_entry(self) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination(
            [b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"]
        )
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_plain_http(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_plain_http = fake_connect_plain_http  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(targets=["target.example"]),
            target_all=False,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                b"GET http://target.example/page?x=1 HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Connection: close\r\n\r\n"
            )
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
            server.close()
            await server.wait_closed()

        assert b"hello" in response
        # Direct mode must rewrite to origin-form (just the path), not the
        # absolute-URI the client sent.
        assert received[0].startswith(b"GET /page?x=1 HTTP/1.1")
        assert b"http://" not in received[0].split(b"\r\n", 1)[0]

        assert len(recorded) == 1
        assert recorded[0].request.method == "GET"
        assert recorded[0].request.url == "http://target.example/page?x=1"
        assert recorded[0].response.body == b"hello"


class TestOutOfScopeNotRecordedButStillForwarded:
    async def test_out_of_scope_request_forwarded_but_not_recorded(self) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination()
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_plain_http(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_plain_http = fake_connect_plain_http  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(targets=["some-other-domain.example"]),
            target_all=False,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                b"GET http://out-of-scope.example/ HTTP/1.1\r\n"
                b"Host: out-of-scope.example\r\n"
                b"Connection: close\r\n\r\n"
            )
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
            server.close()
            await server.wait_closed()

        assert b"200" in response.split(b"\r\n", 1)[0]
        assert len(received) == 1  # still forwarded
        assert recorded == []  # but never recorded


class TestTargetAllRecordsRegardlessOfScope:
    async def test_target_all_records_even_without_matching_target(self) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination()
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_plain_http(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_plain_http = fake_connect_plain_http  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(),
            target_all=True,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                b"GET http://anything.example/ HTTP/1.1\r\n"
                b"Host: anything.example\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            server.close()
            await server.wait_closed()

        assert len(recorded) == 1


class TestKeepAliveAcrossDifferentHosts:
    async def test_each_request_scope_checked_independently_on_same_connection(self) -> None:
        dest_server, dest_port, received = await _start_plaintext_http_destination(
            [
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none",
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo",
            ]
        )
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def fake_connect_plain_http(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        connector.connect_plain_http = fake_connect_plain_http  # type: ignore[method-assign]

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(targets=["in-scope.example"]),
            target_all=False,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                b"GET http://in-scope.example/one HTTP/1.1\r\nHost: in-scope.example\r\n\r\n"
            )
            await writer.drain()
            writer.write(
                b"GET http://out-of-scope.example/two HTTP/1.1\r\n"
                b"Host: out-of-scope.example\r\n"
                b"Connection: close\r\n\r\n"
            )
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
            server.close()
            await server.wait_closed()

        assert b"one" in response
        assert b"two" in response
        assert len(received) == 2
        assert len(recorded) == 1
        assert recorded[0].request.url == "http://in-scope.example/one"


class TestMalformedTarget:
    async def test_non_absolute_uri_target_drops_connection_without_crashing(self) -> None:
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def on_entry_recorded(entry: HarEntry) -> None:
            raise AssertionError("should never record")

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(),
            target_all=True,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # Origin-form target (no scheme/host) — not valid for this path
            # (SPEC.md §4.4 describes absolute-URI as the expected shape).
            writer.write(b"GET /just-a-path HTTP/1.1\r\nHost: whatever\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert data == b""
            writer.close()
        finally:
            server.close()
            await server.wait_closed()


class TestUpstreamUnreachable:
    async def test_returns_502_without_crashing(self) -> None:
        connector = UpstreamConnector(upstream_host=None, upstream_port=None, no_upstream=True)

        async def on_entry_recorded(entry: HarEntry) -> None:
            raise AssertionError("should never record")

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(),
            target_all=True,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            server.close()
            await server.wait_closed()

        assert response.startswith(b"HTTP/1.1 502")


class TestUpstreamModePreservesAbsoluteUriTarget:
    async def test_upstream_mode_sends_absolute_uri_to_upstream_not_origin_form(self) -> None:
        upstream_received: list[bytes] = []

        async def handle_upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await reader.read(65536)
            upstream_received.append(data)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        upstream_server = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]

        connector = UpstreamConnector(
            upstream_host="127.0.0.1",
            upstream_port=upstream_port,
            no_upstream=False,
            upstream_insecure=True,
        )

        recorded: list[HarEntry] = []

        async def on_entry_recorded(entry: HarEntry) -> None:
            recorded.append(entry)

        handler = PlainHttpHandler(
            scope_matcher=ScopeMatcher(),
            target_all=True,
            upstream_connector=connector,
            on_entry_recorded=on_entry_recorded,
        )
        server, port = await _open_plain_http_listener(handler)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                b"GET http://dest.example/page HTTP/1.1\r\n"
                b"Host: dest.example\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
        finally:
            upstream_server.close()
            await upstream_server.wait_closed()
            server.close()
            await server.wait_closed()

        assert upstream_received[0].startswith(b"GET http://dest.example/page HTTP/1.1")
