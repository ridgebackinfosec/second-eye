"""Tests for secondeye.proxy.splice (SPEC.md §4.1, §4.2, §14 Phase 4)."""

import asyncio
import socket

import pytest

from secondeye.proxy.splice import blind_relay, splice


async def _stream_pair(
    sock: socket.socket,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(sock=sock)


class TestSplice:
    async def test_relays_bytes_in_both_directions(self) -> None:
        sock_a1, sock_a2 = socket.socketpair()
        sock_b1, sock_b2 = socket.socketpair()

        reader_a, writer_a = await _stream_pair(sock_a1)
        reader_b, writer_b = await _stream_pair(sock_b1)
        test_reader_a, test_writer_a = await _stream_pair(sock_a2)
        test_reader_b, test_writer_b = await _stream_pair(sock_b2)

        task = asyncio.create_task(splice(reader_a, writer_a, reader_b, writer_b))
        try:
            test_writer_a.write(b"hello from client")
            await test_writer_a.drain()
            assert await test_reader_b.read(64) == b"hello from client"

            test_writer_b.write(b"hello from remote")
            await test_writer_b.drain()
            assert await test_reader_a.read(64) == b"hello from remote"
        finally:
            test_writer_a.close()
            test_writer_b.close()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    async def test_returns_promptly_when_remote_side_closes(self) -> None:
        sock_a1, sock_a2 = socket.socketpair()
        sock_b1, sock_b2 = socket.socketpair()

        reader_a, writer_a = await _stream_pair(sock_a1)
        reader_b, writer_b = await _stream_pair(sock_b1)
        test_reader_a, test_writer_a = await _stream_pair(sock_a2)
        _test_reader_b, test_writer_b = await _stream_pair(sock_b2)

        task = asyncio.create_task(splice(reader_a, writer_a, reader_b, writer_b))

        test_writer_b.close()
        await test_writer_b.wait_closed()

        await asyncio.wait_for(task, timeout=2)

        # The client-facing writer must have been closed too, so the "real"
        # client observes EOF rather than hanging forever.
        assert await test_reader_a.read(64) == b""

        test_writer_a.close()

    async def test_returns_promptly_when_client_side_closes(self) -> None:
        sock_a1, sock_a2 = socket.socketpair()
        sock_b1, sock_b2 = socket.socketpair()

        reader_a, writer_a = await _stream_pair(sock_a1)
        reader_b, writer_b = await _stream_pair(sock_b1)
        test_writer_a = (await _stream_pair(sock_a2))[1]
        test_reader_b = (await _stream_pair(sock_b2))[0]

        task = asyncio.create_task(splice(reader_a, writer_a, reader_b, writer_b))

        test_writer_a.close()
        await test_writer_a.wait_closed()

        await asyncio.wait_for(task, timeout=2)
        assert await test_reader_b.read(64) == b""

        test_writer_a.close()


class TestBlindRelay:
    async def test_replays_prebuffered_bytes_before_duplex_relay(self) -> None:
        sock_remote_1, sock_remote_2 = socket.socketpair()
        test_reader_remote, test_writer_remote = await _stream_pair(sock_remote_2)

        async def fake_connect(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            assert (host, port) == ("example.com", 8443)
            return await _stream_pair(sock_remote_1)

        sock_client_1, sock_client_2 = socket.socketpair()
        client_reader, client_writer = await _stream_pair(sock_client_1)
        test_reader_client, test_writer_client = await _stream_pair(sock_client_2)

        task = asyncio.create_task(
            blind_relay(
                client_reader,
                client_writer,
                "example.com",
                8443,
                fake_connect,
                prebuffered=b"PREBUFFERED-CLIENTHELLO",
            )
        )
        try:
            assert await test_reader_remote.read(64) == b"PREBUFFERED-CLIENTHELLO"

            test_writer_client.write(b"more from client")
            await test_writer_client.drain()
            assert await test_reader_remote.read(64) == b"more from client"

            test_writer_remote.write(b"reply from destination")
            await test_writer_remote.drain()
            assert await test_reader_client.read(64) == b"reply from destination"
        finally:
            test_writer_client.close()
            test_writer_remote.close()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    async def test_no_prebuffered_bytes_skips_replay(self) -> None:
        sock_remote_1, sock_remote_2 = socket.socketpair()
        test_reader_remote, test_writer_remote = await _stream_pair(sock_remote_2)

        async def fake_connect(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await _stream_pair(sock_remote_1)

        sock_client_1, sock_client_2 = socket.socketpair()
        client_reader, client_writer = await _stream_pair(sock_client_1)
        test_writer_client = (await _stream_pair(sock_client_2))[1]

        task = asyncio.create_task(
            blind_relay(client_reader, client_writer, "example.com", 443, fake_connect)
        )
        try:
            test_writer_client.write(b"only real traffic")
            await test_writer_client.drain()
            assert await test_reader_remote.read(64) == b"only real traffic"
        finally:
            test_writer_client.close()
            test_writer_remote.close()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
