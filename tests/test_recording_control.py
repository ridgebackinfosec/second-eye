"""Tests for secondeye.recording.control (SPEC.md §6.4, §14 Phase 6)."""

import logging
from pathlib import Path

import pytest

from secondeye.exceptions import ConfigError
from secondeye.recording.control import (
    ControlServer,
    ControlSocketUnavailableError,
    build_capture_handlers,
    send_request,
)
from secondeye.recording.manager import CaptureManager


def _manager(tmp_path: Path) -> CaptureManager:
    return CaptureManager(
        state_dir=tmp_path,
        target_label="example-com",
        targets=["example.com"],
        target_regex=None,
        target_all=False,
        upstream="127.0.0.1:8080",
        no_upstream=False,
    )


class TestSendRequestNoDaemon:
    async def test_missing_socket_raises_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(ControlSocketUnavailableError):
            await send_request(tmp_path / "control.sock", "capture.list")


class TestCaptureLifecycleOverSocket:
    async def test_start_stop_list_round_trip(self, tmp_path: Path) -> None:
        socket_path = tmp_path / "control.sock"
        server = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await server.start()
        try:
            start_response = await send_request(
                socket_path, "capture.start", {"name": "auth-flow-test"}
            )
            assert start_response["ok"] is True
            result = start_response["result"]
            assert isinstance(result, dict)
            assert result["name"] == "auth-flow-test"
            assert "started_at" in result
            assert "output_dir" in result

            scope = result["scope"]
            assert isinstance(scope, dict)
            assert scope["targets"] == ["example.com"]

            stop_response = await send_request(socket_path, "capture.stop")
            assert stop_response["ok"] is True
            stop_result = stop_response["result"]
            assert isinstance(stop_result, dict)
            assert stop_result["name"] == "auth-flow-test"
            assert stop_result["request_count"] == 0

            list_response = await send_request(socket_path, "capture.list")
            assert list_response["ok"] is True
            captures = list_response["result"]
            assert isinstance(captures, list)
            assert len(captures) == 1
            assert captures[0]["name"] == "auth-flow-test"
        finally:
            await server.stop()

    async def test_second_start_while_active_returns_structured_error(self, tmp_path: Path) -> None:
        socket_path = tmp_path / "control.sock"
        server = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await server.start()
        try:
            await send_request(socket_path, "capture.start", {"name": "first"})
            response = await send_request(socket_path, "capture.start", {"name": "second"})
            assert response["ok"] is False
            error = response["error"]
            assert isinstance(error, dict)
            assert error["type"] == "CaptureAlreadyActiveError"
            assert error["name"] == "first"
            assert "started_at" in error
        finally:
            await server.stop()

    async def test_stop_without_active_capture_returns_structured_error(
        self, tmp_path: Path
    ) -> None:
        socket_path = tmp_path / "control.sock"
        server = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await server.start()
        try:
            response = await send_request(socket_path, "capture.stop")
            assert response["ok"] is False
            error = response["error"]
            assert isinstance(error, dict)
            assert error["type"] == "NoActiveCaptureError"
        finally:
            await server.stop()

    async def test_duplicate_name_returns_structured_error_with_output_dir(
        self, tmp_path: Path
    ) -> None:
        socket_path = tmp_path / "control.sock"
        server = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await server.start()
        try:
            await send_request(socket_path, "capture.start", {"name": "dup"})
            await send_request(socket_path, "capture.stop")
            response = await send_request(socket_path, "capture.start", {"name": "dup"})
            assert response["ok"] is False
            error = response["error"]
            assert isinstance(error, dict)
            assert error["type"] == "CaptureNameConflictError"
            assert "output_dir" in error
        finally:
            await server.stop()


class TestSecondInstanceGuard:
    async def test_second_server_on_live_socket_raises_config_error(self, tmp_path: Path) -> None:
        socket_path = tmp_path / "control.sock"
        first = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await first.start()
        try:
            second = ControlServer(
                socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
            )
            with pytest.raises(ConfigError):
                await second.start()

            # The first server must be untouched and still fully functional.
            response = await send_request(socket_path, "capture.list")
            assert response["ok"] is True
        finally:
            await first.stop()

    async def test_stale_socket_file_does_not_block_a_fresh_start(self, tmp_path: Path) -> None:
        socket_path = tmp_path / "control.sock"
        stale = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await stale.start()
        # Simulate an unclean shutdown: the listening socket goes away but
        # the socket file is left behind on disk (stale.stop() is never
        # called, so it never unlinks it).
        assert stale._server is not None
        stale._server.close()
        await stale._server.wait_closed()

        fresh = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await fresh.start()
        try:
            response = await send_request(socket_path, "capture.list")
            assert response["ok"] is True
        finally:
            await fresh.stop()


class TestHandlerMerging:
    async def test_handlers_from_independent_sources_can_be_merged(self, tmp_path: Path) -> None:
        # This is the pattern daemon.py (a later phase) relies on: its own
        # proxy.status/proxy.stop handlers merged alongside
        # build_capture_handlers()'s, in one dict, on one socket.
        socket_path = tmp_path / "control.sock"

        async def ping(_params: dict[str, object]) -> dict[str, object]:
            return {"ok": True, "result": "pong"}

        merged = {**build_capture_handlers(_manager(tmp_path)), "diagnostic.ping": ping}
        server = ControlServer(socket_path=socket_path, handlers=merged)
        await server.start()
        try:
            ping_response = await send_request(socket_path, "diagnostic.ping")
            assert ping_response == {"ok": True, "result": "pong"}

            capture_response = await send_request(socket_path, "capture.list")
            assert capture_response["ok"] is True
        finally:
            await server.stop()


class TestUnhandledExceptionSurvival:
    async def test_unhandled_exception_in_handler_is_logged_without_crashing(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        socket_path = tmp_path / "control.sock"

        async def exploding_handler(_params: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("boom: simulated bug in a control handler")

        handlers = {
            **build_capture_handlers(_manager(tmp_path)),
            "diagnostic.explode": exploding_handler,
        }
        server = ControlServer(socket_path=socket_path, handlers=handlers)
        await server.start()
        try:
            with caplog.at_level(logging.ERROR, logger="secondeye.recording.control"):
                with pytest.raises(ControlSocketUnavailableError):
                    await send_request(socket_path, "diagnostic.explode")

            assert any("unhandled exception" in r.message for r in caplog.records)

            # The server itself must still be alive and answering.
            response = await send_request(socket_path, "capture.list")
            assert response["ok"] is True
        finally:
            await server.stop()


class TestProtocolRobustness:
    async def test_unknown_command_does_not_crash_server(self, tmp_path: Path) -> None:
        socket_path = tmp_path / "control.sock"
        server = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await server.start()
        try:
            response = await send_request(socket_path, "bogus.command")
            assert response["ok"] is False

            # Server must still be alive and serving further requests.
            follow_up = await send_request(socket_path, "capture.list")
            assert follow_up["ok"] is True
        finally:
            await server.stop()

    async def test_malformed_json_does_not_crash_server(self, tmp_path: Path) -> None:
        import asyncio

        socket_path = tmp_path / "control.sock"
        server = ControlServer(
            socket_path=socket_path, handlers=build_capture_handlers(_manager(tmp_path))
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_unix_connection(path=str(socket_path))
            writer.write(b"not json at all\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            assert line  # got some response, didn't just hang/close
            writer.close()

            follow_up = await send_request(socket_path, "capture.list")
            assert follow_up["ok"] is True
        finally:
            await server.stop()
