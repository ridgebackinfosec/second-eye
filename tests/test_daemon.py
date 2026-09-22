"""Tests for secondeye.daemon (SPEC.md §2, §4, §9, §14 Phase 7)."""

import asyncio
import datetime
import logging
import os
import signal
import stat
import subprocess
from pathlib import Path

import pytest

from secondeye.capture.har import HarEntry, HarHeader, HarRequest, HarResponse
from secondeye.daemon import Daemon, DaemonConfig
from secondeye.exceptions import ConfigError
from secondeye.recording.control import send_request


def _entry() -> HarEntry:
    return HarEntry(
        started_at=datetime.datetime.now(datetime.UTC),
        time_ms=1.0,
        request=HarRequest(
            method="GET",
            url="https://example.com/page",
            http_version="1.1",
            headers=(HarHeader("Sec-Fetch-Mode", "navigate"),),
            body=b"",
        ),
        response=HarResponse(
            status=200,
            status_text="OK",
            http_version="1.1",
            headers=(HarHeader("Content-Type", "text/html"),),
            body=b"",
        ),
    )


class TestConfigValidationBeforeBinding:
    def test_non_loopback_listen_host_raises_before_any_socket(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            Daemon(
                DaemonConfig(
                    listen_host="0.0.0.0",
                    listen_port=0,
                    targets=["example.com"],
                    no_upstream=True,
                    state_dir=tmp_path,
                )
            )

    def test_missing_upstream_trust_config_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            Daemon(
                DaemonConfig(
                    targets=["example.com"],
                    no_upstream=False,
                    upstream_ca=None,
                    upstream_insecure=False,
                    state_dir=tmp_path,
                )
            )

    def test_conflicting_upstream_trust_flags_raise(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            Daemon(
                DaemonConfig(
                    targets=["example.com"],
                    no_upstream=False,
                    upstream_ca=tmp_path / "ca.pem",
                    upstream_insecure=True,
                    state_dir=tmp_path,
                )
            )

    def test_valid_no_upstream_config_constructs_cleanly(self, tmp_path: Path) -> None:
        Daemon(
            DaemonConfig(
                listen_port=0, targets=["example.com"], no_upstream=True, state_dir=tmp_path
            )
        )

    def test_no_scope_at_all_raises(self, tmp_path: Path) -> None:
        # SPEC.md §2 marks --target "required (at least one)".
        with pytest.raises(ConfigError):
            Daemon(
                DaemonConfig(
                    listen_port=0,
                    targets=[],
                    target_regex=[],
                    target_all=False,
                    no_upstream=True,
                    state_dir=tmp_path,
                )
            )

    def test_target_regex_alone_satisfies_the_requirement(self, tmp_path: Path) -> None:
        Daemon(
            DaemonConfig(
                listen_port=0,
                targets=[],
                target_regex=[r"^dev-.*\.example\.com$"],
                no_upstream=True,
                state_dir=tmp_path,
            )
        )

    def test_target_all_alone_satisfies_the_requirement(self, tmp_path: Path) -> None:
        Daemon(
            DaemonConfig(
                listen_port=0,
                targets=[],
                target_regex=[],
                target_all=True,
                no_upstream=True,
                state_dir=tmp_path,
            )
        )


async def _wait_until_started(daemon: Daemon, wait_seconds: float = 2.0) -> None:
    async def poll() -> None:
        while True:
            try:
                _ = daemon.listener_bound_port
            except RuntimeError:
                await asyncio.sleep(0.02)
            else:
                return

    await asyncio.wait_for(poll(), timeout=wait_seconds)


def _daemon(tmp_path: Path, **overrides: object) -> Daemon:
    base: dict[str, object] = {
        "listen_port": 0,
        "targets": ["example.com"],
        "no_upstream": True,
        "state_dir": tmp_path,
    }
    base.update(overrides)
    return Daemon(DaemonConfig(**base))  # type: ignore[arg-type]


class TestStateDirectoryPermissions:
    def test_state_dir_locked_via_daemon_construction(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        Daemon(
            DaemonConfig(
                listen_port=0, targets=["example.com"], no_upstream=True, state_dir=state_dir
            )
        )
        assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700

    def test_ca_warning_fires_and_state_dir_still_locked_through_daemon(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        state_dir = tmp_path / "state"
        # First daemon construction creates a full CA.
        Daemon(
            DaemonConfig(
                listen_port=0, targets=["example.com"], no_upstream=True, state_dir=state_dir
            )
        )
        (state_dir / "ca" / "secondeye-ca.key").unlink()  # simulate partial corruption

        with caplog.at_level(logging.WARNING, logger="secondeye.tls.ca"):
            Daemon(
                DaemonConfig(
                    listen_port=0, targets=["example.com"], no_upstream=True, state_dir=state_dir
                )
            )

        assert any("regenerat" in r.message.lower() for r in caplog.records)
        assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700


class TestStartupAndControlSocket:
    async def test_start_binds_listener_and_control_socket(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        await daemon.start()
        try:
            assert daemon.listener_bound_port != 0
            assert (tmp_path / "control.sock").exists()
        finally:
            await daemon.shutdown()

    async def test_proxy_status_reports_scope_and_no_active_capture(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        await daemon.start()
        try:
            response = await send_request(tmp_path / "control.sock", "proxy.status")
            assert response["ok"] is True
            result = response["result"]
            assert isinstance(result, dict)
            assert result["active_capture"] is None
            scope = result["scope"]
            assert isinstance(scope, dict)
            assert scope["targets"] == ["example.com"]
        finally:
            await daemon.shutdown()

    async def test_proxy_status_reports_active_capture(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        await daemon.start()
        try:
            await send_request(tmp_path / "control.sock", "capture.start", {"name": "t1"})
            response = await send_request(tmp_path / "control.sock", "proxy.status")
            result = response["result"]
            assert isinstance(result, dict)
            active = result["active_capture"]
            assert isinstance(active, dict)
            assert active["name"] == "t1"
            assert active["request_count"] == 0
        finally:
            await daemon.shutdown()

    async def test_proxy_status_request_count_reflects_recorded_entries(
        self, tmp_path: Path
    ) -> None:
        daemon = _daemon(tmp_path)
        await daemon.start()
        try:
            await send_request(tmp_path / "control.sock", "capture.start", {"name": "t2"})
            await daemon._capture_manager.record_entry(_entry())
            await daemon._capture_manager.record_entry(_entry())

            response = await send_request(tmp_path / "control.sock", "proxy.status")
            result = response["result"]
            assert isinstance(result, dict)
            active = result["active_capture"]
            assert isinstance(active, dict)
            assert active["request_count"] == 2
        finally:
            await daemon.shutdown()

    async def test_proxy_stop_over_socket_triggers_shutdown_event(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        await daemon.start()
        response = await send_request(tmp_path / "control.sock", "proxy.stop")
        assert response["ok"] is True
        await asyncio.wait_for(daemon.wait_for_shutdown(), timeout=5)
        await daemon.shutdown()


class TestCaWasCreated:
    def test_true_on_first_construction(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        assert daemon.ca_was_created is True

    def test_false_when_ca_already_exists(self, tmp_path: Path) -> None:
        _daemon(tmp_path)  # first construction generates the CA
        second = _daemon(tmp_path)
        assert second.ca_was_created is False


class TestSecondInstanceGuard:
    async def test_second_daemon_on_same_state_dir_raises_and_first_stays_up(
        self, tmp_path: Path
    ) -> None:
        first = _daemon(tmp_path)
        await first.start()
        try:
            second = _daemon(tmp_path)
            with pytest.raises(ConfigError):
                await second.start()

            response = await send_request(tmp_path / "control.sock", "proxy.status")
            assert response["ok"] is True
        finally:
            await first.shutdown()


class TestShutdownFlushesActiveCapture:
    async def test_shutdown_flushes_capture_and_writes_output(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        await daemon.start()
        start_response = await send_request(
            tmp_path / "control.sock", "capture.start", {"name": "interrupted"}
        )
        assert start_response["ok"] is True
        output_dir = Path(start_response["result"]["output_dir"])  # type: ignore[index]

        await daemon.shutdown()

        assert (output_dir / "raw.har").exists()
        assert (output_dir / "manifest.json").exists()
        assert (output_dir / "ANALYSIS.md").exists()


class TestOnStartedHook:
    async def test_on_started_fires_once_after_bind_succeeds(self, tmp_path: Path) -> None:
        calls: list[None] = []
        daemon = _daemon(tmp_path)
        run_task = asyncio.create_task(daemon.run(on_started=lambda: calls.append(None)))
        try:
            await _wait_until_started(daemon)
            assert calls == [None]
        finally:
            daemon.request_shutdown()
            await asyncio.wait_for(run_task, timeout=5)


class TestSignalHandling:
    async def test_sigint_sets_shutdown_event(self, tmp_path: Path) -> None:
        daemon = _daemon(tmp_path)
        run_task = asyncio.create_task(daemon.run())
        try:
            await _wait_until_started(daemon)

            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.wait_for(run_task, timeout=5)
        finally:
            if not run_task.done():
                run_task.cancel()

    async def test_sigint_during_active_capture_flushes_complete_output(
        self, tmp_path: Path
    ) -> None:
        daemon = _daemon(tmp_path)
        run_task = asyncio.create_task(daemon.run())
        try:
            await _wait_until_started(daemon)

            start_response = await send_request(
                tmp_path / "control.sock", "capture.start", {"name": "sig-test"}
            )
            output_dir = Path(start_response["result"]["output_dir"])  # type: ignore[index]

            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.wait_for(run_task, timeout=5)

            assert (output_dir / "raw.har").exists()
            assert (output_dir / "manifest.json").exists()
            assert (output_dir / "ANALYSIS.md").exists()
        finally:
            if not run_task.done():
                run_task.cancel()

    async def test_second_sigint_forces_immediate_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exit_calls: list[int] = []
        monkeypatch.setattr(os, "_exit", lambda code: exit_calls.append(code))

        daemon = _daemon(tmp_path)
        await daemon.start()
        daemon.install_signal_handlers()

        daemon._handle_signal()  # first "signal": begins shutdown
        assert exit_calls == []
        daemon._handle_signal()  # second "signal": forces exit
        assert exit_calls == [1]

        await daemon.shutdown()


class TestEndToEndCurlThroughDaemon:
    async def test_real_curl_capture_start_traffic_capture_stop(self, tmp_path: Path) -> None:
        if not _has_curl():
            pytest.skip("curl binary not available")

        response_body = b"hello from destination"
        http_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(response_body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + response_body
        )

        async def handle_dest(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(65536)
            writer.write(http_response)
            await writer.drain()
            writer.close()

        dest_server = await asyncio.start_server(handle_dest, "127.0.0.1", 0)
        dest_port = dest_server.sockets[0].getsockname()[1]

        daemon = _daemon(tmp_path, targets=["target.example"])
        await daemon.start()

        # target.example is in scope, so intercept.py's InterceptHandler
        # holds the connector object and calls connect_tls() per-request
        # (not a bound-method snapshot) — reroute it to our local fake
        # destination instead of doing real DNS for a fake domain.
        async def fake_connect_tls(
            host: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", dest_port)

        daemon._upstream_connector.connect_tls = fake_connect_tls  # type: ignore[method-assign]

        try:
            start_response = await send_request(
                tmp_path / "control.sock", "capture.start", {"name": "e2e"}
            )
            assert start_response["ok"] is True

            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "curl",
                    "-s",
                    "-k",
                    "-x",
                    f"127.0.0.1:{daemon.listener_bound_port}",
                    f"https://target.example:{dest_port}/",
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout == response_body

            stop_response = await send_request(tmp_path / "control.sock", "capture.stop")
            assert stop_response["ok"] is True
            stop_result = stop_response["result"]
            assert isinstance(stop_result, dict)
            assert stop_result["request_count"] == 1

            output_dir = Path(stop_result["output_dir"])
            manifest_text = (output_dir / "manifest.json").read_text(encoding="utf-8")
            assert "target.example" in manifest_text
            analysis_text = (output_dir / "ANALYSIS.md").read_text(encoding="utf-8")
            assert "e2e" in analysis_text
        finally:
            dest_server.close()
            await dest_server.wait_closed()
            await daemon.shutdown()


def _has_curl() -> bool:
    import shutil

    return shutil.which("curl") is not None
