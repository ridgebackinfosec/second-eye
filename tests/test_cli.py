"""Tests for secondeye.cli (SPEC.md §2, §14 Phase 7).

``main()`` calls ``asyncio.run()`` internally for every subcommand (proxy
start blocks in the foreground; every other subcommand is a short-lived
control-socket client), so tests here are plain sync functions — pytest
would otherwise already be running an event loop, and ``asyncio.run()``
cannot be called from inside one. The full ``proxy start`` -> traffic ->
``capture stop`` flow is driven through a real subprocess for exactly that
reason: it's the only way to exercise cli.py's own blocking entry point
end-to-end. Each subprocess/test gets an isolated state directory by
overriding ``HOME`` (``default_state_dir()`` resolves via ``Path.home()``),
never touching the real operator's ``~/.local/state/secondeye``.
"""

import asyncio
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from secondeye import cli


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(cli, "default_state_dir", lambda: home / ".local" / "state" / "secondeye")
    return home


class TestArgumentParsing:
    def test_capture_start_requires_name(self) -> None:
        with pytest.raises(SystemExit):
            cli.main(["capture", "start"])

    def test_ca_import_upstream_requires_from_burp(self) -> None:
        with pytest.raises(SystemExit):
            cli.main(["ca", "import-upstream"])

    def test_unknown_noun_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit):
            cli.main(["bogus"])


class TestCaExport:
    def test_pem_export_writes_valid_certificate_to_stdout(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(["ca", "export", "--format", "pem"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "BEGIN CERTIFICATE" in captured.out

    def test_second_export_reuses_existing_ca(self, capsys: pytest.CaptureFixture[str]) -> None:
        cli.main(["ca", "export", "--format", "pem"])
        first = capsys.readouterr().out
        cli.main(["ca", "export", "--format", "pem"])
        second = capsys.readouterr().out
        assert first == second


class TestCommandsWithoutRunningDaemon:
    def test_capture_start_reports_no_daemon(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["capture", "start", "--name", "x"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "no running secondeye daemon found" in captured.err
        assert "secondeye proxy start" in captured.err

    def test_capture_stop_reports_no_daemon(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["capture", "stop"])
        assert exit_code == 1
        assert "no running secondeye daemon found" in capsys.readouterr().err

    def test_proxy_status_reports_not_running_without_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(["proxy", "status"])
        assert exit_code == 0
        assert "Daemon running: no" in capsys.readouterr().out

    def test_proxy_stop_reports_no_daemon(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["proxy", "stop"])
        assert exit_code == 1
        assert "no running secondeye daemon found" in capsys.readouterr().err.lower()


class TestHostPortParsing:
    def test_plain_host_colon_port(self) -> None:
        assert cli._parse_host_port("127.0.0.1:9000", 1234) == ("127.0.0.1", 9000)

    def test_missing_port_uses_default(self) -> None:
        assert cli._parse_host_port("127.0.0.1", 1234) == ("127.0.0.1", 1234)

    def test_bracketed_ipv6_with_port(self) -> None:
        assert cli._parse_host_port("[::1]:9000", 1234) == ("::1", 9000)

    def test_bracketed_ipv6_without_port_uses_default(self) -> None:
        assert cli._parse_host_port("[::1]", 1234) == ("::1", 1234)


def _spawn_daemon_subprocess(
    home: Path, *extra_args: str, expect_start: bool = True
) -> subprocess.Popen[str]:
    env = {**os.environ, "HOME": str(home)}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "secondeye.cli",
            "proxy",
            "start",
            "--no-upstream",
            "--listen-address",
            f"127.0.0.1:{_free_port()}",
            *extra_args,
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if not expect_start:
        return proc
    socket_path = home / ".local" / "state" / "secondeye" / "control.sock"
    for _ in range(100):
        if socket_path.exists():
            break
        assert proc.poll() is None, proc.stderr.read() if proc.stderr else ""
        time.sleep(0.05)
    else:
        pytest.fail("daemon did not create control socket in time")
    return proc


def _stop_daemon_subprocess(proc: subprocess.Popen[str], home: Path) -> None:
    env = {**os.environ, "HOME": str(home)}
    subprocess.run(
        [sys.executable, "-m", "secondeye.cli", "proxy", "stop"],
        env=env,
        capture_output=True,
        timeout=10,
    )
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _read_lines_with_timeout(
    proc: subprocess.Popen[str], num_lines: int, timeout: float = 5.0
) -> list[str]:
    # A plain blocking readline() loop, fed by a background thread into a
    # queue: mixing select() with a buffered TextIOWrapper is a classic trap
    # here — the first readline() can slurp an entire flushed burst into the
    # wrapper's internal buffer, so a later select() on the raw fd reports
    # "not ready" even though more already-buffered lines are available
    # without blocking.
    assert proc.stdout is not None
    stdout = proc.stdout
    q: queue.Queue[str | None] = queue.Queue()

    def reader() -> None:
        for line in iter(stdout.readline, ""):
            q.put(line)
        q.put(None)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    lines: list[str] = []
    while len(lines) < num_lines:
        try:
            line = q.get(timeout=timeout)
        except queue.Empty:
            pytest.fail(f"timed out waiting for output; got so far: {lines!r}")
        if line is None:
            pytest.fail(f"daemon process closed stdout unexpectedly; got so far: {lines!r}")
        lines.append(line)
    return lines


class TestStartupBanner:
    def test_banner_printed_immediately_with_scope_and_next_step(
        self, tmp_path: Path, _isolated_home: Path
    ) -> None:
        proc = _spawn_daemon_subprocess(_isolated_home, "--target", "example.com")
        try:
            text = "".join(_read_lines_with_timeout(proc, num_lines=6))
            assert "secondeye started" in text
            assert "Listening:" in text
            assert "Scope:" in text
            assert "example.com" in text
            assert "Upstream:" in text
            assert "none (--no-upstream)" in text
            assert "secondeye capture start" in text
        finally:
            _stop_daemon_subprocess(proc, _isolated_home)

    def test_banner_not_suppressed_by_quiet_flag(
        self, tmp_path: Path, _isolated_home: Path
    ) -> None:
        proc = _spawn_daemon_subprocess(_isolated_home, "--target", "example.com", "-q")
        try:
            text = "".join(_read_lines_with_timeout(proc, num_lines=6))
            assert "secondeye started" in text
        finally:
            _stop_daemon_subprocess(proc, _isolated_home)


class TestTargetFile:
    def test_target_file_merges_into_scope_alongside_target_flag(
        self, tmp_path: Path, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target_file = tmp_path / "targets.txt"
        target_file.write_text("file-a.example\nfile-b.example\n", encoding="utf-8")

        proc = _spawn_daemon_subprocess(
            _isolated_home, "--target", "extra.example", "-tf", str(target_file)
        )
        try:
            code, out, _err = _run_cli(capsys, "proxy", "status")
            assert code == 0
            assert "extra.example" in out
            assert "file-a.example" in out
            assert "file-b.example" in out
        finally:
            _stop_daemon_subprocess(proc, _isolated_home)

    def test_target_file_skips_comments_and_blank_lines(
        self, tmp_path: Path, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target_file = tmp_path / "targets.txt"
        target_file.write_text(
            "# a comment\n\n   \nfile-only.example\n# trailing comment\n", encoding="utf-8"
        )

        proc = _spawn_daemon_subprocess(_isolated_home, "-tf", str(target_file))
        try:
            code, out, _err = _run_cli(capsys, "proxy", "status")
            assert code == 0
            assert "file-only.example" in out
            assert "comment" not in out
        finally:
            _stop_daemon_subprocess(proc, _isolated_home)

    def test_multiple_target_files_combine_in_order(
        self, tmp_path: Path, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        first_file = tmp_path / "first.txt"
        first_file.write_text("first.example\n", encoding="utf-8")
        second_file = tmp_path / "second.txt"
        second_file.write_text("second.example\n", encoding="utf-8")

        proc = _spawn_daemon_subprocess(
            _isolated_home, "-tf", str(first_file), "-tf", str(second_file)
        )
        try:
            code, out, _err = _run_cli(capsys, "proxy", "status")
            assert code == 0
            assert "first.example" in out
            assert "second.example" in out
        finally:
            _stop_daemon_subprocess(proc, _isolated_home)

    def test_target_file_alone_satisfies_scope_requirement_without_target_flag(
        self, tmp_path: Path, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target_file = tmp_path / "targets.txt"
        target_file.write_text("only-from-file.example\n", encoding="utf-8")

        proc = _spawn_daemon_subprocess(_isolated_home, "-tf", str(target_file))
        try:
            code, out, _err = _run_cli(capsys, "proxy", "status")
            assert code == 0
            assert "Daemon running: yes" in out
            assert "only-from-file.example" in out
        finally:
            _stop_daemon_subprocess(proc, _isolated_home)

    def test_missing_target_file_exits_nonzero_with_clear_message(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist.txt"
        exit_code = cli.main(
            [
                "proxy",
                "start",
                "--no-upstream",
                "-tf",
                str(missing),
            ]
        )
        assert exit_code == 1

    def test_missing_target_file_message_names_the_path(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = tmp_path / "does-not-exist.txt"
        cli.main(["proxy", "start", "--no-upstream", "-tf", str(missing)])
        err = capsys.readouterr().err
        assert str(missing) in err

    def test_empty_target_file_with_no_other_scope_still_raises_config_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("# only comments\n\n", encoding="utf-8")

        exit_code = cli.main(
            [
                "proxy",
                "start",
                "--no-upstream",
                "-tf",
                str(empty_file),
            ]
        )
        assert exit_code == 1
        assert "at least one" in capsys.readouterr().err


class TestByteFormatting:
    def test_small_values_in_bytes(self) -> None:
        assert cli._format_bytes(500) == "500B"

    def test_kilobyte_values(self) -> None:
        assert cli._format_bytes(4300) == "4.2KB"

    def test_megabyte_values(self) -> None:
        assert cli._format_bytes(4_400_000) == "4.2MB"


class TestColorHelpers:
    def test_green_wraps_in_ansi_when_color_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        assert cli._green("✓") == "\033[32m✓\033[0m"

    def test_red_wraps_in_ansi_when_color_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        assert cli._red("✗") == "\033[31m✗\033[0m"

    def test_red_no_color_when_stderr_not_a_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: False)
        assert cli._red("✗") == "✗"

    def test_no_color_when_not_a_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
        assert cli._green("✓") == "✓"

    def test_no_color_when_no_color_env_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        monkeypatch.setenv("NO_COLOR", "1")
        assert cli._green("✓") == "✓"

    def test_no_color_when_term_is_dumb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")
        assert cli._green("✓") == "✓"


@pytest.fixture
def running_daemon(_isolated_home: Path) -> object:
    """A real, lightweight --no-upstream daemon subprocess for testing
    capture-lifecycle CLI commands and their exact §2 output formats,
    without needing real HTTP traffic through it.

    The daemon itself must be a subprocess (its ``run()`` blocks in the
    foreground) but the commands tests run *against* it call ``cli.main()``
    directly in-process (see ``_run_cli`` below) — both resolve the same
    isolated control socket, since ``_isolated_home`` monkeypatches
    ``cli.default_state_dir`` in this process while the subprocess gets the
    same location via an overridden ``HOME``.
    """
    home = _isolated_home
    env = {**os.environ, "HOME": str(home)}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "secondeye.cli",
            "proxy",
            "start",
            "--target",
            "example.com",
            "--no-upstream",
            "--listen-address",
            f"127.0.0.1:{_free_port()}",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    socket_path = home / ".local" / "state" / "secondeye" / "control.sock"
    for _ in range(100):
        if socket_path.exists():
            break
        assert proc.poll() is None, proc.stderr.read() if proc.stderr else ""
        time.sleep(0.05)
    else:
        pytest.fail("daemon did not create control socket in time")

    yield

    cli.main(["proxy", "stop"])
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _run_cli(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    exit_code = cli.main(list(args))
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


@pytest.mark.usefixtures("running_daemon")
class TestColoredOutput:
    def test_capture_start_success_glyph_colored_when_tty(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        _code, out, _err = _run_cli(capsys, "capture", "start", "--name", "colored")
        assert "\033[32m✓\033[0m Capture started: colored" in out

    def test_capture_start_success_glyph_plain_when_not_tty(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
        _code, out, _err = _run_cli(capsys, "capture", "start", "--name", "plain")
        assert "✓ Capture started: plain" in out
        assert "\033[" not in out

    def test_daemon_running_yes_colored_green(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        _code, out, _err = _run_cli(capsys, "proxy", "status")
        assert f"Daemon running: {cli._green('yes')}" in out

    def test_generic_error_glyph_colored_red(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # running_daemon is already up; a second `proxy start` hits the
        # second-instance guard's ConfigError, which main()'s generic
        # top-level handler prints via the plain "✗ {exc}" path (distinct
        # from capture start/stop's own command-specific error formatting).
        monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
        _code, _out, err = _run_cli(
            capsys, "proxy", "start", "--target", "other.example", "--no-upstream"
        )
        assert "\033[31m✗\033[0m" in err


@pytest.mark.usefixtures("running_daemon")
class TestCaptureLifecycleOutputFormats:
    def test_capture_already_active_error_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _out, _err = _run_cli(capsys, "capture", "start", "--name", "first")
        assert code == 0

        code, _out, err = _run_cli(capsys, "capture", "start", "--name", "second")
        assert code == 1
        assert "a capture is already active ('first', started" in err
        assert "Run 'secondeye capture stop' first." in err

    def test_capture_name_conflict_error_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        _run_cli(capsys, "capture", "start", "--name", "dup")
        _run_cli(capsys, "capture", "stop")

        code, _out, err = _run_cli(capsys, "capture", "start", "--name", "dup")
        assert code == 1
        assert "a capture named 'dup' already exists for today" in err
        assert "Pick a different name or remove" in err

    def test_capture_stop_without_active_error_format(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _out, err = _run_cli(capsys, "capture", "stop")
        assert code == 1
        assert "Cannot stop capture:" in err

    def test_capture_stop_success_format_with_zero_traffic(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _run_cli(capsys, "capture", "start", "--name", "empty-run")
        code, out, _err = _run_cli(capsys, "capture", "stop")
        assert code == 0
        assert "✓ Capture stopped: empty-run (0 requests, 0B)" in out

    def test_capture_list_reports_multiple_completed_captures(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _run_cli(capsys, "capture", "start", "--name", "first")
        _run_cli(capsys, "capture", "stop")
        _run_cli(capsys, "capture", "start", "--name", "second")
        _run_cli(capsys, "capture", "stop")

        code, out, _err = _run_cli(capsys, "capture", "list")
        assert code == 0
        assert "first" in out
        assert "second" in out

    def test_capture_list_empty_before_any_completed(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _err = _run_cli(capsys, "capture", "list")
        assert code == 0
        assert "No captures recorded yet this run." in out

    def test_proxy_status_reports_active_capture(self, capsys: pytest.CaptureFixture[str]) -> None:
        _run_cli(capsys, "capture", "start", "--name", "active-one")
        code, out, _err = _run_cli(capsys, "proxy", "status")
        assert code == 0
        assert "Active capture: active-one (started" in out
        assert "Upstream:       none (--no-upstream)" in out

    def test_proxy_stop_success_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _err = _run_cli(capsys, "proxy", "stop")
        assert code == 0
        assert "✓ secondeye daemon stopping." in out


class TestCaImportUpstream:
    def test_fetches_and_converts_upstream_ca_to_pem(self, tmp_path: Path) -> None:
        from secondeye.tls.ca import load_or_create_ca

        fake_ca = load_or_create_ca(tmp_path / "fake-burp-ca")
        der_bytes = fake_ca.certificate.public_bytes(serialization.Encoding.DER)
        http_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\n"
            b"Content-Length: " + str(len(der_bytes)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n" + der_bytes
        )

        server_port = _free_port()
        server_loop = asyncio.new_event_loop()
        ready = threading.Event()
        server_holder: list[asyncio.Server] = []

        def serve() -> None:
            asyncio.set_event_loop(server_loop)

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(http_response)
                await writer.drain()
                writer.close()

            async def main_inner() -> None:
                server = await asyncio.start_server(handle, "127.0.0.1", server_port)
                server_holder.append(server)
                ready.set()
                async with server:
                    await server.serve_forever()

            try:
                server_loop.run_until_complete(main_inner())
            except asyncio.CancelledError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            assert ready.wait(timeout=5)
            output_path = tmp_path / "imported-ca.pem"

            exit_code = cli.main(
                [
                    "ca",
                    "import-upstream",
                    "--from-burp",
                    "--upstream-proxy",
                    f"127.0.0.1:{server_port}",
                    "--output",
                    str(output_path),
                ]
            )
            assert exit_code == 0
            assert output_path.exists()
            assert b"BEGIN CERTIFICATE" in output_path.read_bytes()
        finally:
            if server_holder:
                server_loop.call_soon_threadsafe(server_holder[0].close)
            thread.join(timeout=5)

    def test_unreachable_upstream_exits_nonzero(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(
            [
                "ca",
                "import-upstream",
                "--from-burp",
                "--upstream-proxy",
                "127.0.0.1:1",  # nothing listens on port 1
            ]
        )
        assert exit_code == 1
        assert "✗" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl binary not available")
class TestEndToEndSubprocessDaemon:
    def test_full_operator_workflow_through_the_real_cli(
        self, tmp_path: Path, _isolated_home: Path
    ) -> None:
        # Subprocesses can't see this test's monkeypatch, so isolate them
        # via HOME instead (default_state_dir() resolves via Path.home()) —
        # reuse the same directory the autouse fixture already created.
        home = _isolated_home
        env = {**os.environ, "HOME": str(home)}

        # --no-upstream's direct-connect leg does full system trust store
        # validation with no override (SPEC.md §5.1) — a self-signed test
        # cert for a fake "upstream.example" domain would never validate,
        # and a real system-CA-trusted cert isn't something a repeatable
        # offline test can produce. So this test instead drives the
        # --upstream-proxy/--upstream-insecure path: the "destination" below
        # speaks the CONNECT protocol and upgrades to TLS server-side with
        # a self-signed cert, exactly like a real intercepting proxy (Burp)
        # would — --upstream-insecure is the explicitly-supported way to
        # skip validating that leg's cert.
        response_body = b"hello from destination"
        http_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(response_body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + response_body
        )

        from secondeye.tls.ca import load_or_create_ca
        from secondeye.tls.leaf import LeafCertificateStore

        ca = load_or_create_ca(tmp_path / "test-ca")
        leaf_store = LeafCertificateStore(ca)
        upstream_tls_context = leaf_store.get_context("upstream.example")

        # The test itself is a sync function (main() needs to own the event
        # loop for each of its own asyncio.run() calls), so the fake
        # upstream/destination server runs on a dedicated background
        # thread with its own loop.
        upstream_port = _free_port()
        dest_loop = asyncio.new_event_loop()
        dest_ready = threading.Event()
        server_holder: list[asyncio.Server] = []

        def serve_forever() -> None:
            asyncio.set_event_loop(dest_loop)

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                await reader.readuntil(b"\r\n\r\n")  # the CONNECT request
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await writer.start_tls(upstream_tls_context)
                await reader.read(65536)
                writer.write(http_response)
                await writer.drain()
                writer.close()

            async def main_inner() -> None:
                server = await asyncio.start_server(handle, "127.0.0.1", upstream_port)
                server_holder.append(server)
                dest_ready.set()
                async with server:
                    await server.serve_forever()

            try:
                dest_loop.run_until_complete(main_inner())
            except asyncio.CancelledError:
                pass

        thread = threading.Thread(target=serve_forever, daemon=True)
        thread.start()
        assert dest_ready.wait(timeout=5)

        proxy_port = _free_port()
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "secondeye.cli",
                "proxy",
                "start",
                "--target",
                "localhost",
                "--upstream-proxy",
                f"127.0.0.1:{upstream_port}",
                "--upstream-insecure",
                "--listen-address",
                f"127.0.0.1:{proxy_port}",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            socket_path = home / ".local" / "state" / "secondeye" / "control.sock"
            for _ in range(100):
                if socket_path.exists():
                    break
                assert proc.poll() is None, proc.stderr.read() if proc.stderr else ""
                time.sleep(0.05)
            else:
                pytest.fail("daemon did not create control socket in time")

            status_result = subprocess.run(
                [sys.executable, "-m", "secondeye.cli", "proxy", "status"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert status_result.returncode == 0
            assert "Daemon running: yes" in status_result.stdout
            assert "localhost" in status_result.stdout

            start_result = subprocess.run(
                [sys.executable, "-m", "secondeye.cli", "capture", "start", "--name", "e2e"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert start_result.returncode == 0, start_result.stderr
            assert "✓ Capture started: e2e" in start_result.stdout
            assert "Output dir:" in start_result.stdout
            assert "Scope:       localhost" in start_result.stdout

            curl_result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-k",
                    "-x",
                    f"127.0.0.1:{proxy_port}",
                    # This port never needs to be a real listening service —
                    # the daemon routes everything through the fake upstream
                    # above via CONNECT, which ignores the requested target
                    # port entirely (just like a real Burp/ZAP would decide
                    # routing itself).
                    "https://localhost:8443/",
                ],
                capture_output=True,
                timeout=10,
            )
            assert curl_result.returncode == 0
            assert curl_result.stdout == response_body

            stop_result = subprocess.run(
                [sys.executable, "-m", "secondeye.cli", "capture", "stop"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert stop_result.returncode == 0, stop_result.stderr
            assert "✓ Capture stopped: e2e (1 requests," in stop_result.stdout

            list_result = subprocess.run(
                [sys.executable, "-m", "secondeye.cli", "capture", "list"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert "e2e" in list_result.stdout

            duplicate_result = subprocess.run(
                [sys.executable, "-m", "secondeye.cli", "capture", "start", "--name", "e2e"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert duplicate_result.returncode == 1
            assert "already exists" in duplicate_result.stderr
        finally:
            subprocess.run(
                [sys.executable, "-m", "secondeye.cli", "proxy", "stop"],
                env=env,
                capture_output=True,
                timeout=10,
            )
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            if server_holder:
                dest_loop.call_soon_threadsafe(server_holder[0].close)
            thread.join(timeout=5)
