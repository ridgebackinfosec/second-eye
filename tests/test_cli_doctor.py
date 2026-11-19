"""Tests for `secondeye doctor` — answering "will this work?" up front.

A newcomer otherwise finds out piecemeal: the CA isn't trusted (every
in-scope HTTPS request fails), the listen port is taken, Burp isn't
running, `certutil` is missing. doctor collects those into one pass/warn/
fail report before any of them bites.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from secondeye import cli
from secondeye.tls.ca import load_or_create_ca


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point secondeye's state directory at a throwaway location.

    Mirrors the fixture in test_cli.py. Deliberately kept local rather
    than promoted to a conftest.py: there it would be autouse for every
    test module, silently changing the environment of tests that manage
    their own paths.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(cli, "default_state_dir", lambda: home / ".local" / "state" / "secondeye")
    return home


def _state_dir(home: Path) -> Path:
    """The isolated state directory the fixture points secondeye at.

    Deliberately derived from the fixture rather than by calling
    ``secondeye.tls.ca.default_state_dir()``: the fixture patches the
    name on ``cli``, so importing it from ``tls.ca`` bypasses the patch
    and operates on the developer's real ~/.local/state/secondeye.
    """
    return home / ".local" / "state" / "secondeye"


def _run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = cli.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


class TestExitCode:
    def test_clean_environment_exits_zero(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # No CA yet is a warning, not a failure: `proxy start` creates one.
        code, _out, _err = _run(capsys, "doctor", "--no-upstream")
        assert code == 0

    def test_a_failing_check_exits_nonzero(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Occupy the listen port so the port check fails.
        with socket.socket() as taken:
            taken.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            taken.bind(("127.0.0.1", 0))
            taken.listen(1)
            port = taken.getsockname()[1]
            code, _out, _err = _run(
                capsys, "doctor", "--no-upstream", "--listen-address", f"127.0.0.1:{port}"
            )
        assert code == 1

    def test_warnings_alone_do_not_fail(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert code == 0
        assert "WARN" in out or "warn" in out


class TestReportContents:
    def test_reports_the_installed_version(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import secondeye

        _code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert secondeye.__version__ in out

    def test_reports_missing_ca_as_a_warning_not_a_failure(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "CA" in out
        assert code == 0

    def test_reports_an_existing_ca(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_or_create_ca(_state_dir(_isolated_home))
        code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "CA" in out
        assert "days remaining" in out
        assert code == 0

    def test_checks_the_listen_port(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "port" in out.lower()

    def test_checks_the_captures_directory(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "captures" in out.lower()

    def test_mentions_certutil_for_trust_store_installation(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "certutil" in out

    def test_every_check_is_labelled_with_an_outcome(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _code, out, _err = _run(capsys, "doctor", "--no-upstream")
        # Each rendered row carries one of the three markers.
        assert any(marker in out for marker in ("✓", "⚠", "✗"))


class TestUpstreamCheck:
    def test_no_upstream_skips_the_upstream_check(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "--no-upstream" in out

    def test_unreachable_upstream_is_reported_as_a_failure(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]
        code, out, _err = _run(capsys, "doctor", "--upstream-proxy", f"127.0.0.1:{dead_port}")
        assert code == 1
        assert str(dead_port) in out

    def test_reachable_upstream_passes(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with socket.socket() as stub:
            stub.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stub.bind(("127.0.0.1", 0))
            stub.listen(1)
            port = stub.getsockname()[1]
            code, out, _err = _run(
                capsys,
                "doctor",
                "--upstream-proxy",
                f"127.0.0.1:{port}",
                "--upstream-insecure",
            )
        assert code == 0
        assert str(port) in out

    def test_reachable_upstream_without_trust_config_still_fails(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # proxy start requires one of --upstream-ca/--upstream-insecure/
        # --no-upstream, so reporting a reachable upstream as "ready" when
        # none is configured would be misleading.
        with socket.socket() as stub:
            stub.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stub.bind(("127.0.0.1", 0))
            stub.listen(1)
            port = stub.getsockname()[1]
            code, out, _err = _run(capsys, "doctor", "--upstream-proxy", f"127.0.0.1:{port}")
        assert code == 1
        assert "--upstream-ca" in out

    def test_missing_upstream_ca_file_is_a_failure(
        self, _isolated_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with socket.socket() as stub:
            stub.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stub.bind(("127.0.0.1", 0))
            stub.listen(1)
            port = stub.getsockname()[1]
            code, out, _err = _run(
                capsys,
                "doctor",
                "--upstream-proxy",
                f"127.0.0.1:{port}",
                "--upstream-ca",
                str(tmp_path / "absent.pem"),
            )
        assert code == 1
        assert "absent.pem" in out


class TestStateDirectoryPermissions:
    def test_reports_state_directory_mode(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_or_create_ca(_state_dir(_isolated_home))
        code, out, _err = _run(capsys, "doctor", "--no-upstream")
        assert "0700" in out
        assert code == 0

    def test_loose_permissions_are_flagged(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        state_dir = _state_dir(_isolated_home)
        load_or_create_ca(state_dir)
        state_dir.chmod(0o755)
        code, out, _err = _run(capsys, "doctor", "--no-upstream")
        # SECURITY.md documents 0700 as a guarantee; a looser mode means
        # CA private key material is readable by other local users.
        assert code == 1
        assert "0700" in out


class TestCaInstall:
    """`secondeye ca install` — the automatable half of trust-store setup."""

    def test_print_only_shows_manual_steps_without_touching_anything(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_or_create_ca(_state_dir(_isolated_home))
        code, out, _err = _run(capsys, "ca", "install", "--print-only")
        assert code == 0
        assert "update-ca-certificates" in out
        assert "sudo" in out

    def test_system_store_commands_are_printed_never_executed(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_or_create_ca(_state_dir(_isolated_home))
        _code, out, _err = _run(capsys, "ca", "install", "--print-only")
        # Shown as text for the operator to run: secondeye must never
        # invoke sudo against the machine's root trust store itself.
        assert "/usr/local/share/ca-certificates" in out

    def test_requires_an_existing_ca(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _out, err = _run(capsys, "ca", "install", "--print-only")
        assert code == 1
        assert "No CA" in err or "no CA" in err

    def test_reports_when_no_nss_profiles_are_found(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_or_create_ca(_state_dir(_isolated_home))
        # The isolated HOME has no Firefox or Chromium profiles in it.
        code, out, _err = _run(capsys, "ca", "install", "--home", str(_isolated_home))
        assert code == 0
        assert "No " in out or "no " in out

    def test_lists_discovered_profiles(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        load_or_create_ca(_state_dir(_isolated_home))
        profile = _isolated_home / ".mozilla" / "firefox" / "abc.default"
        profile.mkdir(parents=True)
        (profile / "cert9.db").write_bytes(b"")
        _code, out, err = _run(capsys, "ca", "install", "--home", str(_isolated_home), "--dry-run")
        assert "abc.default" in out + err


class TestJsonOutput:
    """--json for scripting. Cheap because ui.py already separated the
    view dataclasses from their rendering."""

    def test_doctor_json_is_parseable_and_carries_every_check(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import json

        code, out, _err = _run(capsys, "doctor", "--no-upstream", "--json")
        payload = json.loads(out)
        assert payload["version"]
        assert isinstance(payload["checks"], list)
        assert payload["checks"]
        assert {"name", "status", "detail"} <= set(payload["checks"][0])
        assert payload["ready"] is (code == 0)

    def test_doctor_json_emits_no_ansi_even_on_a_tty(
        self,
        _isolated_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Machine-readable output must stay machine-readable regardless of
        # how the terminal is detected.
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        _code, out, _err = _run(capsys, "doctor", "--no-upstream", "--json")
        assert "\033[" not in out

    def test_doctor_json_reports_failure(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import json

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead = probe.getsockname()[1]
        code, out, _err = _run(capsys, "doctor", "--upstream-proxy", f"127.0.0.1:{dead}", "--json")
        payload = json.loads(out)
        assert code == 1
        assert payload["ready"] is False
        assert any(check["status"] == "fail" for check in payload["checks"])

    def test_capture_list_json_is_parseable(
        self, _isolated_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import datetime
        import json

        from secondeye.analysis.pipeline import CaptureMetadata, write_capture_outputs

        captures = tmp_path / "caps"
        started = datetime.datetime(2026, 11, 18, 9, 15, tzinfo=datetime.UTC)
        write_capture_outputs(
            captures / "2026-11-18_example-com" / "json-test",
            [],
            CaptureMetadata(
                name="json-test",
                started_at=started,
                ended_at=started,
                targets=["example.com"],
                no_upstream=True,
            ),
        )
        code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(captures), "--json")
        payload = json.loads(out)
        assert code == 0
        assert payload["captures_dir"] == str(captures)
        assert payload["captures"][0]["name"] == "json-test"

    def test_capture_list_json_on_an_empty_directory_is_still_valid_json(
        self, _isolated_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import json

        code, out, _err = _run(capsys, "capture", "list", "--captures-dir", str(tmp_path), "--json")
        assert code == 0
        assert json.loads(out)["captures"] == []

    def test_proxy_status_json_without_a_daemon(
        self, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import json

        code, out, _err = _run(capsys, "proxy", "status", "--json")
        payload = json.loads(out)
        assert code == 0
        assert payload["running"] is False
