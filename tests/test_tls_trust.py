"""Tests for secondeye.tls.trust — installing the CA into NSS trust stores.

Structured so that the parts that can be tested without `certutil` are
pure functions over a filesystem tree: profile discovery and command
construction. Only the actual install shells out, and those tests skip
when `certutil` is absent (it is not installed by default on most
distributions — which is itself a case this module has to handle well).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secondeye.exceptions import TrustStoreError
from secondeye.tls.trust import (
    CERTUTIL_PACKAGES,
    NICKNAME,
    NssProfile,
    build_install_command,
    build_remove_command,
    discover_nss_profiles,
    install_into_profile,
    require_certutil,
    system_store_instructions,
)

_HAS_CERTUTIL = shutil.which("certutil") is not None


def _make_profile(root: Path, relative: str, *, db: str = "cert9.db") -> Path:
    profile = root / relative
    profile.mkdir(parents=True, exist_ok=True)
    (profile / db).write_bytes(b"")
    return profile


class TestDiscovery:
    def test_finds_a_firefox_profile(self, tmp_path: Path) -> None:
        expected = _make_profile(tmp_path, ".mozilla/firefox/abc123.default")
        found = {p.path for p in discover_nss_profiles(home=tmp_path)}
        assert expected in found

    def test_finds_the_shared_nssdb(self, tmp_path: Path) -> None:
        expected = _make_profile(tmp_path, ".pki/nssdb")
        found = {p.path for p in discover_nss_profiles(home=tmp_path)}
        assert expected in found

    def test_finds_snap_and_flatpak_firefox_profiles(self, tmp_path: Path) -> None:
        snap = _make_profile(tmp_path, "snap/firefox/common/.mozilla/firefox/s.default")
        flatpak = _make_profile(tmp_path, ".var/app/org.mozilla.firefox/.mozilla/firefox/f.default")
        found = {p.path for p in discover_nss_profiles(home=tmp_path)}
        assert snap in found
        assert flatpak in found

    def test_accepts_a_legacy_cert8_database(self, tmp_path: Path) -> None:
        legacy = _make_profile(tmp_path, ".mozilla/firefox/old.default", db="cert8.db")
        found = {p.path for p in discover_nss_profiles(home=tmp_path)}
        assert legacy in found

    def test_accepts_a_key4_only_database(self, tmp_path: Path) -> None:
        # A profile that has been created but never had a cert added has
        # key4.db without cert9.db; certutil can still write to it.
        profile = _make_profile(tmp_path, ".mozilla/firefox/fresh.default", db="key4.db")
        found = {p.path for p in discover_nss_profiles(home=tmp_path)}
        assert profile in found

    def test_ignores_directories_without_a_database(self, tmp_path: Path) -> None:
        noise = tmp_path / ".mozilla/firefox/Crash Reports"
        noise.mkdir(parents=True)
        found = {p.path for p in discover_nss_profiles(home=tmp_path)}
        assert noise not in found

    def test_returns_empty_when_nothing_is_installed(self, tmp_path: Path) -> None:
        assert discover_nss_profiles(home=tmp_path) == []

    def test_each_profile_is_labelled_for_display(self, tmp_path: Path) -> None:
        _make_profile(tmp_path, ".mozilla/firefox/abc123.default")
        _make_profile(tmp_path, ".pki/nssdb")
        labels = {p.label for p in discover_nss_profiles(home=tmp_path)}
        assert any("Firefox" in label for label in labels)
        assert any("NSS" in label or "Chromium" in label for label in labels)

    def test_discovery_is_deduplicated_and_ordered(self, tmp_path: Path) -> None:
        _make_profile(tmp_path, ".mozilla/firefox/b.default")
        _make_profile(tmp_path, ".mozilla/firefox/a.default")
        paths = [p.path for p in discover_nss_profiles(home=tmp_path)]
        assert len(paths) == len(set(paths))
        assert paths == sorted(paths)


class TestCommandConstruction:
    def test_install_command_uses_sql_prefix_and_ca_trust_flags(self, tmp_path: Path) -> None:
        profile = NssProfile(path=tmp_path / "p", label="Firefox (p)")
        pem = tmp_path / "ca.pem"
        command = build_install_command(profile, pem)
        assert command[0] == "certutil"
        assert "-A" in command
        # sql: is required for the modern cert9.db format.
        assert f"sql:{profile.path}" in command
        assert NICKNAME in command
        # "C,," = trusted CA for TLS only; not email, not code signing.
        assert "C,," in command
        assert str(pem) in command

    def test_remove_command_targets_the_same_nickname(self, tmp_path: Path) -> None:
        profile = NssProfile(path=tmp_path / "p", label="Firefox (p)")
        command = build_remove_command(profile)
        assert "-D" in command
        assert NICKNAME in command
        assert f"sql:{profile.path}" in command

    def test_install_and_remove_agree_on_the_nickname(self, tmp_path: Path) -> None:
        # A mismatch would make --remove silently no-op.
        profile = NssProfile(path=tmp_path / "p", label="p")
        install = build_install_command(profile, tmp_path / "ca.pem")
        remove = build_remove_command(profile)
        assert install[install.index("-n") + 1] == remove[remove.index("-n") + 1]


class TestCertutilRequirement:
    @pytest.mark.skipif(_HAS_CERTUTIL, reason="certutil is installed here")
    def test_missing_certutil_raises_a_message_naming_the_package(self) -> None:
        with pytest.raises(TrustStoreError) as excinfo:
            require_certutil()
        message = str(excinfo.value)
        assert "certutil" in message
        assert "libnss3-tools" in message

    @pytest.mark.skipif(not _HAS_CERTUTIL, reason="certutil not installed")
    def test_present_certutil_returns_its_path(self) -> None:
        assert Path(require_certutil()).name.startswith("certutil")

    def test_package_hint_names_both_major_families(self) -> None:
        assert "libnss3-tools" in CERTUTIL_PACKAGES
        assert "nss-tools" in CERTUTIL_PACKAGES


class TestSystemStoreInstructions:
    def test_prints_commands_rather_than_running_them(self, tmp_path: Path) -> None:
        pem = tmp_path / "secondeye-ca.pem"
        lines = system_store_instructions(pem)
        joined = "\n".join(lines)
        assert "update-ca-certificates" in joined
        assert str(pem) in joined
        # sudo appears as text for the operator to run, never executed by us.
        assert "sudo" in joined

    def test_uses_a_crt_extension_for_the_system_store(self, tmp_path: Path) -> None:
        # update-ca-certificates only picks up *.crt from
        # /usr/local/share/ca-certificates.
        joined = "\n".join(system_store_instructions(tmp_path / "secondeye-ca.pem"))
        assert ".crt" in joined


@pytest.mark.skipif(not _HAS_CERTUTIL, reason="certutil not installed")
class TestRealInstall:
    """Against a throwaway NSS database, when certutil is available."""

    def _new_db(self, tmp_path: Path) -> NssProfile:
        import subprocess

        db = tmp_path / "nssdb"
        db.mkdir()
        password = tmp_path / "pw"
        password.write_text("", encoding="utf-8")
        subprocess.run(
            ["certutil", "-N", "-d", f"sql:{db}", "-f", str(password)],
            check=True,
            capture_output=True,
        )
        return NssProfile(path=db, label="throwaway")

    def test_installing_puts_the_ca_in_the_database(self, tmp_path: Path) -> None:
        import subprocess

        from secondeye.tls.ca import load_or_create_ca

        ca = load_or_create_ca(tmp_path / "state")
        profile = self._new_db(tmp_path)
        install_into_profile(profile, ca.cert_path)
        listed = subprocess.run(
            ["certutil", "-L", "-d", f"sql:{profile.path}"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert NICKNAME in listed.stdout
