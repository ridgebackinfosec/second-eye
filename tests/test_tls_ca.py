"""Tests for secondeye.tls.ca (SPEC.md §5.2, §5.4, §14 Phase 2)."""

import logging
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from secondeye.exceptions import CertGenerationError
from secondeye.tls.ca import ca_exists, default_state_dir, load_or_create_ca

_OPENSSL_MISSING = shutil.which("openssl") is None


class TestCaGenerationAndPersistence:
    def test_generates_and_persists_ca_files(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        assert ca.cert_path == tmp_path / "ca" / "secondeye-ca.pem"
        assert ca.key_path == tmp_path / "ca" / "secondeye-ca.key"
        assert ca.cert_path.exists()
        assert ca.key_path.exists()

    def test_second_run_loads_existing_ca_rather_than_regenerating(self, tmp_path: Path) -> None:
        first = load_or_create_ca(tmp_path)
        second = load_or_create_ca(tmp_path)

        assert first.certificate.serial_number == second.certificate.serial_number
        assert first.private_key.private_numbers().d == second.private_key.private_numbers().d

    def test_ca_certificate_is_self_signed(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        assert ca.certificate.subject == ca.certificate.issuer

    def test_ca_key_file_permissions_are_owner_only(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        mode = ca.key_path.stat().st_mode & 0o777
        assert mode == 0o600

    @pytest.mark.skipif(_OPENSSL_MISSING, reason="openssl binary not available")
    def test_ca_cert_verifies_as_self_signed_via_openssl(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca.cert_path), str(ca.cert_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_warns_when_only_cert_file_exists(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # First call generates a full CA (both cert and key persisted).
    load_or_create_ca(tmp_path)
    key_path = tmp_path / "ca" / "secondeye-ca.key"
    key_path.unlink()  # simulate partial corruption: key missing, cert remains

    with caplog.at_level(logging.WARNING, logger="secondeye.tls.ca"):
        load_or_create_ca(tmp_path)

    message = next(r.message for r in caplog.records if "secondeye-ca.key" in r.message)
    assert "secondeye-ca.pem" in message  # the surviving file is also named
    assert message.index("secondeye-ca.pem") < message.index("secondeye-ca.key")
    assert "regenerat" in message.lower()


def test_warns_when_only_key_file_exists(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    load_or_create_ca(tmp_path)
    cert_path = tmp_path / "ca" / "secondeye-ca.pem"
    cert_path.unlink()  # simulate partial corruption: cert missing, key remains

    with caplog.at_level(logging.WARNING, logger="secondeye.tls.ca"):
        load_or_create_ca(tmp_path)

    message = next(r.message for r in caplog.records if "secondeye-ca.key" in r.message)
    assert "secondeye-ca.pem" in message  # the surviving file is also named
    assert message.index("secondeye-ca.key") < message.index("secondeye-ca.pem")
    assert "regenerat" in message.lower()


class TestStateDirectoryPermissions:
    def test_state_dir_locked_to_owner_only(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        load_or_create_ca(state_dir)
        assert state_dir.is_dir()
        assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700

    def test_preexisting_world_readable_state_dir_gets_tightened(self, tmp_path: Path) -> None:
        # Simulates upgrading from a pre-v1.0.0 install, where the state
        # directory was created with default umask permissions.
        state_dir = tmp_path / "state"
        state_dir.mkdir(mode=0o755)
        state_dir.chmod(0o755)  # mkdir's mode= is masked by umask; force it explicitly

        load_or_create_ca(state_dir)

        assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700

    def test_lockdown_runs_before_the_ca_is_created(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        state_dir.mkdir(mode=0o500)
        state_dir.chmod(0o500)  # read+execute only: unwritable until tightened to 0700

        load_or_create_ca(state_dir)

        # Only reachable if the chmod preceded CA file creation.
        assert (state_dir / "ca" / "secondeye-ca.pem").exists()
        assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700


class TestCreatedFlag:
    def test_first_generation_reports_created_true(self, tmp_path: Path) -> None:
        ca = load_or_create_ca(tmp_path)
        assert ca.created is True

    def test_subsequent_load_reports_created_false(self, tmp_path: Path) -> None:
        load_or_create_ca(tmp_path)
        second = load_or_create_ca(tmp_path)
        assert second.created is False


class TestCaExists:
    def test_false_before_any_ca_generated(self, tmp_path: Path) -> None:
        assert ca_exists(tmp_path) is False

    def test_true_after_generation(self, tmp_path: Path) -> None:
        load_or_create_ca(tmp_path)
        assert ca_exists(tmp_path) is True

    def test_does_not_itself_generate_a_ca(self, tmp_path: Path) -> None:
        ca_exists(tmp_path)
        assert not (tmp_path / "ca" / "secondeye-ca.pem").exists()


class TestCaLoadFailure:
    def test_corrupted_ca_files_raise_cert_generation_error(self, tmp_path: Path) -> None:
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir(parents=True)
        (ca_dir / "secondeye-ca.pem").write_bytes(b"not a certificate")
        (ca_dir / "secondeye-ca.key").write_bytes(b"not a key")

        with pytest.raises(CertGenerationError):
            load_or_create_ca(tmp_path)

    def test_non_rsa_ca_key_raises_cert_generation_error(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        ca_dir = tmp_path / "ca"
        ca_dir.mkdir(parents=True)

        ec_key = ec.generate_private_key(ec.SECP256R1())
        cert = load_or_create_ca(tmp_path / "unrelated").certificate
        (ca_dir / "secondeye-ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (ca_dir / "secondeye-ca.key").write_bytes(
            ec_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with pytest.raises(CertGenerationError):
            load_or_create_ca(tmp_path)

    def test_generation_failure_raises_cert_generation_error(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"a file, not a directory")

        with pytest.raises(CertGenerationError):
            load_or_create_ca(blocker / "state")


class TestDefaultStateDir:
    def test_default_state_dir_is_xdg_state_path(self) -> None:
        assert default_state_dir() == Path.home() / ".local" / "state" / "secondeye"
