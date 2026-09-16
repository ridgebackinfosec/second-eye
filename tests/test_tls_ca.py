"""Tests for secondeye.tls.ca (SPEC.md §5.2, §5.4, §14 Phase 2)."""

import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from secondeye.exceptions import CertGenerationError
from secondeye.tls.ca import default_state_dir, load_or_create_ca

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
