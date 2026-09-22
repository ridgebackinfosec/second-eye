"""Root CA generation and persistence for secondeye (SPEC.md §5.2, §5.4).

The root CA is generated once on first run and persisted to disk; every
subsequent run loads the existing CA rather than regenerating it, so the
operator only has to install trust for it once per host.
"""

from __future__ import annotations

import datetime
import logging
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from secondeye.exceptions import CertGenerationError

__all__ = ["CertificateAuthority", "ca_exists", "default_state_dir", "load_or_create_ca"]

logger = logging.getLogger(__name__)

_CA_KEY_SIZE = 2048
_CA_VALIDITY_DAYS = 3650
_CA_COMMON_NAME = "secondeye Root CA"
_CERT_FILENAME = "secondeye-ca.pem"
_KEY_FILENAME = "secondeye-ca.key"


def default_state_dir() -> Path:
    """Return secondeye's default state directory (SPEC.md §6.5).

    Returns:
        ``~/.local/state/secondeye``.
    """
    return Path.home() / ".local" / "state" / "secondeye"


@dataclass(frozen=True)
class CertificateAuthority:
    """A loaded or freshly generated secondeye root CA.

    Attributes:
        certificate: The CA's self-signed X.509 certificate.
        private_key: The CA's RSA private key, used to sign leaf certs.
        cert_path: Path to the persisted CA certificate (PEM).
        key_path: Path to the persisted CA private key (PEM).
    """

    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey
    cert_path: Path
    key_path: Path
    created: bool = False


def ca_exists(state_dir: Path | None = None) -> bool:
    """Whether a CA has already been generated, without generating one.

    Unlike :func:`load_or_create_ca`, this never creates a CA as a side
    effect — for read-only callers like ``secondeye ca status``.

    Args:
        state_dir: secondeye's state directory. Defaults to
            :func:`default_state_dir`.

    Returns:
        True if both the cert and key files are already persisted.
    """
    ca_dir = (state_dir if state_dir is not None else default_state_dir()) / "ca"
    return (ca_dir / _CERT_FILENAME).exists() and (ca_dir / _KEY_FILENAME).exists()


def load_or_create_ca(state_dir: Path | None = None) -> CertificateAuthority:
    """Load the persisted root CA, generating and persisting one if absent.

    Args:
        state_dir: secondeye's state directory. Defaults to
            :func:`default_state_dir`.

    Returns:
        The loaded or newly generated CertificateAuthority.

    Raises:
        CertGenerationError: If CA generation or loading fails.
    """
    ca_dir = (state_dir if state_dir is not None else default_state_dir()) / "ca"
    cert_path = ca_dir / _CERT_FILENAME
    key_path = ca_dir / _KEY_FILENAME

    cert_exists = cert_path.exists()
    key_exists = key_path.exists()
    if cert_exists and key_exists:
        return _load_ca(cert_path, key_path)
    if cert_exists != key_exists:
        missing_path = key_path if cert_exists else cert_path
        logger.warning(
            "%s is missing its counterpart — the existing CA is incomplete and "
            "will be regenerated, invalidating trust for any previously-captured host",
            missing_path,
        )
    return _generate_ca(ca_dir, cert_path, key_path)


def _load_ca(cert_path: Path, key_path: Path) -> CertificateAuthority:
    try:
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise CertGenerationError(f"failed to load existing CA from {cert_path}: {exc}") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CertGenerationError(f"CA key at {key_path} is not an RSA private key")

    return CertificateAuthority(
        certificate=certificate,
        private_key=private_key,
        cert_path=cert_path,
        key_path=key_path,
    )


def _generate_ca(ca_dir: Path, cert_path: Path, key_path: Path) -> CertificateAuthority:
    try:
        ca_dir.mkdir(parents=True, exist_ok=True)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=_CA_KEY_SIZE)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_COMMON_NAME)])
        now = datetime.datetime.now(datetime.UTC)

        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=_CA_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        raise CertGenerationError(f"failed to generate/persist CA at {ca_dir}: {exc}") from exc

    return CertificateAuthority(
        certificate=certificate,
        private_key=private_key,
        cert_path=cert_path,
        key_path=key_path,
        created=True,
    )
