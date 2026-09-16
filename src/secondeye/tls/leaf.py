"""Per-SNI leaf certificate generation and in-memory caching (SPEC.md §4.6, §5.2, §5.3).

Leaf certs are generated on first sight of an SNI, signed by the secondeye
root CA, and cached in-memory for the life of the process — never
regenerated per-request. Cert generation is CPU-bound and synchronous; the
async proxy path (built in a later phase) is responsible for wrapping calls
into this module with ``asyncio.to_thread()``.
"""

from __future__ import annotations

import datetime
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from secondeye.exceptions import CertGenerationError
from secondeye.tls.ca import CertificateAuthority

__all__ = ["LeafCertificateStore", "generate_leaf_certificate"]

_LEAF_KEY_SIZE = 2048
_LEAF_VALIDITY_DAYS = 365


def generate_leaf_certificate(ca: CertificateAuthority, sni: str) -> tuple[bytes, bytes]:
    """Generate a CA-signed leaf certificate for a single SNI.

    Args:
        ca: The secondeye root CA used to sign the leaf certificate.
        sni: The TLS SNI value the leaf certificate is issued for.

    Returns:
        A ``(cert_pem, key_pem)`` tuple.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=_LEAF_KEY_SIZE)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sni)])
    now = datetime.datetime.now(datetime.UTC)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=_LEAF_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(sni)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.private_key.public_key()),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class LeafCertificateStore:
    """Generates and caches per-SNI leaf certs, signed by a secondeye CA."""

    def __init__(self, ca: CertificateAuthority) -> None:
        """Initialize the store against a loaded root CA.

        Args:
            ca: The secondeye root CA used to sign generated leaf certs.
        """
        self._ca = ca
        self._cache: dict[str, ssl.SSLContext] = {}

    def get_context(self, sni: str) -> ssl.SSLContext:
        """Return the cached or newly generated server SSLContext for an SNI.

        Args:
            sni: The TLS SNI value to generate/retrieve a leaf cert for.

        Returns:
            An ``ssl.SSLContext`` configured with a CA-signed leaf cert for
            ``sni`` and ALPN pinned to ``http/1.1`` (SPEC.md §4.6).

        Raises:
            CertGenerationError: If leaf cert generation fails.
        """
        cached = self._cache.get(sni)
        if cached is not None:
            return cached
        context = self._build_context(sni)
        self._cache[sni] = context
        return context

    def _build_context(self, sni: str) -> ssl.SSLContext:
        try:
            cert_pem, key_pem = generate_leaf_certificate(self._ca, sni)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.set_alpn_protocols(["http/1.1"])
            with tempfile.TemporaryDirectory() as tmp_dir:
                combined_path = Path(tmp_dir) / "leaf.pem"
                combined_path.write_bytes(cert_pem + key_pem)
                context.load_cert_chain(certfile=str(combined_path))
        except (ValueError, OSError, ssl.SSLError) as exc:
            raise CertGenerationError(f"failed to generate leaf cert for {sni!r}: {exc}") from exc
        return context
