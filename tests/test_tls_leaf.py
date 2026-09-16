"""Tests for secondeye.tls.leaf (SPEC.md §4.6, §5.2, §5.3, §14 Phase 2)."""

import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from secondeye.exceptions import CertGenerationError
from secondeye.tls.ca import CertificateAuthority, load_or_create_ca
from secondeye.tls.leaf import LeafCertificateStore, generate_leaf_certificate

_OPENSSL_MISSING = shutil.which("openssl") is None


@pytest.fixture
def ca(tmp_path: Path) -> CertificateAuthority:
    return load_or_create_ca(tmp_path)


class TestGenerateLeafCertificate:
    @pytest.mark.skipif(_OPENSSL_MISSING, reason="openssl binary not available")
    def test_leaf_cert_validates_against_ca(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        cert_pem, _key_pem = generate_leaf_certificate(ca, "example.com")
        leaf_path = tmp_path / "leaf.pem"
        leaf_path.write_bytes(cert_pem)

        result = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca.cert_path), str(leaf_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    async def test_leaf_cert_verifies_under_strict_ssl_chain_validation(
        self, ca: CertificateAuthority
    ) -> None:
        # openssl verify is lenient about a missing Authority Key
        # Identifier; ssl.create_default_context()'s chain validation
        # (used for real handshakes, e.g. --upstream-ca) is not. A leaf
        # cert missing AKI can pass the openssl check above yet still fail
        # a real TLS handshake with CERTIFICATE_VERIFY_FAILED.
        import asyncio

        store = LeafCertificateStore(ca)
        server_ctx = store.get_context("strict-verify.example")

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
        port = server.sockets[0].getsockname()[1]
        try:
            client_ctx = ssl.create_default_context(cafile=str(ca.cert_path))
            _reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx, server_hostname="strict-verify.example"
            )
            writer.close()
        finally:
            server.close()
            await server.wait_closed()

    def test_leaf_cert_is_signed_by_ca_not_self_signed(self, ca: CertificateAuthority) -> None:
        cert_pem, _key_pem = generate_leaf_certificate(ca, "example.com")
        from cryptography import x509

        leaf_cert = x509.load_pem_x509_certificate(cert_pem)
        assert leaf_cert.issuer == ca.certificate.subject
        assert leaf_cert.subject != leaf_cert.issuer

    def test_leaf_cert_subject_alternative_name_matches_sni(self, ca: CertificateAuthority) -> None:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert_pem, _key_pem = generate_leaf_certificate(ca, "dev-a1b2.example.com")
        leaf_cert = x509.load_pem_x509_certificate(cert_pem)
        san = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        assert isinstance(san, x509.SubjectAlternativeName)
        assert san.get_values_for_type(x509.DNSName) == ["dev-a1b2.example.com"]


class TestLeafCertificateStoreCaching:
    def test_repeat_calls_for_same_sni_return_same_context_object(
        self, ca: CertificateAuthority
    ) -> None:
        store = LeafCertificateStore(ca)
        first = store.get_context("example.com")
        second = store.get_context("example.com")
        assert first is second

    def test_different_sni_values_get_different_context_objects(
        self, ca: CertificateAuthority
    ) -> None:
        store = LeafCertificateStore(ca)
        a = store.get_context("a.example.com")
        b = store.get_context("b.example.com")
        assert a is not b


class TestAlpnPinning:
    def test_alpn_negotiates_http1_1_even_when_client_offers_h2(
        self, ca: CertificateAuthority
    ) -> None:
        store = LeafCertificateStore(ca)
        server_context = store.get_context("example.com")

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        server_result: dict[str, str | None] = {}

        def run_server() -> None:
            conn, _addr = server_sock.accept()
            with server_context.wrap_socket(conn, server_side=True) as tls_conn:
                server_result["alpn"] = tls_conn.selected_alpn_protocol()

        server_thread = threading.Thread(target=run_server)
        server_thread.start()

        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.set_alpn_protocols(["h2", "http/1.1"])

        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_client:
            with client_context.wrap_socket(raw_client, server_hostname="example.com") as tls:
                client_alpn = tls.selected_alpn_protocol()

        server_thread.join(timeout=5)
        server_sock.close()

        assert client_alpn == "http/1.1"
        assert server_result["alpn"] == "http/1.1"


class TestLeafCertGenerationFailure:
    def test_generation_failure_raises_cert_generation_error(
        self, ca: CertificateAuthority, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = LeafCertificateStore(ca)

        def _boom(*_args: object, **_kwargs: object) -> None:
            raise ValueError("boom")

        monkeypatch.setattr(
            "secondeye.tls.leaf.generate_leaf_certificate",
            _boom,
        )

        with pytest.raises(CertGenerationError):
            store.get_context("example.com")
