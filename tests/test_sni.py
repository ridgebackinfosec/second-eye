"""Tests for secondeye.proxy.sni (SPEC.md §4.2, §4.3, §14 Phase 3).

Fixtures under tests/fixtures/clienthello_*.bin are real ClientHello bytes
captured from a raw loopback listener: curl, Firefox (headless), and
Chromium (headless) all connecting to a hostname (via --resolve /
--host-resolver-rules / a forced DNS override) that maps to the listener,
so each fixture carries a genuine SNI value from that client's real TLS
stack. clienthello_no_sni.bin is a real capture from Python's ssl module
with server_hostname=None, exercising the no-SNI-extension path.
"""

from pathlib import Path

import pytest

from secondeye.proxy.sni import ClientHelloParseResult, SniOutcome, parse_client_hello

_FIXTURES = Path(__file__).parent / "fixtures"
_EXPECTED_SNI = "sni-test.example"


def _load(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


class TestRealClientFixtures:
    @pytest.mark.parametrize(
        "fixture_name",
        ["clienthello_curl.bin", "clienthello_firefox.bin", "clienthello_chrome.bin"],
    )
    def test_extracts_sni_from_real_client_capture(self, fixture_name: str) -> None:
        data = _load(fixture_name)
        result = parse_client_hello(data)
        assert result == ClientHelloParseResult(SniOutcome.FOUND, sni=_EXPECTED_SNI)

    def test_no_sni_extension_present_is_reported_distinctly(self) -> None:
        data = _load("clienthello_no_sni.bin")
        result = parse_client_hello(data)
        assert result.outcome is SniOutcome.NO_SNI
        assert result.sni is None


class TestMalformedInput:
    def test_non_tls_bytes_are_malformed_not_raised(self) -> None:
        result = parse_client_hello(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert result.outcome is SniOutcome.MALFORMED

    def test_empty_bytes_are_incomplete_not_raised(self) -> None:
        result = parse_client_hello(b"")
        assert result.outcome is SniOutcome.INCOMPLETE

    def test_handshake_type_that_is_not_client_hello_is_malformed(self) -> None:
        # content_type=handshake, version, record_len=4, handshake_type=0x02
        # (ServerHello) instead of 0x01 (ClientHello).
        data = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00])
        result = parse_client_hello(data)
        assert result.outcome is SniOutcome.MALFORMED

    def test_corrupted_extension_length_is_malformed_not_raised(self) -> None:
        data = bytearray(_load("clienthello_curl.bin"))
        # Locate the server_name extension (type 0x0000) and blow out its
        # declared length so it claims to extend past the record boundary.
        needle = bytes([0x00, 0x00])  # extension type = server_name
        idx = data.index(needle, 40)
        data[idx + 2] = 0xFF
        data[idx + 3] = 0xFF
        result = parse_client_hello(bytes(data))
        assert result.outcome is SniOutcome.MALFORMED

    def test_truncated_extension_name_length_field_is_malformed(self) -> None:
        # A server_name extension whose inner name_length claims more bytes
        # than are actually present in the extension body.
        server_name_ext = bytes(
            [
                0x00,
                0x00,  # extension type: server_name
                0x00,
                0x07,  # extension length: 7
                0x00,
                0x05,  # server_name_list length: 5
                0x00,  # name_type: host_name
                0xFF,
                0xFF,  # name_length: 65535 (way beyond available bytes)
                0x61,
                0x62,  # 2 bytes of "name" data, nowhere near 65535
            ]
        )
        hello_body = (
            bytes([0x03, 0x03])
            + bytes(32)  # random
            + bytes([0x00])  # session_id_len = 0
            + bytes([0x00, 0x02, 0x00, 0x2F])  # cipher_suites (len=2, one suite)
            + bytes([0x01, 0x00])  # compression_methods (len=1, null)
            + len(server_name_ext).to_bytes(2, "big")
            + server_name_ext
        )
        handshake = bytes([0x01]) + len(hello_body).to_bytes(3, "big") + hello_body
        record = bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake

        result = parse_client_hello(record)
        assert result.outcome is SniOutcome.MALFORMED


def _wrap_handshake(hello_body: bytes) -> bytes:
    handshake = bytes([0x01]) + len(hello_body).to_bytes(3, "big") + hello_body
    return bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake


def _minimal_hello_prefix() -> bytes:
    return (
        bytes([0x03, 0x03])
        + bytes(32)  # random
        + bytes([0x00])  # session_id_len = 0
        + bytes([0x00, 0x02, 0x00, 0x2F])  # cipher_suites (len=2, one suite)
        + bytes([0x01, 0x00])  # compression_methods (len=1, null)
    )


class TestHandshakeBodyBoundsChecks:
    def test_handshake_body_shorter_than_header_is_malformed(self) -> None:
        record = bytes([0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00])
        assert parse_client_hello(record).outcome is SniOutcome.MALFORMED

    def test_declared_handshake_length_mismatch_is_malformed(self) -> None:
        hello_body = _minimal_hello_prefix()
        # Handshake header claims a length far larger than the bytes present.
        handshake = bytes([0x01]) + (len(hello_body) + 50).to_bytes(3, "big") + hello_body
        record = bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake
        assert parse_client_hello(record).outcome is SniOutcome.MALFORMED

    def test_hello_ending_right_after_random_is_malformed(self) -> None:
        hello_body = bytes([0x03, 0x03]) + bytes(32)
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_session_id_length_exceeding_remaining_bytes_is_malformed(self) -> None:
        hello_body = bytes([0x03, 0x03]) + bytes(32) + bytes([0xFF])
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_missing_cipher_suites_length_field_is_malformed(self) -> None:
        hello_body = bytes([0x03, 0x03]) + bytes(32) + bytes([0x00]) + bytes([0x00])
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_cipher_suites_length_exceeding_remaining_bytes_is_malformed(self) -> None:
        hello_body = bytes([0x03, 0x03]) + bytes(32) + bytes([0x00]) + bytes([0xFF, 0xFF])
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_missing_compression_methods_length_byte_is_malformed(self) -> None:
        hello_body = (
            bytes([0x03, 0x03]) + bytes(32) + bytes([0x00]) + bytes([0x00, 0x02, 0x00, 0x2F])
        )
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_compression_methods_length_exceeding_remaining_bytes_is_malformed(self) -> None:
        hello_body = (
            bytes([0x03, 0x03])
            + bytes(32)
            + bytes([0x00])
            + bytes([0x00, 0x02, 0x00, 0x2F])
            + bytes([0xFF])
        )
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_no_extensions_block_present_is_no_sni(self) -> None:
        hello_body = _minimal_hello_prefix()
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.NO_SNI

    def test_missing_extensions_length_field_is_malformed(self) -> None:
        hello_body = _minimal_hello_prefix() + bytes([0x00])
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_extensions_length_exceeding_remaining_bytes_is_malformed(self) -> None:
        hello_body = _minimal_hello_prefix() + bytes([0xFF, 0xFF])
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_partial_extension_header_is_malformed(self) -> None:
        hello_body = _minimal_hello_prefix() + bytes([0x00, 0x02]) + bytes([0x00, 0x00])
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED


class TestServerNameExtensionBoundsChecks:
    def test_empty_server_name_extension_body_is_malformed(self) -> None:
        ext = bytes([0x00, 0x00, 0x00, 0x00])  # type=server_name, length=0
        hello_body = _minimal_hello_prefix() + len(ext).to_bytes(2, "big") + ext
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_server_name_list_length_exceeding_extension_body_is_malformed(self) -> None:
        ext_data = bytes([0xFF, 0xFF])  # server_name_list_len = 65535
        ext = bytes([0x00, 0x00]) + len(ext_data).to_bytes(2, "big") + ext_data
        hello_body = _minimal_hello_prefix() + len(ext).to_bytes(2, "big") + ext
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_partial_server_name_entry_header_is_malformed(self) -> None:
        ext_data = bytes([0x00, 0x02]) + bytes([0x00, 0x00])  # list_len=2, only 2 bytes follow
        ext = bytes([0x00, 0x00]) + len(ext_data).to_bytes(2, "big") + ext_data
        hello_body = _minimal_hello_prefix() + len(ext).to_bytes(2, "big") + ext
        assert parse_client_hello(_wrap_handshake(hello_body)).outcome is SniOutcome.MALFORMED

    def test_non_ascii_server_name_is_malformed(self) -> None:
        name = bytes([0xC3, 0x28])  # invalid ASCII/UTF-8 byte sequence
        entry = bytes([0x00]) + len(name).to_bytes(2, "big") + name
        ext_data = len(entry).to_bytes(2, "big") + entry
        ext = bytes([0x00, 0x00]) + len(ext_data).to_bytes(2, "big") + ext_data
        hello_body = _minimal_hello_prefix() + len(ext).to_bytes(2, "big") + ext
        result = parse_client_hello(_wrap_handshake(hello_body))
        assert result.outcome is SniOutcome.MALFORMED

    def test_server_name_entry_with_non_host_name_type_is_no_sni(self) -> None:
        # name_type 0x01 is not host_name (0x00); a compliant parser skips it.
        name = b"irrelevant"
        entry = bytes([0x01]) + len(name).to_bytes(2, "big") + name
        ext_data = len(entry).to_bytes(2, "big") + entry
        ext = bytes([0x00, 0x00]) + len(ext_data).to_bytes(2, "big") + ext_data
        hello_body = _minimal_hello_prefix() + len(ext).to_bytes(2, "big") + ext
        result = parse_client_hello(_wrap_handshake(hello_body))
        assert result.outcome is SniOutcome.NO_SNI


class TestIncompleteBuffering:
    def test_partial_record_header_is_incomplete(self) -> None:
        data = _load("clienthello_curl.bin")[:3]
        result = parse_client_hello(data)
        assert result.outcome is SniOutcome.INCOMPLETE
        assert result.bytes_needed == 5

    def test_partial_record_body_reports_exact_bytes_needed(self) -> None:
        full = _load("clienthello_curl.bin")
        result = parse_client_hello(full[:20])
        assert result.outcome is SniOutcome.INCOMPLETE
        assert result.bytes_needed == len(full)

    def test_feeding_full_length_after_incomplete_succeeds(self) -> None:
        full = _load("clienthello_curl.bin")
        first_pass = parse_client_hello(full[:20])
        assert first_pass.outcome is SniOutcome.INCOMPLETE
        assert first_pass.bytes_needed is not None

        second_pass = parse_client_hello(full[: first_pass.bytes_needed])
        assert second_pass == ClientHelloParseResult(SniOutcome.FOUND, sni=_EXPECTED_SNI)
