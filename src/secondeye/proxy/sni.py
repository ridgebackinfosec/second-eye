"""ClientHello buffer-and-parse: TLS SNI extraction (SPEC.md §4.2, §4.3).

Implements the buffer-and-replay strategy: since ``asyncio.StreamReader`` has
no true ``MSG_PEEK``, callers accumulate bytes from the client into memory
and call :func:`parse_client_hello` again as more arrive. Every failure mode
— not enough bytes yet, or bytes that are conclusively not a valid TLS
ClientHello — is reported through the returned result rather than raised,
so a single malformed connection can never take down the daemon (SPEC.md §8).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["ClientHelloParseResult", "SniOutcome", "parse_client_hello"]

_RECORD_HEADER_LEN = 5
_HANDSHAKE_HEADER_LEN = 4
_RANDOM_LEN = 32
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
_EXTENSION_SERVER_NAME = 0x0000
_SERVER_NAME_TYPE_HOST_NAME = 0x00


class SniOutcome(Enum):
    """Classification of a :func:`parse_client_hello` attempt."""

    FOUND = "found"
    NO_SNI = "no_sni"
    MALFORMED = "malformed"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ClientHelloParseResult:
    """Outcome of attempting to parse a (possibly partial) ClientHello buffer.

    Attributes:
        outcome: Which of the four possible classifications applies.
        sni: The extracted SNI hostname, only set when outcome is FOUND.
        bytes_needed: Total buffer length required to retry the parse, only
            set when outcome is INCOMPLETE.
    """

    outcome: SniOutcome
    sni: str | None = None
    bytes_needed: int | None = None


def parse_client_hello(data: bytes) -> ClientHelloParseResult:
    """Attempt to extract the SNI from a buffered TLS ClientHello.

    Never raises on malformed or truncated input (SPEC.md §4.3) — every
    failure mode is reported through the returned result's outcome.

    Args:
        data: Bytes buffered so far from the client connection, starting at
            the first byte of the TLS record.

    Returns:
        A ClientHelloParseResult describing whether an SNI was found, no
        SNI extension was present, the buffer needs more bytes before it
        can be evaluated, or the buffered bytes are not a valid ClientHello.
    """
    if len(data) < _RECORD_HEADER_LEN:
        return ClientHelloParseResult(SniOutcome.INCOMPLETE, bytes_needed=_RECORD_HEADER_LEN)

    if data[0] != _TLS_CONTENT_TYPE_HANDSHAKE:
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    record_length = int.from_bytes(data[3:5], "big")
    total_needed = _RECORD_HEADER_LEN + record_length
    if len(data) < total_needed:
        return ClientHelloParseResult(SniOutcome.INCOMPLETE, bytes_needed=total_needed)

    body = data[_RECORD_HEADER_LEN:total_needed]
    return _parse_handshake_body(body)


def _parse_handshake_body(body: bytes) -> ClientHelloParseResult:
    if len(body) < _HANDSHAKE_HEADER_LEN:
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    if body[0] != _HANDSHAKE_TYPE_CLIENT_HELLO:
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    handshake_length = int.from_bytes(body[1:4], "big")
    hello = body[_HANDSHAKE_HEADER_LEN : _HANDSHAKE_HEADER_LEN + handshake_length]
    if len(hello) != handshake_length:
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    pos = 2 + _RANDOM_LEN  # client_version + random
    if pos >= len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    session_id_len = hello[pos]
    pos += 1
    if pos + session_id_len > len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)
    pos += session_id_len

    if pos + 2 > len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)
    cipher_suites_len = int.from_bytes(hello[pos : pos + 2], "big")
    pos += 2
    if pos + cipher_suites_len > len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)
    pos += cipher_suites_len

    if pos >= len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)
    compression_methods_len = hello[pos]
    pos += 1
    if pos + compression_methods_len > len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)
    pos += compression_methods_len

    if pos >= len(hello):
        # No extensions block at all: a structurally valid (if archaic)
        # ClientHello with no possibility of carrying an SNI.
        return ClientHelloParseResult(SniOutcome.NO_SNI)

    if pos + 2 > len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)
    extensions_len = int.from_bytes(hello[pos : pos + 2], "big")
    pos += 2
    extensions_end = pos + extensions_len
    if extensions_end > len(hello):
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    while pos < extensions_end:
        if pos + 4 > extensions_end:
            return ClientHelloParseResult(SniOutcome.MALFORMED)
        ext_type = int.from_bytes(hello[pos : pos + 2], "big")
        ext_len = int.from_bytes(hello[pos + 2 : pos + 4], "big")
        ext_data_start = pos + 4
        ext_data_end = ext_data_start + ext_len
        if ext_data_end > extensions_end:
            return ClientHelloParseResult(SniOutcome.MALFORMED)

        if ext_type == _EXTENSION_SERVER_NAME:
            return _parse_server_name_extension(hello[ext_data_start:ext_data_end])

        pos = ext_data_end

    return ClientHelloParseResult(SniOutcome.NO_SNI)


def _parse_server_name_extension(ext_data: bytes) -> ClientHelloParseResult:
    if len(ext_data) < 2:
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    server_name_list_len = int.from_bytes(ext_data[0:2], "big")
    pos = 2
    list_end = pos + server_name_list_len
    if list_end > len(ext_data):
        return ClientHelloParseResult(SniOutcome.MALFORMED)

    while pos < list_end:
        if pos + 3 > list_end:
            return ClientHelloParseResult(SniOutcome.MALFORMED)
        name_type = ext_data[pos]
        name_len = int.from_bytes(ext_data[pos + 1 : pos + 3], "big")
        name_start = pos + 3
        name_end = name_start + name_len
        if name_end > list_end:
            return ClientHelloParseResult(SniOutcome.MALFORMED)
        name_bytes = ext_data[name_start:name_end]

        if name_type == _SERVER_NAME_TYPE_HOST_NAME:
            try:
                return ClientHelloParseResult(SniOutcome.FOUND, sni=name_bytes.decode("ascii"))
            except UnicodeDecodeError:
                return ClientHelloParseResult(SniOutcome.MALFORMED)

        pos = name_end

    return ClientHelloParseResult(SniOutcome.NO_SNI)
