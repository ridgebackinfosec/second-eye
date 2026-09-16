"""Custom exception hierarchy for secondeye.

Every error path in secondeye raises one of these instead of a bare stdlib
exception, so callers can catch precisely what they mean to handle.
"""

from __future__ import annotations

import datetime
from pathlib import Path

__all__ = [
    "SecondEyeError",
    "ConfigError",
    "ScopeConfigError",
    "CertGenerationError",
    "UpstreamConnectionError",
    "MalformedClientHelloError",
    "CaptureControlError",
    "CaptureAlreadyActiveError",
    "CaptureNameConflictError",
    "NoActiveCaptureError",
]


class SecondEyeError(Exception):
    """Base class for all secondeye-specific errors."""


class ConfigError(SecondEyeError):
    """Raised for invalid daemon-startup configuration (SPEC.md §2).

    Covers cases not specific to scope/cert/upstream/ClientHello handling,
    e.g. a non-loopback --listen address or conflicting upstream flags.
    """


class CaptureControlError(SecondEyeError):
    """Base class for capture lifecycle control errors (SPEC.md §2, §6.3).

    §8's exception table doesn't enumerate these (it's written from a
    proxy/TLS lens), but §2 describes each as a required hard error with
    its own specific operator-facing message, so each gets a distinct
    subclass rather than being force-fit into an unrelated existing type.
    """


class CaptureAlreadyActiveError(CaptureControlError):
    """Raised by capture start when a capture is already active (SPEC.md §2).

    Carries the active capture's name/start time structured (not just in
    the message string) so a later phase's CLI can render §2's exact
    "a capture is already active ('idor-probe-orders', started 14:15:02)"
    format without re-parsing prose.
    """

    def __init__(self, name: str, started_at: datetime.datetime) -> None:
        super().__init__(f"a capture is already active ({name!r}, started {started_at})")
        self.name = name
        self.started_at = started_at


class CaptureNameConflictError(CaptureControlError):
    """Raised by capture start when today's output dir for this name exists (SPEC.md §2)."""

    def __init__(self, name: str, output_dir: Path) -> None:
        super().__init__(f"a capture named {name!r} already exists at {output_dir}")
        self.name = name
        self.output_dir = output_dir


class NoActiveCaptureError(CaptureControlError):
    """Raised by capture stop (or a record attempt) when no capture is active."""


class ScopeConfigError(SecondEyeError):
    """Raised when scope configuration (targets/regexes) is invalid."""


class CertGenerationError(SecondEyeError):
    """Raised when TLS leaf or CA certificate generation fails."""


class UpstreamConnectionError(SecondEyeError):
    """Raised when the upstream proxy or destination is unreachable."""


class MalformedClientHelloError(SecondEyeError):
    """Raised when a buffered ClientHello cannot be parsed."""
