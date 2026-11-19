"""Pre-flight environment checks behind ``secondeye doctor``.

A newcomer otherwise discovers each of these the hard way and one at a
time: the CA isn't in any trust store so every in-scope HTTPS request
fails, the listen port is already taken, Burp isn't running yet,
``certutil`` is missing so ``ca install`` can't work. Each failure looks
like a different problem. This module collects them into one report that
can be read before any of them bites.

Checks return data, never printed output: ``ui.py`` renders them, and a
future ``--json`` serialises the same dataclasses. Nothing here mutates
anything — in particular it never creates a CA as a side effect, matching
``ca status``'s read-only contract.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import os
import shutil
import socket
import stat
from dataclasses import dataclass, field
from pathlib import Path

import secondeye
from secondeye.tls.ca import ca_exists, load_ca_certificate

__all__ = ["Check", "CheckStatus", "DoctorReport", "run_checks"]

_EXPECTED_STATE_MODE = 0o700
_CERTUTIL_PACKAGES = "libnss3-tools (Debian/Ubuntu/Kali) or nss-tools (Fedora/RHEL)"


class CheckStatus(enum.Enum):
    """Outcome of one check.

    ``WARN`` is for something the operator should know that secondeye can
    still work around — a CA that doesn't exist yet gets created on
    ``proxy start``. ``FAIL`` is for something that will stop a capture
    working, and is what makes ``doctor`` exit non-zero.
    """

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class Check:
    """One environment check's result.

    Attributes:
        name: Short label, e.g. ``"listen port"``.
        status: Whether it passed, warned or failed.
        detail: What was found.
        hint: What to do about it, when there is something to do.
    """

    name: str
    status: CheckStatus
    detail: str
    hint: str | None = None


@dataclass(frozen=True)
class DoctorReport:
    """Every check, plus the overall verdict.

    Attributes:
        version: The installed secondeye version.
        checks: Each check's result, in display order.
    """

    version: str
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        """Whether any check failed (warnings don't count)."""
        return any(check.status is CheckStatus.FAIL for check in self.checks)

    @property
    def counts(self) -> dict[CheckStatus, int]:
        """How many checks landed in each status."""
        return {
            status: sum(1 for check in self.checks if check.status is status)
            for status in CheckStatus
        }


def run_checks(
    *,
    state_dir: Path,
    captures_dir: Path,
    listen_host: str,
    listen_port: int,
    upstream: tuple[str, int] | None,
    upstream_ca: Path | None,
    upstream_insecure: bool = False,
) -> DoctorReport:
    """Run every environment check and collect the results.

    Args:
        state_dir: secondeye's state directory.
        captures_dir: Where captures would be written.
        listen_host: Proxy listener bind host.
        listen_port: Proxy listener bind port.
        upstream: Upstream ``(host, port)``, or None for --no-upstream.
        upstream_ca: Path passed to --upstream-ca, if any.
        upstream_insecure: Whether --upstream-insecure was passed.

    Returns:
        The full report.
    """
    checks = [
        _check_ca(state_dir),
        _check_state_dir_mode(state_dir),
        _check_captures_dir(captures_dir),
        _check_listen_port(listen_host, listen_port),
        *_check_upstream(upstream, upstream_ca, upstream_insecure),
        _check_certutil(),
        _check_completion(),
    ]
    return DoctorReport(version=secondeye.__version__, checks=checks)


def _check_ca(state_dir: Path) -> Check:
    if not ca_exists(state_dir):
        return Check(
            name="CA",
            status=CheckStatus.WARN,
            detail="not generated yet",
            hint="'secondeye proxy start' creates one; then 'secondeye ca install' to trust it",
        )
    certificate = load_ca_certificate(state_dir)
    if certificate is None:
        return Check(
            name="CA",
            status=CheckStatus.FAIL,
            detail=f"present at {state_dir / 'ca'} but unreadable",
            hint="remove the ca/ directory to have a fresh one generated",
        )
    import datetime

    now = datetime.datetime.now(datetime.UTC)
    not_after = certificate.not_valid_after_utc
    if now > not_after:
        return Check(
            name="CA",
            status=CheckStatus.FAIL,
            detail=f"expired {(now - not_after).days} days ago",
            hint="remove the ca/ directory and re-import the new CA",
        )
    return Check(
        name="CA",
        status=CheckStatus.OK,
        detail=f"valid, {(not_after - now).days} days remaining",
    )


def _check_state_dir_mode(state_dir: Path) -> Check:
    if not state_dir.is_dir():
        return Check(
            name="state dir",
            status=CheckStatus.WARN,
            detail=f"{state_dir} does not exist yet",
            hint="created on first run",
        )
    mode = stat.S_IMODE(state_dir.stat().st_mode)
    if mode != _EXPECTED_STATE_MODE:
        # SECURITY.md documents 0700 as a guarantee; looser means the CA
        # private key is readable by other local users.
        return Check(
            name="state dir",
            status=CheckStatus.FAIL,
            detail=f"{state_dir} is {mode:04o}, expected 0700",
            hint=f"chmod 0700 {state_dir} — it holds the CA private key",
        )
    return Check(name="state dir", status=CheckStatus.OK, detail=f"{state_dir} is 0700")


def _check_captures_dir(captures_dir: Path) -> Check:
    existing = captures_dir
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if not os.access(existing, os.W_OK):
        return Check(
            name="captures dir",
            status=CheckStatus.FAIL,
            detail=f"{captures_dir} is not writable",
            hint=f"check permissions on {existing}, or pass --captures-dir elsewhere",
        )
    if captures_dir.is_dir():
        return Check(
            name="captures dir",
            status=CheckStatus.OK,
            detail=f"{captures_dir} is writable",
        )
    return Check(
        name="captures dir",
        status=CheckStatus.OK,
        detail=f"{captures_dir} will be created",
    )


def _check_listen_port(host: str, port: int) -> Check:
    if port == 0:
        return Check(
            name="listen port",
            status=CheckStatus.OK,
            detail=f"{host}:0 (an unused port is chosen at startup)",
        )
    probe = socket.socket()
    try:
        # No SO_REUSEADDR: the point is to find out whether binding would
        # fail for real, and that option would mask exactly that.
        probe.bind((host, port))
    except OSError as exc:
        return Check(
            name="listen port",
            status=CheckStatus.FAIL,
            detail=f"{host}:{port} is unavailable ({exc.strerror or exc})",
            hint="stop whatever holds it, or pass a different --listen-address",
        )
    finally:
        probe.close()
    return Check(name="listen port", status=CheckStatus.OK, detail=f"{host}:{port} is free")


def _check_upstream(
    upstream: tuple[str, int] | None, upstream_ca: Path | None, upstream_insecure: bool
) -> list[Check]:
    if upstream is None:
        return [
            Check(
                name="upstream",
                status=CheckStatus.OK,
                detail="none (--no-upstream): connecting directly to each destination",
            )
        ]

    host, port = upstream
    checks = [_probe_upstream(host, port)]
    if upstream_ca is not None:
        checks.append(_check_upstream_ca(upstream_ca))
    elif upstream_insecure:
        checks.append(
            Check(
                name="upstream trust",
                status=CheckStatus.WARN,
                detail="--upstream-insecure: TLS verification disabled on the upstream leg",
                hint="prefer --upstream-ca with the proxy's certificate",
            )
        )
    else:
        checks.append(
            Check(
                name="upstream trust",
                status=CheckStatus.FAIL,
                detail="neither --upstream-ca nor --upstream-insecure given",
                hint="'secondeye ca import-upstream --from-burp' fetches Burp's CA",
            )
        )
    return checks


def _probe_upstream(host: str, port: int) -> Check:
    async def probe() -> str | None:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
        except (OSError, TimeoutError) as exc:
            return "connection timed out" if isinstance(exc, TimeoutError) else str(exc)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return None

    failure = asyncio.run(probe())
    if failure is not None:
        return Check(
            name="upstream",
            status=CheckStatus.FAIL,
            detail=f"{host}:{port} is not reachable ({failure})",
            hint="start Burp/ZAP, fix --upstream-proxy, or use --no-upstream",
        )
    return Check(name="upstream", status=CheckStatus.OK, detail=f"{host}:{port} is reachable")


def _check_upstream_ca(path: Path) -> Check:
    if not path.is_file():
        return Check(
            name="upstream trust",
            status=CheckStatus.FAIL,
            detail=f"--upstream-ca {path} does not exist",
            hint="'secondeye ca import-upstream --from-burp' writes one",
        )
    try:
        path.read_bytes()
    except OSError as exc:
        return Check(
            name="upstream trust",
            status=CheckStatus.FAIL,
            detail=f"--upstream-ca {path} is unreadable ({exc.strerror or exc})",
        )
    return Check(name="upstream trust", status=CheckStatus.OK, detail=f"--upstream-ca {path}")


def _check_certutil() -> Check:
    found = shutil.which("certutil")
    if found is None:
        return Check(
            name="certutil",
            status=CheckStatus.WARN,
            detail="not installed — 'secondeye ca install' can't reach Firefox/Chromium",
            hint=f"install {_CERTUTIL_PACKAGES}",
        )
    return Check(name="certutil", status=CheckStatus.OK, detail=found)


def _check_completion() -> Check:
    # argcomplete's global hook writes this directory; its presence is the
    # cheapest reliable signal that completion was activated, short of
    # inspecting the user's shell rc files.
    activated = Path.home() / ".bash_completion.d" / "python-argcomplete"
    if activated.exists():
        return Check(name="completion", status=CheckStatus.OK, detail="argcomplete activated")
    return Check(
        name="completion",
        status=CheckStatus.WARN,
        detail="shell completion not detected",
        hint="run 'activate-global-python-argcomplete --user', or see the README",
    )
