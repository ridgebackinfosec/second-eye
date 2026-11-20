"""Installing secondeye's CA into local trust stores (``ca install``).

Trusting the CA is the one unavoidable manual step between installing
secondeye and capturing in-scope HTTPS, and "import this file into your
browser" is where a newcomer stalls. This automates the part that can be
automated safely.

**Scope, deliberately limited.** NSS databases — Firefox, Chromium, and
the shared ``~/.pki/nssdb`` — are handled automatically via ``certutil``,
because they live in the user's own home directory and need no
privilege. The *system* trust store is only ever **printed** as the exact
two commands to run: it needs ``sudo``, and a security tool that silently
writes to the machine's root trust store on the operator's behalf is
asking to be distrusted. The operator should see the command that touches
their root trust before it runs.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from secondeye.exceptions import TrustStoreError

__all__ = [
    "CERTUTIL_PACKAGES",
    "NICKNAME",
    "NssProfile",
    "build_install_command",
    "build_remove_command",
    "discover_nss_profiles",
    "install_into_profile",
    "remove_from_profile",
    "require_certutil",
    "system_store_instructions",
]

NICKNAME = "secondeye Root CA"
"""Nickname the certificate is stored under, and looked up by on removal."""

CERTUTIL_PACKAGES = "libnss3-tools (Debian/Ubuntu/Kali) or nss-tools (Fedora/RHEL)"

# A directory is an NSS database if it holds any of these. cert9.db is the
# modern (sqlite) format and cert8.db the legacy one; key4.db alone shows
# up in a profile created but never yet written to, which certutil can
# still add to.
_DB_FILENAMES = ("cert9.db", "cert8.db", "key4.db")

_SYSTEM_STORE_DIR = "/usr/local/share/ca-certificates"


@dataclass(frozen=True)
class NssProfile:
    """One NSS database that can hold the CA.

    Attributes:
        path: The database directory.
        label: Human-readable description, e.g. ``"Firefox (abc.default)"``.
    """

    path: Path
    label: str


def discover_nss_profiles(*, home: Path | None = None) -> list[NssProfile]:
    """Find every NSS database in the user's home directory.

    Covers Firefox installed from a distribution package, from Snap and
    from Flatpak — each keeps its profiles in a different place, and an
    operator may well have more than one — plus the shared
    ``~/.pki/nssdb`` that Chromium and some other tools use.

    Args:
        home: Home directory to search; defaults to the real one.

    Returns:
        Profiles sorted by path, deduplicated.
    """
    root = home if home is not None else Path.home()
    candidates: list[tuple[Path, str]] = []

    firefox_roots = (
        (root / ".mozilla" / "firefox", "Firefox"),
        (root / "snap" / "firefox" / "common" / ".mozilla" / "firefox", "Firefox (snap)"),
        (
            root / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
            "Firefox (flatpak)",
        ),
    )
    for firefox_root, product in firefox_roots:
        if not firefox_root.is_dir():
            continue
        for profile in firefox_root.iterdir():
            if _is_nss_db(profile):
                candidates.append((profile, f"{product} ({profile.name})"))

    shared = root / ".pki" / "nssdb"
    if _is_nss_db(shared):
        candidates.append((shared, "Shared NSS store (Chromium and others)"))

    seen: set[Path] = set()
    profiles: list[NssProfile] = []
    for path, label in sorted(candidates, key=lambda item: item[0]):
        if path in seen:
            continue
        seen.add(path)
        profiles.append(NssProfile(path=path, label=label))
    return profiles


def _is_nss_db(path: Path) -> bool:
    return path.is_dir() and any((path / name).exists() for name in _DB_FILENAMES)


def require_certutil() -> str:
    """Locate ``certutil``, or explain how to install it.

    Returns:
        Absolute path to the ``certutil`` binary.

    Raises:
        TrustStoreError: If it isn't on PATH. Most distributions don't
            ship it by default, so this is a likely outcome rather than
            an edge case, and the message names the package to install.
    """
    found = shutil.which("certutil")
    if found is None:
        raise TrustStoreError(
            "certutil is not installed, so secondeye cannot reach Firefox's or "
            f"Chromium's trust store. Install {CERTUTIL_PACKAGES}, then re-run "
            "'secondeye ca install'. To trust the CA without it, run "
            "'secondeye ca install --print-only' and follow the manual steps."
        )
    return found


def build_install_command(profile: NssProfile, pem_path: Path) -> list[str]:
    """Build the ``certutil`` invocation that adds the CA to one profile.

    ``-t "C,,"`` marks the certificate trusted to issue **TLS server**
    certificates only — not email, not code signing. Narrower than the
    ``CT,C,C`` some guides suggest, and all secondeye needs.

    Args:
        profile: The NSS database to add to.
        pem_path: The CA certificate, PEM-encoded.

    Returns:
        The argv list.
    """
    return [
        "certutil",
        "-A",
        "-d",
        f"sql:{profile.path}",
        "-n",
        NICKNAME,
        "-t",
        "C,,",
        "-i",
        str(pem_path),
    ]


def build_remove_command(profile: NssProfile) -> list[str]:
    """Build the ``certutil`` invocation that removes the CA from one profile.

    Args:
        profile: The NSS database to remove from.

    Returns:
        The argv list.
    """
    return ["certutil", "-D", "-d", f"sql:{profile.path}", "-n", NICKNAME]


def install_into_profile(profile: NssProfile, pem_path: Path) -> None:
    """Add the CA to one NSS database, replacing any previous copy.

    Args:
        profile: The NSS database to add to.
        pem_path: The CA certificate, PEM-encoded.

    Raises:
        TrustStoreError: If ``certutil`` is missing or fails.
    """
    require_certutil()
    # Remove first so re-running after regenerating the CA replaces the
    # old certificate rather than leaving two under one nickname.
    _run(build_remove_command(profile), allow_failure=True)
    _run(build_install_command(profile, pem_path))


def remove_from_profile(profile: NssProfile) -> bool:
    """Remove the CA from one NSS database.

    Args:
        profile: The NSS database to remove from.

    Returns:
        True if a certificate was removed, False if none was present.

    Raises:
        TrustStoreError: If ``certutil`` is missing.
    """
    require_certutil()
    return _run(build_remove_command(profile), allow_failure=True)


def system_store_instructions(pem_path: Path) -> list[str]:
    """The commands to trust the CA system-wide, as text to be read.

    Not executed. This needs ``sudo`` and writes to the machine's root
    trust store, which the operator should see before it happens.

    Args:
        pem_path: The CA certificate, PEM-encoded.

    Returns:
        Lines to print.
    """
    return [
        # update-ca-certificates only reads *.crt from this directory, so
        # the copy is renamed even though the contents are PEM either way.
        f"sudo cp {pem_path} {_SYSTEM_STORE_DIR}/secondeye-ca.crt",
        "sudo update-ca-certificates",
    ]


def _run(command: list[str], *, allow_failure: bool = False) -> bool:
    """Run a certutil command.

    Args:
        command: argv to execute.
        allow_failure: Treat a non-zero exit as "nothing to do" rather
            than an error (used for the pre-emptive delete).

    Returns:
        True if the command succeeded.

    Raises:
        TrustStoreError: On failure, unless allow_failure is set.
    """
    try:
        result = subprocess.run(  # noqa: S603  (argv list, no shell, fixed binary)
            command, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        raise TrustStoreError(f"failed to run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        if allow_failure:
            return False
        detail = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        raise TrustStoreError(f"{' '.join(command)} failed: {detail}")
    return True
