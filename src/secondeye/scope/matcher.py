"""Scope matching for secondeye (SPEC.md §3).

Evaluates a hostname (TLS SNI or plain-HTTP Host header) against the
operator-configured scope: exact/subdomain targets, glob-wildcard targets,
and regex targets. All comparisons are normalized through IDN/punycode
encoding so unicode targets match punycode SNI values and vice versa.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Sequence
from dataclasses import dataclass

import idna

from secondeye.exceptions import ScopeConfigError

__all__ = ["ScopeMatch", "ScopeMatcher", "normalize_hostname"]

_GLOB_CHARS = frozenset("*?[]")


def _normalize_label(label: str) -> str:
    """Normalize a single dot-separated hostname label.

    Labels containing glob metacharacters are lowercased only (IDNA
    encoding rejects '*'/'?'/'[]'), since glob targets are compiled
    directly into a match pattern rather than compared for equality.
    """
    if any(ch in _GLOB_CHARS for ch in label):
        return label.lower()
    try:
        return idna.encode(label, uts46=True).decode("ascii")
    except idna.IDNAError:
        return label.lower()


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname for scope comparison.

    Lowercases and IDNA/punycode-encodes each label, and strips a
    trailing root-zone dot. Used for both configured targets and
    incoming SNI/Host values so unicode and punycode forms compare equal.

    Args:
        hostname: A hostname, possibly containing unicode labels, glob
            wildcard characters, or a trailing dot.

    Returns:
        The normalized hostname.
    """
    stripped = hostname.strip().rstrip(".")
    labels = stripped.split(".")
    return ".".join(_normalize_label(label) for label in labels)


@dataclass(frozen=True)
class ScopeMatch:
    """Result of evaluating a hostname against the configured scope.

    Attributes:
        matched: Whether the hostname is in scope.
        matched_target: The configured target or regex pattern that
            produced the match, or None if unmatched.
    """

    matched: bool
    matched_target: str | None = None


class ScopeMatcher:
    """Evaluates hostnames against configured `--target`/`--target-regex` scope."""

    def __init__(
        self,
        targets: Sequence[str] = (),
        target_regexes: Sequence[str] = (),
    ) -> None:
        """Compile scope configuration into matchable form.

        Args:
            targets: Exact/subdomain or glob-wildcard domain patterns
                (SPEC.md §3.1, §3.2).
            target_regexes: Regex patterns for cases glob cannot express
                (SPEC.md §3.3).

        Raises:
            ScopeConfigError: If any target_regexes entry fails to compile.
        """
        self._exact_targets: list[str] = []
        self._glob_targets: list[tuple[str, re.Pattern[str]]] = []
        for target in targets:
            normalized = normalize_hostname(target)
            if any(ch in _GLOB_CHARS for ch in normalized):
                self._glob_targets.append((target, re.compile(fnmatch.translate(normalized))))
            else:
                self._exact_targets.append(normalized)

        self._regex_targets: list[tuple[str, re.Pattern[str]]] = []
        for pattern_str in target_regexes:
            try:
                compiled = re.compile(pattern_str)
            except re.error as exc:
                raise ScopeConfigError(
                    f"invalid --target-regex pattern {pattern_str!r}: {exc}"
                ) from exc
            self._regex_targets.append((pattern_str, compiled))

    def match(self, hostname: str) -> ScopeMatch:
        """Evaluate a hostname against the configured scope.

        Args:
            hostname: SNI value (HTTPS) or Host header value (plain HTTP).

        Returns:
            A ScopeMatch describing whether the hostname is in scope and,
            if so, which configured target/regex matched.
        """
        normalized = normalize_hostname(hostname)

        for target in self._exact_targets:
            if normalized == target or normalized.endswith("." + target):
                return ScopeMatch(matched=True, matched_target=target)

        for original, pattern in self._glob_targets:
            if pattern.match(normalized):
                return ScopeMatch(matched=True, matched_target=original)

        for original, pattern in self._regex_targets:
            if pattern.match(normalized):
                return ScopeMatch(matched=True, matched_target=original)

        return ScopeMatch(matched=False)
