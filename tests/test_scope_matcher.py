"""Tests for secondeye.scope.matcher (SPEC.md §3, §14 Phase 1)."""

import pytest

from secondeye.exceptions import ScopeConfigError
from secondeye.scope.matcher import ScopeMatcher, normalize_hostname


class TestExactAndSubdomainMatch:
    def test_exact_apex_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        result = matcher.match("example.com")
        assert result.matched is True
        assert result.matched_target == "example.com"

    def test_automatic_subdomain_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("www.example.com").matched is True
        assert matcher.match("api.example.com").matched is True
        assert matcher.match("dev-a1b2.example.com").matched is True

    def test_multi_level_subdomain_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("a.b.c.example.com").matched is True

    def test_case_insensitive_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("WWW.Example.COM").matched is True

    def test_multiple_targets_repeatable(self) -> None:
        matcher = ScopeMatcher(targets=["example.com", "corp.internal"])
        assert matcher.match("api.example.com").matched is True
        assert matcher.match("host.corp.internal").matched is True


class TestNonMatches:
    def test_unrelated_domain_does_not_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("notexample.com").matched is False

    def test_domain_with_target_as_suffix_of_label_does_not_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("evil-example.com").matched is False

    def test_target_as_suffix_after_extra_domain_does_not_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("example.com.evil.com").matched is False

    def test_empty_matcher_matches_nothing(self) -> None:
        matcher = ScopeMatcher()
        assert matcher.match("example.com").matched is False


class TestGlobWildcardMatch:
    def test_wildcard_apex_matches_subdomain(self) -> None:
        matcher = ScopeMatcher(targets=["*.corp.internal"])
        assert matcher.match("foo.corp.internal").matched is True
        assert matcher.match("a.b.corp.internal").matched is True

    def test_wildcard_does_not_match_unrelated_domain(self) -> None:
        matcher = ScopeMatcher(targets=["*.corp.internal"])
        assert matcher.match("notcorp.internal").matched is False

    def test_wildcard_does_not_match_bare_apex(self) -> None:
        matcher = ScopeMatcher(targets=["*.corp.internal"])
        assert matcher.match("corp.internal").matched is False


class TestRegexMatch:
    def test_alternation_regex_matches_env_prefixes(self) -> None:
        matcher = ScopeMatcher(target_regexes=[r"^(dev|stg|qa)-[a-z0-9]+\.example\.com$"])
        assert matcher.match("dev-a1b2.example.com").matched is True
        assert matcher.match("stg-x9.example.com").matched is True
        assert matcher.match("qa-1.example.com").matched is True

    def test_alternation_regex_rejects_other_prefixes(self) -> None:
        matcher = ScopeMatcher(target_regexes=[r"^(dev|stg|qa)-[a-z0-9]+\.example\.com$"])
        assert matcher.match("prod-a1.example.com").matched is False

    def test_bounded_numeric_range_regex(self) -> None:
        matcher = ScopeMatcher(target_regexes=[r"^shard(0[1-9]|[1-4][0-9]|50)\.example\.com$"])
        assert matcher.match("shard01.example.com").matched is True
        assert matcher.match("shard50.example.com").matched is True
        assert matcher.match("shard51.example.com").matched is False

    def test_invalid_regex_raises_scope_config_error(self) -> None:
        with pytest.raises(ScopeConfigError):
            ScopeMatcher(target_regexes=["(unclosed"])


class TestIdnPunycodeNormalization:
    def test_unicode_target_matches_punycode_sni(self) -> None:
        matcher = ScopeMatcher(targets=["müller.example"])
        assert matcher.match("xn--mller-kva.example").matched is True

    def test_punycode_target_matches_unicode_sni(self) -> None:
        matcher = ScopeMatcher(targets=["xn--mller-kva.example"])
        assert matcher.match("müller.example").matched is True

    def test_unicode_target_matches_unicode_sni(self) -> None:
        matcher = ScopeMatcher(targets=["müller.example"])
        assert matcher.match("müller.example").matched is True


class TestNormalizeHostname:
    def test_lowercases_ascii(self) -> None:
        assert normalize_hostname("Example.COM") == "example.com"

    def test_encodes_unicode_to_punycode(self) -> None:
        assert normalize_hostname("müller.example") == "xn--mller-kva.example"

    def test_strips_trailing_dot(self) -> None:
        assert normalize_hostname("example.com.") == "example.com"

    def test_preserves_glob_wildcard_chars(self) -> None:
        assert normalize_hostname("*.corp.internal") == "*.corp.internal"

    def test_falls_back_to_lowercase_for_idna_invalid_label(self) -> None:
        # Underscores are common in real-world internal hostnames but are not
        # valid per strict IDNA rules; normalization must not raise on them.
        assert normalize_hostname("Has_Underscore.example.com") == "has_underscore.example.com"


class TestIpLiteralTargets:
    def test_ip_literal_target_matches_exact_ip(self) -> None:
        matcher = ScopeMatcher(targets=["10.0.0.5"])
        result = matcher.match("10.0.0.5")
        assert result.matched is True
        assert result.matched_target == "10.0.0.5"

    def test_ip_literal_target_does_not_match_unrelated_ip(self) -> None:
        matcher = ScopeMatcher(targets=["10.0.0.5"])
        assert matcher.match("10.0.0.6").matched is False

    def test_domain_target_does_not_match_an_ip_literal_hostname(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("10.0.0.5").matched is False


class TestControlCharacterAndEmptyInputs:
    def test_null_byte_in_hostname_does_not_match_and_does_not_raise(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        result = matcher.match("exa\x00mple.com")
        assert result.matched is False

    def test_empty_hostname_against_nonempty_target_does_not_match(self) -> None:
        matcher = ScopeMatcher(targets=["example.com"])
        assert matcher.match("").matched is False

    def test_empty_string_target_matches_only_empty_hostname(self) -> None:
        # Documents current, correct behavior: an empty --target string
        # (however it might arise — a blank line in a --target-file that
        # somehow slipped past the comment/blank-line filter, or an
        # operator typo) matches only an empty hostname, never a real one.
        matcher = ScopeMatcher(targets=[""])
        assert matcher.match("").matched is True
        assert matcher.match("example.com").matched is False


class TestBareWildcardTarget:
    def test_bare_wildcard_target_matches_any_hostname(self) -> None:
        # Documents current behavior, deliberately pinned rather than left
        # implicit: a "*" target (reachable via a plain --target flag, not
        # just --target-all) matches essentially any hostname, since
        # fnmatch's "*" is not dot-aware and therefore isn't scoped to a
        # single label. This is the single-target equivalent of
        # --target-all and is worth a test precisely because it's
        # security-relevant scope-widening behavior that should never
        # change silently.
        matcher = ScopeMatcher(targets=["*"])
        assert matcher.match("anything.example.com").matched is True
        assert matcher.match("totally-unrelated-domain.org").matched is True
