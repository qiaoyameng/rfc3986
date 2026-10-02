"""Tests for explicit normalization profiles.

The comparison examples below document, for reserved characters, duplicate
query keys, and default ports, exactly which representations a profile
unifies and which it keeps distinct. Every example also proves that
applying the same profile a second time changes nothing further.
"""

import pytest

from rfc3986 import NormalizationProfile
from rfc3986 import uri_reference
from rfc3986.exceptions import ConflictingProfileOptions
from rfc3986.profiles import Transformation
from rfc3986.profiles import decode_unreserved_characters


def unsplit(uri_string, profile):
    return profile.apply(uri_reference(uri_string)).uri.unsplit()


def assert_idempotent(profile, uri_string):
    """Prove a second application of the profile changes nothing."""
    once = profile.apply(uri_reference(uri_string))
    twice = profile.apply(once.uri)
    assert twice.uri == once.uri
    assert twice.uri.unsplit() == once.uri.unsplit()
    # No transformations are recorded the second time around.
    assert twice.transformations == ()
    return once


class TestDefaultProfile:
    def test_matches_normalize(self):
        """The default profile agrees with URIReference.normalize()."""
        uri_string = "HTTP://User@Example.COM:8080/a/./b/../c%7d?x=%3a#%df"
        profile = NormalizationProfile()
        result = profile.apply(uri_reference(uri_string))
        assert result.uri == uri_reference(uri_string).normalize()
        assert result.uri.unsplit() == (
            uri_reference(uri_string).normalize().unsplit()
        )

    def test_normalize_method_is_unchanged(self):
        """normalize() keeps its historical behaviour and defaults."""
        uri = uri_reference("HTTP://Example.COM/%7e?q=%2f+%7E")
        assert uri.normalize().unsplit() == "http://example.com/%7E?q=%2F+%7E"

    def test_does_not_sort_query(self):
        profile = NormalizationProfile()
        result = profile.apply(uri_reference("http://e.com/?b=2&a=1"))
        assert result.uri.query == "b=2&a=1"
        assert result.transformations == ()

    def test_does_not_decode_plus_as_space(self):
        profile = NormalizationProfile(decode_unreserved=True)
        result = profile.apply(uri_reference("http://e.com/?q=a+b"))
        assert result.uri.query == "q=a+b"
        assert result.transformations == ()


class TestIndividualRules:
    def test_scheme_case_preserved_when_disabled(self):
        profile = NormalizationProfile(lowercase_scheme=False)
        assert unsplit("HTTP://example.com/", profile).startswith("HTTP://")

    def test_authority_preserved_when_disabled(self):
        profile = NormalizationProfile(normalize_authority=False)
        result = profile.apply(uri_reference("http://User@Example.COM/"))
        assert result.uri.authority == "User@Example.COM"
        assert all(t.component != "authority" for t in result.transformations)

    def test_dot_segments_preserved_when_disabled(self):
        profile = NormalizationProfile(remove_dot_segments=False)
        result = profile.apply(uri_reference("http://e.com/a/./b/../c"))
        assert result.uri.path == "/a/./b/../c"

    def test_percent_case_preserved_when_disabled(self):
        profile = NormalizationProfile(normalize_percent_case=False)
        result = profile.apply(uri_reference("http://e.com/%3a%df"))
        assert result.uri.path == "/%3a%df"

    def test_unreserved_decoding_opt_in(self):
        profile = NormalizationProfile(decode_unreserved=True)
        result = profile.apply(uri_reference("http://e.com/%7E%41/%2F"))
        assert result.uri.path == "/~A/%2F"

    def test_decode_unreserved_characters(self):
        assert decode_unreserved_characters("%7e%41%2f%25") == "~A%2f%25"


class TestConflictingRules:
    def test_strip_default_port_requires_authority_normalization(self):
        with pytest.raises(ConflictingProfileOptions):
            NormalizationProfile(
                normalize_authority=False, strip_default_port=True
            )

    def test_decode_unreserved_requires_percent_case_normalization(self):
        with pytest.raises(ConflictingProfileOptions):
            NormalizationProfile(
                normalize_percent_case=False, decode_unreserved=True
            )

    def test_non_conflicting_combinations_are_accepted(self):
        NormalizationProfile(normalize_authority=False)
        NormalizationProfile(normalize_percent_case=False)
        NormalizationProfile(strip_default_port=True)
        NormalizationProfile(decode_unreserved=True)


class TestTransformationRecord:
    def test_records_only_components_that_changed(self):
        profile = NormalizationProfile()
        result = profile.apply(
            uri_reference("HTTP://Example.COM/a/./b?x=%3a#frag")
        )
        assert result.transformations == (
            Transformation("scheme", "HTTP", "http"),
            Transformation("authority", "Example.COM", "example.com"),
            Transformation("path", "/a/./b", "/a/b"),
            Transformation("query", "x=%3a", "x=%3A"),
        )
        assert result.uri.unsplit() == "http://example.com/a/b?x=%3A#frag"

    def test_records_nothing_for_an_already_normalized_uri(self):
        profile = NormalizationProfile()
        result = profile.apply(uri_reference("http://example.com/b?x=%3A"))
        assert result.transformations == ()
        assert result.uri.unsplit() == "http://example.com/b?x=%3A"

    def test_records_default_port_removal(self):
        profile = NormalizationProfile(strip_default_port=True)
        result = profile.apply(uri_reference("http://example.com:80/"))
        assert result.transformations == (
            Transformation("authority", "example.com:80", "example.com"),
        )


class TestReservedCharacterComparison:
    """Reserved characters stay encoded; unreserved ones may be unified."""

    uri_string = "http://example.com/%2F%7E?q=%2f%7e"

    def test_default_profile_keeps_reserved_and_unreserved_distinct(self):
        once = assert_idempotent(NormalizationProfile(), self.uri_string)
        # Percent case is unified, but nothing is decoded: "%2F" stays
        # distinct from "/" and "%7E" stays distinct from "~".
        assert once.uri.unsplit() == "http://example.com/%2F%7E?q=%2F%7E"
        assert once.uri != uri_reference("http://example.com//~?q=/~")

    def test_decode_unreserved_unifies_only_unreserved_characters(self):
        profile = NormalizationProfile(decode_unreserved=True)
        once = assert_idempotent(profile, self.uri_string)
        # "%7E" and "~" now denote the same URI; "%2F" and "/" do not.
        assert once.uri.unsplit() == "http://example.com/%2F~?q=%2F~"
        assert once.uri == uri_reference("http://example.com/%2F~?q=%2F~")
        assert once.uri.path != uri_reference(
            "http://example.com//~"
        ).path


class TestDuplicateQueryKeyComparison:
    """Query keys are never sorted, merged, or deduplicated."""

    def test_duplicate_keys_are_preserved_verbatim(self):
        profile = NormalizationProfile()
        once = assert_idempotent(profile, "http://e.com/?a=1&a=2&a=1")
        assert once.uri.query == "a=1&a=2&a=1"

    def test_key_order_still_distinguishes_uris(self):
        profile = NormalizationProfile()
        first = profile.apply(uri_reference("http://e.com/?a=1&a=2"))
        second = profile.apply(uri_reference("http://e.com/?a=2&a=1"))
        assert first.uri != second.uri
        assert first.uri.query != second.uri.query

    def test_plus_and_percent_encoded_space_stay_distinct(self):
        profile = NormalizationProfile(decode_unreserved=True)
        plus = profile.apply(uri_reference("http://e.com/?q=a+b"))
        space = profile.apply(uri_reference("http://e.com/?q=a%20b"))
        assert plus.uri.query == "q=a+b"
        assert space.uri.query == "q=a%20b"
        assert plus.uri != space.uri


class TestDefaultPortComparison:
    """Default ports are kept unless stripping is explicitly requested."""

    def test_default_profile_keeps_explicit_default_port_distinct(self):
        profile = NormalizationProfile()
        explicit = assert_idempotent(profile, "http://example.com:80/")
        implicit = assert_idempotent(profile, "http://example.com/")
        assert explicit.uri.authority == "example.com:80"
        assert explicit.uri != implicit.uri

    def test_strip_default_port_unifies_representations(self):
        profile = NormalizationProfile(strip_default_port=True)
        explicit = assert_idempotent(profile, "HTTP://Example.COM:80/")
        implicit = assert_idempotent(profile, "http://example.com/")
        assert explicit.uri == implicit.uri
        assert explicit.uri.authority == "example.com"

    def test_non_default_port_is_never_stripped(self):
        profile = NormalizationProfile(strip_default_port=True)
        once = assert_idempotent(profile, "http://example.com:8080/")
        assert once.uri.authority == "example.com:8080"

    def test_port_stripping_is_scheme_aware(self):
        profile = NormalizationProfile(strip_default_port=True)
        https = assert_idempotent(profile, "https://example.com:80/")
        assert https.uri.authority == "example.com:80"


class TestProfileReuse:
    def test_profile_is_reusable_and_stateless(self):
        """A profile never retains state from the previous URI."""
        profile = NormalizationProfile(
            decode_unreserved=True, strip_default_port=True
        )
        first_uri = "HTTP://Example.COM:80/a/./%7e?x=%3a"
        second_uri = "https://User@Example.COM:443/b/../c?q=%2f"

        first = profile.apply(uri_reference(first_uri))
        second = profile.apply(uri_reference(second_uri))
        first_again = profile.apply(uri_reference(first_uri))

        assert first.uri.unsplit() == "http://example.com/a/~?x=%3A"
        assert second.uri.unsplit() == "https://User@example.com/c?q=%2F"
        # Reapplying to the first input reproduces the first result
        # exactly: nothing leaked from the second URI.
        assert first_again == first
        assert first_again.uri == first.uri
        assert first_again.transformations == first.transformations

    def test_profile_is_immutable(self):
        profile = NormalizationProfile()
        with pytest.raises(Exception):
            profile.decode_unreserved = True

    def test_input_reference_is_not_mutated(self):
        profile = NormalizationProfile(
            decode_unreserved=True, strip_default_port=True
        )
        reference = uri_reference("HTTP://Example.COM:80/%7e")
        before = reference.unsplit()
        profile.apply(reference)
        assert reference.unsplit() == before
