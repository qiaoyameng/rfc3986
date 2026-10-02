"""Configurable URI normalization."""

from __future__ import annotations

import dataclasses
import typing as t

from . import exceptions
from . import misc
from . import normalizers
from .uri import URIReference


@dataclasses.dataclass(frozen=True)
class NormalizationTransformation:
    """A single transformation performed while normalizing a URI."""

    rule: str
    component: str
    before: t.Optional[str]
    after: t.Optional[str]


@dataclasses.dataclass(frozen=True)
class NormalizationResult:
    """A normalized URI and the transformations used to produce it."""

    reference: URIReference
    transformations: t.Tuple[NormalizationTransformation, ...]

    @property
    def uri(self) -> str:
        """Return the normalized reference as a URI string."""
        return self.reference.unsplit()


@dataclasses.dataclass(frozen=True)
class NormalizationProfile:
    """Select the normalization rules applied to a URI reference.

    All rules are opt-in. Profiles are immutable and do not retain state
    from URIs to which they are applied.
    """

    scheme: bool = False
    authority: bool = False
    remove_dot_segments: bool = False
    percent_case: bool = False
    decode_unreserved: bool = False

    def __post_init__(self) -> None:
        """Reject combinations of rules with order-dependent results."""
        if self.remove_dot_segments and self.decode_unreserved:
            raise exceptions.NormalizationProfileError(
                "decode_unreserved cannot be combined with "
                "remove_dot_segments because encoded dot segments would "
                "then be removed only after decoding."
            )

    def apply(self, reference: URIReference) -> NormalizationResult:
        """Apply this profile to ``reference`` without changing it."""
        transformations: t.List[NormalizationTransformation] = []

        scheme = reference.scheme
        if self.scheme and scheme is not None:
            normalized_scheme = normalizers.normalize_scheme(scheme)
            self._record(
                transformations,
                "scheme",
                "scheme",
                scheme,
                normalized_scheme,
            )
            scheme = normalized_scheme

        authority = self._normalize_authority(reference, transformations)

        path = reference.path
        if path is not None:
            if self.percent_case:
                normalized_path = normalizers.normalize_percent_characters(
                    path
                )
                self._record(
                    transformations,
                    "percent_case",
                    "path",
                    path,
                    normalized_path,
                )
                path = normalized_path
            if self.remove_dot_segments:
                normalized_path = normalizers.remove_dot_segments(path)
                self._record(
                    transformations,
                    "remove_dot_segments",
                    "path",
                    path,
                    normalized_path,
                )
                path = normalized_path
            if self.decode_unreserved:
                normalized_path = decode_unreserved_characters(path)
                self._record(
                    transformations,
                    "decode_unreserved",
                    "path",
                    path,
                    normalized_path,
                )
                path = normalized_path

        query = self._normalize_simple_component(
            "query", reference.query, transformations
        )
        fragment = self._normalize_simple_component(
            "fragment", reference.fragment, transformations
        )

        return NormalizationResult(
            reference=type(reference)(
                scheme,
                authority,
                path,
                query,
                fragment,
                reference.encoding,
            ),
            transformations=tuple(transformations),
        )

    def _normalize_authority(
        self,
        reference: URIReference,
        transformations: t.List[NormalizationTransformation],
    ) -> t.Optional[str]:
        authority = reference.authority
        if authority is None:
            return None

        info = reference.authority_info()
        userinfo = info["userinfo"]
        host = info["host"]
        port = info["port"]

        result = ""
        if userinfo is not None:
            normalized_userinfo = self._normalize_userinfo(
                userinfo, transformations
            )
            result += normalized_userinfo + "@"

        if host is not None:
            result += self._normalize_host(host, transformations)

        if port is not None:
            result += ":" + port

        if result != authority:
            changed_authority_parts = {
                transformation.component
                for transformation in transformations
                if transformation.component in {"userinfo", "host"}
            }
            rules = {
                transformation.rule
                for transformation in transformations
                if transformation.component in changed_authority_parts
            }
            if self.authority and "authority" in rules:
                rule = "authority"
            elif "percent_case" in rules:
                rule = "percent_case"
            else:
                rule = "decode_unreserved"
            self._record(
                transformations,
                rule,
                "authority",
                authority,
                result,
            )

        return result

    def _normalize_userinfo(
        self,
        userinfo: str,
        transformations: t.List[NormalizationTransformation],
    ) -> str:
        result = userinfo
        if self.authority or self.percent_case:
            cased_userinfo = normalizers.normalize_percent_characters(result)
            self._record(
                transformations,
                "percent_case",
                "userinfo",
                result,
                cased_userinfo,
            )
            result = cased_userinfo
        if self.decode_unreserved:
            decoded_userinfo = decode_unreserved_characters(result)
            self._record(
                transformations,
                "decode_unreserved",
                "userinfo",
                result,
                decoded_userinfo,
            )
            result = decoded_userinfo
        return result

    def _normalize_host(
        self,
        host: str,
        transformations: t.List[NormalizationTransformation],
    ) -> str:
        result = host
        if self.percent_case:
            cased_host = normalize_host_percent_characters(result)
            self._record(
                transformations,
                "percent_case",
                "host",
                result,
                cased_host,
            )
            result = cased_host
        if self.decode_unreserved and not misc.IPv6_MATCHER.match(result):
            decoded_host = decode_unreserved_characters(result)
            self._record(
                transformations,
                "decode_unreserved",
                "host",
                result,
                decoded_host,
            )
            result = decoded_host
        if self.authority:
            authority_host = normalizers.normalize_host(result)
            self._record(
                transformations,
                "authority",
                "host",
                result,
                authority_host,
            )
            result = authority_host
        return result

    def _normalize_simple_component(
        self,
        component: str,
        value: t.Optional[str],
        transformations: t.List[NormalizationTransformation],
    ) -> t.Optional[str]:
        if value is None:
            return None

        result = value
        if self.percent_case:
            cased_value = normalizers.normalize_percent_characters(result)
            self._record(
                transformations,
                "percent_case",
                component,
                result,
                cased_value,
            )
            result = cased_value
        if self.decode_unreserved:
            decoded_value = decode_unreserved_characters(result)
            self._record(
                transformations,
                "decode_unreserved",
                component,
                result,
                decoded_value,
            )
            result = decoded_value
        return result

    @staticmethod
    def _record(
        transformations: t.List[NormalizationTransformation],
        rule: str,
        component: str,
        before: t.Optional[str],
        after: t.Optional[str],
    ) -> None:
        if before != after:
            transformations.append(
                NormalizationTransformation(
                    rule=rule,
                    component=component,
                    before=before,
                    after=after,
                )
            )


def normalize_host_percent_characters(host: str) -> str:
    """Upper-case percent escapes in a host without changing its zone ID."""
    if not misc.IPv6_MATCHER.match(host):
        return normalizers.normalize_percent_characters(host)

    percent = host.find("%")
    if percent == -1:
        return host

    zone_id = host[percent:]
    if zone_id.startswith("%25"):
        return host[:percent] + normalizers.normalize_percent_characters(
            zone_id
        )
    return host


def decode_unreserved_characters(component: str) -> str:
    """Decode percent escapes that represent unreserved characters."""

    def decode_match(match: t.Match[str]) -> str:
        character = chr(int(match.group(0)[1:], 16))
        if character in misc.UNRESERVED_CHARS:
            return character
        return match.group(0)

    return normalizers.PERCENT_MATCHER.sub(decode_match, component)
