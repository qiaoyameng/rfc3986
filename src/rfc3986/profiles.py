"""Module with explicit, configurable normalization profiles.

Different consumers of URIs need different normalization guarantees. For
example, a cache may want host casing unified while a signature verifier
must keep the query string byte-for-byte intact. A
:class:`NormalizationProfile` lets callers opt into each transformation
individually without changing the default behaviour of
:meth:`rfc3986.uri.URIReference.normalize`.

Profiles are immutable and stateless: they can be reused across any number
of URIs and never retain information about previously normalized input.
"""

# Copyright (c) 2014 Rackspace
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import dataclasses
import typing as t

from . import exceptions
from . import normalizers
from . import uri

#: Characters that RFC 3986 Section 2.3 defines as unreserved. Percent-encoded
#: octets in this set may be safely decoded without changing the meaning of
#: the URI.
UNRESERVED_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-._~"
)

#: Default ports for schemes where the port may be omitted without changing
#: the meaning of the authority component.
DEFAULT_PORTS = {
    "http": "80",
    "https": "443",
    "ftp": "21",
    "ssh": "22",
    "telnet": "23",
    "smtp": "25",
    "ws": "80",
    "wss": "443",
}


def decode_unreserved_characters(s: str) -> str:
    """Decode percent-encoded unreserved characters.

    For example, ``"%7Efoo%41"`` becomes ``"~fooA"`` while reserved
    encodings such as ``"%2F"`` are left untouched.
    """

    def replace(match: "t.Match[str]") -> str:
        encoding = match.group(0)
        character = chr(int(encoding[1:], 16))
        if character in UNRESERVED_CHARACTERS:
            return character
        return encoding

    return normalizers.PERCENT_MATCHER.sub(replace, s)


class Transformation(t.NamedTuple):
    """Record of a single transformation applied to a URI component."""

    component: str
    before: t.Optional[str]
    after: t.Optional[str]


class ProfileNormalizationResult(t.NamedTuple):
    """Result of applying a :class:`NormalizationProfile` to a URI.

    .. attribute:: uri

        The normalized URI reference.

    .. attribute:: transformations

        A tuple of :class:`Transformation` records describing every
        component that was actually changed, in the order the changes were
        applied. Components that were already normalized (or that the
        profile leaves alone) do not appear here, so an empty tuple means
        the URI was already stable under this profile.
    """

    uri: "uri.URIReference"
    transformations: t.Tuple[Transformation, ...]


@dataclasses.dataclass(frozen=True)
class NormalizationProfile:
    """An explicit, reusable set of URI normalization rules.

    Every rule is independent and defaults to the same behaviour as
    :meth:`rfc3986.uri.URIReference.normalize`, except where noted. A
    profile never sorts query parameters and never decodes ``+`` into a
    space, so the query string is preserved as-is unless percent-encoding
    rules apply to it.

    Profiles are frozen dataclasses: they hold no per-URI state and can be
    shared and reused safely.

    :param lowercase_scheme: Lowercase the scheme component.
    :param normalize_authority: Lowercase the host and normalize
        percent-encoding inside the userinfo.
    :param remove_dot_segments: Remove ``.`` and ``..`` segments from the
        path as described in RFC 3986 Section 5.2.4.
    :param normalize_percent_case: Uppercase the hexadecimal digits of
        percent-encoded octets (e.g. ``%3a`` becomes ``%3A``).
    :param decode_unreserved: Decode percent-encoded unreserved characters
        (e.g. ``%7E`` becomes ``~``). Reserved characters such as ``%2F``
        are never decoded. Defaults to ``False`` because it changes more
        representations than :meth:`~rfc3986.uri.URIReference.normalize`.
    :param strip_default_port: Remove the port from the authority when it
        matches the scheme's default port (e.g. ``:80`` for ``http``).
        Requires ``normalize_authority`` and defaults to ``False``.
    :raises rfc3986.exceptions.ConflictingProfileOptions: if the selected
        rules conflict with each other.
    """

    lowercase_scheme: bool = True
    normalize_authority: bool = True
    remove_dot_segments: bool = True
    normalize_percent_case: bool = True
    decode_unreserved: bool = False
    strip_default_port: bool = False

    def __post_init__(self) -> None:
        """Reject combinations of rules that cannot be satisfied."""
        if self.strip_default_port and not self.normalize_authority:
            raise exceptions.ConflictingProfileOptions(
                "strip_default_port requires normalize_authority: the port "
                "cannot be reliably removed without normalizing the "
                "authority component."
            )
        if self.decode_unreserved and not self.normalize_percent_case:
            raise exceptions.ConflictingProfileOptions(
                "decode_unreserved requires normalize_percent_case: "
                "decoding some percent-encodings while leaving the "
                "remaining ones unnormalized would produce inconsistent "
                "output."
            )

    def apply(
        self, reference: "uri.URIReference"
    ) -> ProfileNormalizationResult:
        """Apply this profile to a URI reference.

        This is a pure operation: the profile keeps no state between
        calls and the input reference is never mutated.

        :param reference: The URI reference to normalize.
        :returns: The normalized reference along with the transformations
            that were actually performed.
        :rtype: ProfileNormalizationResult
        """
        transformations = []

        scheme = reference.scheme
        if self.lowercase_scheme and scheme:
            new_scheme = normalizers.normalize_scheme(scheme)
            if new_scheme != scheme:
                transformations.append(
                    Transformation("scheme", scheme, new_scheme)
                )
            scheme = new_scheme

        authority = reference.authority
        if self.normalize_authority and authority is not None:
            userinfo, host, port = (
                reference.userinfo,
                reference.host,
                reference.port,
            )
            if self.strip_default_port and port is not None:
                default_port = DEFAULT_PORTS.get((scheme or "").lower())
                if default_port is not None and port == default_port:
                    port = None
            new_authority = normalizers.normalize_authority(
                (userinfo, host, port)
            )
            if new_authority != authority:
                transformations.append(
                    Transformation("authority", authority, new_authority)
                )
            authority = new_authority

        path = reference.path
        if path:
            new_path = self._normalize_percent_encoded(path)
            if self.remove_dot_segments:
                new_path = normalizers.remove_dot_segments(new_path)
            if new_path != path:
                transformations.append(
                    Transformation("path", path, new_path)
                )
            path = new_path

        query = reference.query
        if query:
            new_query = self._normalize_percent_encoded(query)
            if new_query != query:
                transformations.append(
                    Transformation("query", query, new_query)
                )
            query = new_query

        fragment = reference.fragment
        if fragment:
            new_fragment = self._normalize_percent_encoded(fragment)
            if new_fragment != fragment:
                transformations.append(
                    Transformation("fragment", fragment, new_fragment)
                )
            fragment = new_fragment

        normalized = uri.URIReference(
            scheme,
            authority,
            path,
            query,
            fragment,
            reference.encoding,
        )
        return ProfileNormalizationResult(
            normalized, tuple(transformations)
        )

    def _normalize_percent_encoded(self, component: str) -> str:
        """Apply the percent-encoding rules selected for this profile."""
        if self.normalize_percent_case:
            component = normalizers.normalize_percent_characters(component)
        if self.decode_unreserved:
            component = decode_unreserved_characters(component)
        return component
