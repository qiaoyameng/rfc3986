# Copyright (c) 2017 Ian Stapleton Cordasco
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
"""Module containing the logic for the URIBuilder object."""

import re
import typing as t
from urllib.parse import parse_qsl
from urllib.parse import quote as urlquote
from urllib.parse import urlencode

from . import normalizers
from . import uri
from . import uri_reference
from ._typing_compat import Self as _Self

# Modified from urllib.parse in typeshed.
_QueryType = t.Union[
    t.Mapping[t.Any, t.Any],
    t.Mapping[t.Any, t.Sequence[t.Any]],
    # Substituting List for Sequence since one of the add/extend methods
    # below has a runtime isinstance check for list.
    t.List[t.Tuple[t.Any, t.Any]],
    t.List[t.Tuple[t.Any, t.Sequence[t.Any]]],
]


# Matches a '%' that is not followed by exactly two hexadecimal digits.
_INVALID_PERCENT_MATCHER = re.compile(r"%(?![0-9A-Fa-f]{2})")

# Characters that may not appear raw in a single path segment without
# changing the structure of the resulting URI.
_SEGMENT_DELIMITERS = "/?#"


def _encode_path_segment(segment: str) -> str:
    """Percent-encode raw data so that it fits in exactly one segment.

    Everything outside of the unreserved characters is encoded, including
    '/', '?', '#', and '%', so the value can never alter the structure of
    the URI it is added to. The literal segments '.' and '..' are encoded
    as well so they are not removed by dot-segment normalization.
    """
    if segment == ".":
        return "%2E"
    if segment == "..":
        return "%2E%2E"
    return urlquote(segment, safe="")


def _validate_encoded_path_segment(segment: str) -> None:
    """Validate a path segment that is already percent-encoded.

    Raises a ValueError if the segment contains a malformed percent
    sequence (which would otherwise be encoded a second time), a raw
    delimiter that would break out of the segment, or a raw '.' or '..'
    segment that would be removed by dot-segment normalization.
    """
    if _INVALID_PERCENT_MATCHER.search(segment):
        raise ValueError(
            "Encoded path segments must only contain valid percent "
            "sequences, i.e., '%' followed by two hexadecimal digits. "
            "You provided {!r}".format(segment)
        )
    for delimiter in _SEGMENT_DELIMITERS:
        if delimiter in segment:
            raise ValueError(
                "Encoded path segments must not contain a raw {!r} "
                "character. Percent-encode it or use add_path_segment to "
                "add raw data. You provided {!r}".format(delimiter, segment)
            )
    if segment in (".", ".."):
        raise ValueError(
            "Encoded path segments must not be a raw {!r} segment as it "
            "would be removed by dot-segment normalization. Use {!r} "
            "instead.".format(segment, _encode_path_segment(segment))
        )


class URIBuilder:
    """Object to aid in building up a URI Reference from parts.

    .. note::

        This object should be instantiated by the user, but it's recommended
        that it is not provided with arguments. Instead, use the available
        method to populate the fields.

    """

    def __init__(
        self,
        scheme: t.Optional[str] = None,
        userinfo: t.Optional[str] = None,
        host: t.Optional[str] = None,
        port: t.Optional[t.Union[int, str]] = None,
        path: t.Optional[str] = None,
        query: t.Optional[str] = None,
        fragment: t.Optional[str] = None,
    ):
        """Initialize our URI builder.

        :param str scheme:
            (optional)
        :param str userinfo:
            (optional)
        :param str host:
            (optional)
        :param int | str port:
            (optional)
        :param str path:
            (optional)
        :param str query:
            (optional)
        :param str fragment:
            (optional)
        """
        self.scheme = scheme
        self.userinfo = userinfo
        self.host = host
        self.port = str(port) if port is not None else port
        self.path = path
        self.query = query
        self.fragment = fragment

    def __repr__(self):
        """Provide a convenient view of our builder object."""
        formatstr = (
            "URIBuilder(scheme={b.scheme}, userinfo={b.userinfo}, "
            "host={b.host}, port={b.port}, path={b.path}, "
            "query={b.query}, fragment={b.fragment})"
        )
        return formatstr.format(b=self)

    @classmethod
    def from_uri(cls, reference: t.Union["uri.URIReference", str]) -> _Self:
        """Initialize the URI builder from another URI.

        Takes the given URI reference and creates a new URI builder instance
        populated with the values from the reference. If given a string it will
        try to convert it to a reference before constructing the builder.
        """
        if not isinstance(reference, uri.URIReference):
            reference = uri_reference(reference)
        return cls(
            scheme=reference.scheme,
            userinfo=reference.userinfo,
            host=reference.host,
            port=reference.port,
            path=reference.path,
            query=reference.query,
            fragment=reference.fragment,
        )

    def add_scheme(self, scheme: str) -> "URIBuilder":
        """Add a scheme to our builder object.

        After normalizing, this will generate a new URIBuilder instance with
        the specified scheme and all other attributes the same.

        .. code-block:: python

            >>> URIBuilder().add_scheme('HTTPS')
            URIBuilder(scheme='https', userinfo=None, host=None, port=None,
                    path=None, query=None, fragment=None)

        """
        scheme = normalizers.normalize_scheme(scheme)
        return URIBuilder(
            scheme=scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_credentials(
        self,
        username: str,
        password: t.Optional[str],
    ) -> "URIBuilder":
        """Add credentials as the userinfo portion of the URI.

        .. code-block:: python

            >>> URIBuilder().add_credentials('root', 's3crete')
            URIBuilder(scheme=None, userinfo='root:s3crete', host=None,
                    port=None, path=None, query=None, fragment=None)

            >>> URIBuilder().add_credentials('root', None)
            URIBuilder(scheme=None, userinfo='root', host=None,
                    port=None, path=None, query=None, fragment=None)
        """
        if username is None:
            raise ValueError("Username cannot be None")
        userinfo = normalizers.normalize_username(username)

        if password is not None:
            userinfo = "{}:{}".format(
                userinfo,
                normalizers.normalize_password(password),
            )

        return URIBuilder(
            scheme=self.scheme,
            userinfo=userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_host(self, host: str) -> "URIBuilder":
        """Add hostname to the URI.

        .. code-block:: python

            >>> URIBuilder().add_host('google.com')
            URIBuilder(scheme=None, userinfo=None, host='google.com',
                    port=None, path=None, query=None, fragment=None)

        """
        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=normalizers.normalize_host(host),
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_port(self, port: t.Union[int, str]) -> "URIBuilder":
        """Add port to the URI.

        .. code-block:: python

            >>> URIBuilder().add_port(80)
            URIBuilder(scheme=None, userinfo=None, host=None, port='80',
                    path=None, query=None, fragment=None)

            >>> URIBuilder().add_port(443)
            URIBuilder(scheme=None, userinfo=None, host=None, port='443',
                    path=None, query=None, fragment=None)

        """
        port_int = int(port)
        if port_int < 0:
            raise ValueError(
                "ports are not allowed to be negative. You provided {}".format(
                    port_int,
                )
            )
        if port_int > 65535:
            raise ValueError(
                "ports are not allowed to be larger than 65535. "
                "You provided {}".format(
                    port_int,
                )
            )

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=f"{port_int}",
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_path(self, path: str) -> "URIBuilder":
        """Add a path to the URI.

        .. code-block:: python

            >>> URIBuilder().add_path('sigmavirus24/rfc3985')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/sigmavirus24/rfc3986', query=None, fragment=None)

            >>> URIBuilder().add_path('/checkout.php')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/checkout.php', query=None, fragment=None)

        """
        if not path.startswith("/"):
            path = f"/{path}"

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=normalizers.normalize_path(path),
            query=self.query,
            fragment=self.fragment,
        )

    def extend_path(self, path: str) -> "URIBuilder":
        """Extend the existing path value with the provided value.

        .. versionadded:: 1.5.0

        .. code-block:: python

            >>> URIBuilder(path="/users").extend_path("/sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

            >>> URIBuilder(path="/users/").extend_path("/sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

            >>> URIBuilder(path="/users/").extend_path("sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

            >>> URIBuilder(path="/users").extend_path("sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

        """
        existing_path = self.path or ""
        path = "{}/{}".format(existing_path.rstrip("/"), path.lstrip("/"))

        return self.add_path(path)

    def add_path_segment(self, segment: str) -> "URIBuilder":
        """Append a single path segment, encoding the value as raw data.

        .. versionadded:: 2.1.0

        The segment is treated as opaque data: every character outside of
        the unreserved set (including ``/``, ``?``, ``#``, and ``%``) is
        percent-encoded, so the value always occupies exactly one path
        segment and can never alter the structure of the URI. This makes
        it safe to use values such as object keys that may contain
        slashes, question marks, or literal percent signs. Decoding the
        resulting segment (e.g., with ``urllib.parse.unquote``) returns
        the original value.

        An empty segment is allowed and appends an empty segment, which
        is how a trailing slash is produced. The literal segments ``.``
        and ``..`` are encoded (``%2E`` and ``%2E%2E``) so they survive
        dot-segment normalization as data.

        This method does not parse the value as a relative path; use
        :meth:`extend_path` for that. If the value is already
        percent-encoded, use :meth:`add_encoded_path_segment` instead to
        avoid double-encoding.

        .. code-block:: python

            >>> URIBuilder(path="/objects").add_path_segment("a/b?c#d")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/objects/a%2Fb%3Fc%23d', query=None,
                    fragment=None)

            >>> URIBuilder(path="/objects").add_path_segment("100%")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/objects/100%25', query=None, fragment=None)

            >>> URIBuilder(path="/objects").add_path_segment("")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/objects/', query=None, fragment=None)

        """
        return self._append_path_segment(_encode_path_segment(segment))

    def add_encoded_path_segment(self, segment: str) -> "URIBuilder":
        """Append a single path segment that is already percent-encoded.

        .. versionadded:: 2.1.0

        This is the explicit entry point for values that must be kept
        as-is because they are already percent-encoded. The value is
        validated before being appended so that it cannot be
        double-encoded or break out of its segment:

        - Every ``%`` must be followed by two hexadecimal digits,
          otherwise a :exc:`ValueError` is raised.
        - Raw ``/``, ``?``, and ``#`` characters are rejected, as they
          would change the structure of the URI.
        - Raw ``.`` and ``..`` segments are rejected, as they would be
          removed by dot-segment normalization; use ``%2E`` and
          ``%2E%2E`` instead.

        An empty segment is allowed and appends an empty segment, which
        is how a trailing slash is produced. Valid percent sequences are
        normalized to upper-case. To add raw, unencoded data, use
        :meth:`add_path_segment` instead.

        .. code-block:: python

            >>> URIBuilder(path="/objects").add_encoded_path_segment("a%2Fb")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/objects/a%2Fb', query=None, fragment=None)

            >>> URIBuilder(path="/objects").add_encoded_path_segment("a/b")
            Traceback (most recent call last):
            ...
            ValueError: Encoded path segments must not contain a raw ...

        """
        _validate_encoded_path_segment(segment)
        segment = normalizers.normalize_percent_characters(segment)
        return self._append_path_segment(segment)

    def _append_path_segment(self, encoded_segment: str) -> "URIBuilder":
        """Append an already-encoded segment to the existing path.

        The existing path, query, fragment, and authority components are
        preserved exactly as they are.
        """
        existing_path = self.path or ""
        path = "{}/{}".format(existing_path.rstrip("/"), encoded_segment)

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_query_from(self, query_items: _QueryType) -> "URIBuilder":
        """Generate and add a query a dictionary or list of tuples.

        .. code-block:: python

            >>> URIBuilder().add_query_from({'a': 'b c'})
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c', fragment=None)

            >>> URIBuilder().add_query_from([('a', 'b c')])
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c', fragment=None)

        """
        query = normalizers.normalize_query(urlencode(query_items))

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=query,
            fragment=self.fragment,
        )

    def extend_query_with(self, query_items: _QueryType) -> "URIBuilder":
        """Extend the existing query string with the new query items.

        .. versionadded:: 1.5.0

        .. code-block:: python

            >>> URIBuilder(query='a=b+c').extend_query_with({'a': 'b c'})
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c&a=b+c', fragment=None)

            >>> URIBuilder(query='a=b+c').extend_query_with([('a', 'b c')])
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c&a=b+c', fragment=None)
        """
        original_query_items = parse_qsl(self.query or "")
        if not isinstance(query_items, list):
            query_items = list(query_items.items())

        return self.add_query_from(original_query_items + query_items)

    def add_query(self, query: str) -> "URIBuilder":
        """Add a pre-formated query string to the URI.

        .. code-block:: python

            >>> URIBuilder().add_query('a=b&c=d')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b&c=d', fragment=None)

        """
        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=normalizers.normalize_query(query),
            fragment=self.fragment,
        )

    def add_fragment(self, fragment: str) -> "URIBuilder":
        """Add a fragment to the URI.

        .. code-block:: python

            >>> URIBuilder().add_fragment('section-2.6.1')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query=None, fragment='section-2.6.1')

        """
        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=normalizers.normalize_fragment(fragment),
        )

    def finalize(self) -> "uri.URIReference":
        """Create a URIReference from our builder.

        .. code-block:: python

            >>> URIBuilder().add_scheme('https').add_host('github.com'
            ...     ).add_path('sigmavirus24/rfc3986').finalize().unsplit()
            'https://github.com/sigmavirus24/rfc3986'

            >>> URIBuilder().add_scheme('https').add_host('github.com'
            ...     ).add_path('sigmavirus24/rfc3986').add_credentials(
            ...     'sigmavirus24', 'not-re@l').finalize().unsplit()
            'https://sigmavirus24:not-re%40l@github.com/sigmavirus24/rfc3986'

        """
        return uri.URIReference(
            self.scheme,
            normalizers.normalize_authority(
                (self.userinfo, self.host, self.port)
            ),
            self.path,
            self.query,
            self.fragment,
        )

    def geturl(self) -> str:
        """Generate the URL from this builder.

        .. versionadded:: 1.5.0

        This is an alternative to calling :meth:`finalize` and keeping the
        :class:`rfc3986.uri.URIReference` around.
        """
        return self.finalize().unsplit()
