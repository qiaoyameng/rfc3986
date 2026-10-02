"""Strict parsing of URI references per :rfc:`3986`.

Unlike :func:`rfc3986.uri_reference`, the entry points in this module never
silently percent-encode the input. Instead, the original (raw) reference is
inspected first and every problem found is reported together with the exact
component and character range where it occurs.

For example::

    >>> from rfc3986 import strict
    >>> strict.strict_uri_reference("http://example.com:bad/%")
    Traceback (most recent call last):
    ...
    rfc3986.strict.StrictParseError: 2 issue(s) found in URI reference

Errors are exposed on the raised exception as ``StrictParseError.errors``,
where each item is a :class:`ParseIssue` carrying the component name, the
reason, the half-open character range (``start``/``end``) and the raw
offending substring.
"""

import dataclasses
import typing as t

from . import misc
from .exceptions import RFC3986Exception
from .uri import URIReference

__all__ = (
    "ParseIssue",
    "StrictParseError",
    "parse_uri_reference",
    "strict_uri_reference",
    "INVALID_PERCENT_ENCODING",
    "CONTROL_CHARACTER",
    "NON_ASCII_CHARACTER",
    "INVALID_CHARACTER",
    "INVALID_AUTHORITY",
    "INVALID_PORT",
    "INVALID_HOST",
    "ENCODING_ERROR",
)

#: A percent sign that is not followed by two hexadecimal digits.
INVALID_PERCENT_ENCODING: t.Final = "invalid-percent-encoding"
#: A character in the C0 control range (``0x00``-``0x1F``) or ``DEL``.
CONTROL_CHARACTER: t.Final = "control-character"
#: A non-ASCII character that was not percent-encoded.
NON_ASCII_CHARACTER: t.Final = "non-ascii-character"
#: An ASCII character that is not allowed in the component.
INVALID_CHARACTER: t.Final = "invalid-character"
#: The authority component cannot be split into userinfo/host/port.
INVALID_AUTHORITY: t.Final = "invalid-authority"
#: The port is empty, non-numeric, or outside of ``0``-``65535``.
INVALID_PORT: t.Final = "invalid-port"
#: The host is not a valid reg-name, IPv4, or IP-literal.
INVALID_HOST: t.Final = "invalid-host"
#: The bytes input could not be decoded with the requested encoding.
ENCODING_ERROR: t.Final = "encoding-error"

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

# Characters allowed by the ABNF, expressed per component. Percent-encoded
# triplets are handled separately so that they are never flagged as invalid.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_SUB_DELIMS = frozenset("!$&'()*+,;=")
_PCHAR_ALLOWED = _UNRESERVED | _SUB_DELIMS | {":", "@"}
_QUERY_ALLOWED = _PCHAR_ALLOWED | {"/", "?"}
_USERINFO_ALLOWED = _UNRESERVED | _SUB_DELIMS | {":"}
# reg-name allows unreserved, sub-delimiters and percent-encoded octets.
_REG_NAME_ALLOWED = _UNRESERVED | _SUB_DELIMS
# Inside an IP-literal only hex, '.', ':' and (for zone ids) unreserved
# percent-encoded octets are expected; stray characters are scanned directly.
_IP_LITERAL_ALLOWED = frozenset("0123456789abcdefABCDEF:.:vV") | _UNRESERVED


@dataclasses.dataclass(frozen=True)
class ParseIssue:
    """A single problem found while strictly parsing a URI reference.

    .. attribute:: component

        Name of the component containing the problem (``"scheme"``,
        ``"authority"``, ``"userinfo"``, ``"host"``, ``"port"``,
        ``"path"``, ``"query"``, or ``"fragment"``). For undecodable bytes
        input this is ``"uri"``.

    .. attribute:: reason

        One of the reason constants exported from this module.

    .. attribute:: start

        Offset of the first offending unit in the original input.

    .. attribute:: end

        One-past-the-last offset of the offending range.

    .. attribute:: unit

        ``"character"`` for ranges measured in decoded Unicode code points or
        ``"byte"`` for ranges measured in raw bytes (only used by
        :data:`ENCODING_ERROR`).

    .. attribute:: value

        The raw offending slice, when available.
    """

    component: str
    reason: str
    start: int
    end: int
    unit: str = "character"
    value: t.Optional[str] = None

    def __str__(self) -> str:
        where = f"{self.component}[{self.start}:{self.end}] ({self.unit}s)"
        if self.value is not None:
            return f"{self.reason} in {where}: {self.value!r}"
        return f"{self.reason} in {where}"


class StrictParseError(RFC3986Exception):
    """Raised when a strictly parsed URI reference contains problems.

    All independent problems are collected in :attr:`errors` and are ordered
    stably by their location in the original input.
    """

    def __init__(self, errors: t.List[ParseIssue]) -> None:
        """Store the collected issues."""
        self.errors = errors
        super().__init__(f"{len(errors)} issue(s) found in URI reference")


def _scan_text(
    text: str,
    base: int,
    component: str,
    allowed: t.FrozenSet[str],
) -> t.List[ParseIssue]:
    """Scan one component for illegal characters and percent escapes."""
    issues: t.List[ParseIssue] = []
    index = 0
    while index < len(text):
        char = text[index]
        start = base + index

        if char == "%":
            triplet_end = min(index + 3, len(text))
            triplet = text[index:triplet_end]
            if (
                triplet_end - index < 3
                or triplet[1] not in _HEXDIGITS
                or triplet[2] not in _HEXDIGITS
            ):
                issues.append(
                    ParseIssue(
                        component,
                        INVALID_PERCENT_ENCODING,
                        start,
                        base + triplet_end,
                        value=triplet,
                    )
                )
                # Advance past the '%' only; the remainder is rescanned so a
                # character following a malformed escape (e.g. a non-ASCII
                # one) is still classified on its own merits.
                index += 1
            else:
                # A valid triplet is allowed by definition.
                index = triplet_end
            continue

        code_point = ord(char)
        if code_point <= 0x1F or code_point == 0x7F:
            reason = CONTROL_CHARACTER
        elif code_point > 0x7F:
            reason = NON_ASCII_CHARACTER
        elif char not in allowed:
            reason = INVALID_CHARACTER
        else:
            reason = None
        if reason is not None:
            issues.append(
                ParseIssue(
                    component,
                    reason,
                    start,
                    start + 1,
                    value=char,
                )
            )
        index += 1
    return issues


def _full_match(matcher: t.Pattern[str], value: str) -> bool:
    """Return whether the matcher matches the whole value."""
    match = matcher.match(value)
    return match is not None and match.group(0) == value


def _host_is_valid(host: str) -> bool:
    """Return whether the host matches the strict host grammar."""
    if not _full_match(misc.HOST_MATCHER, host):
        return False
    if misc.IPv4_MATCHER.match(host):
        parts = host.split(".")
        return all(
            part.isdigit() and 0 <= int(part) <= 255 for part in parts
        )
    if misc.IPv6_MATCHER.match(host):
        return misc.IPv6_NO_RFC4007_MATCHER.match(host) is not None
    return True


def _covers(issues: t.List[ParseIssue], start: int, end: int) -> bool:
    """Return whether any issue is fully contained in the given span."""
    return any(
        start <= issue.start and issue.end <= end for issue in issues
    )


def _check_port(
    port: str, colon_position: int, issues: t.List[ParseIssue]
) -> None:
    """Validate a port substring positioned after ``colon_position``.

    ``colon_position`` is the offset of the ':' delimiter; the port itself
    starts one position later.
    """
    port_start = colon_position + 1
    if not port:
        # An empty port is reported on the ':' delimiter.
        issues.append(
            ParseIssue(
                "port",
                INVALID_PORT,
                colon_position,
                port_start,
                value=":",
            )
        )
    elif (
        not port.isascii()
        or not port.isdigit()
        or int(port) > 65535
    ):
        issues.append(
            ParseIssue(
                "port",
                INVALID_PORT,
                port_start,
                port_start + len(port),
                value=port,
            )
        )


def _check_authority(
    authority: str,
    base: int,
    out: t.List[ParseIssue],
) -> None:
    """Validate the authority, emitting precise problems into ``out``."""
    issues: t.List[ParseIssue] = []

    at_index = authority.rfind("@")
    if at_index != -1:
        userinfo = authority[:at_index]
        rest = authority[at_index + 1 :]
        issues.extend(
            _scan_text(
                userinfo, base, "userinfo", _USERINFO_ALLOWED
            )
        )
    else:
        rest = authority
    host_start = base + at_index + 1

    if rest.startswith("["):
        closing = rest.find("]")
        if closing == -1:
            literal_end = base + len(authority)
            # Scan the unterminated literal so inner problems (e.g. a stray
            # '%') are still located precisely.
            issues.extend(
                _scan_text(
                    rest[1:],
                    host_start + 1,
                    "host",
                    _IP_LITERAL_ALLOWED,
                )
            )
            if not _covers(issues, host_start, literal_end):
                issues.append(
                    ParseIssue(
                        "host",
                        INVALID_HOST,
                        host_start,
                        literal_end,
                        value=rest,
                    )
                )
        else:
            literal = rest[: closing + 1]
            literal_end = host_start + len(literal)
            tail = rest[closing + 1 :]
            # Scan the inside of the brackets so that, e.g., a stray '%' is
            # located precisely instead of being hidden by a host-level error.
            issues.extend(
                _scan_text(
                    literal[1:-1],
                    host_start + 1,
                    "host",
                    _IP_LITERAL_ALLOWED,
                )
            )
            if tail and not tail.startswith(":"):
                if not _covers(issues, host_start, literal_end):
                    issues.append(
                        ParseIssue(
                            "host",
                            INVALID_HOST,
                            host_start,
                            literal_end,
                            value=literal,
                        )
                    )
            elif not _host_is_valid(literal):
                if not _covers(issues, host_start, literal_end):
                    issues.append(
                        ParseIssue(
                            "host",
                            INVALID_HOST,
                            host_start,
                            literal_end,
                            value=literal,
                        )
                    )
            if tail.startswith(":"):
                _check_port(
                    tail[1:], literal_end, issues
                )
        out.extend(issues)
        return

    colon_index = rest.rfind(":")
    if colon_index == -1:
        host = rest
        port = None
    else:
        host = rest[:colon_index]
        port = rest[colon_index + 1 :]
    host_end = host_start + len(host)

    if host:
        issues.extend(
            _scan_text(host, host_start, "host", _REG_NAME_ALLOWED)
        )
        if not _host_is_valid(host) and not _covers(
            issues, host_start, host_end
        ):
            issues.append(
                ParseIssue(
                    "host",
                    INVALID_HOST,
                    host_start,
                    host_end,
                    value=host,
                )
            )
    if colon_index != -1:
        _check_port(port, host_start + colon_index, issues)

    # Catch structural problems (e.g. an empty userinfo) that character-level
    # scans cannot express, but only when nothing more precise was found.
    if not _covers(issues, base, base + len(authority)):
        subauthority_match = misc.SUBAUTHORITY_MATCHER.match(authority)
        if subauthority_match is None or (
            subauthority_match.group(0) != authority
        ):
            issues.append(
                ParseIssue(
                    "authority",
                    INVALID_AUTHORITY,
                    base,
                    base + len(authority),
                    value=authority,
                )
            )

    out.extend(issues)


def _check_text(text: str) -> t.List[ParseIssue]:
    """Split the raw text and validate every component."""
    match = misc.URI_MATCHER.match(text)
    if match is None:  # pragma: no cover - the generic grammar always matches
        return []

    authority_span = match.span("authority")
    path_span = match.span("path")
    query_span = match.span("query")
    fragment_span = match.span("fragment")

    issues: t.List[ParseIssue] = []

    if authority_span[0] != -1:
        authority_issues: t.List[ParseIssue] = []
        _check_authority(
            match.group("authority") or "",
            authority_span[0],
            authority_issues,
        )
        issues.extend(authority_issues)

    issues.extend(
        _scan_text(
            match.group("path") or "",
            path_span[0],
            "path",
            _PCHAR_ALLOWED | {"/"},
        )
    )
    if query_span[0] != -1:
        issues.extend(
            _scan_text(
                match.group("query") or "",
                query_span[0],
                "query",
                _QUERY_ALLOWED,
            )
        )
    if fragment_span[0] != -1:
        issues.extend(
            _scan_text(
                match.group("fragment") or "",
                fragment_span[0],
                "fragment",
                _QUERY_ALLOWED,
            )
        )

    issues.sort(key=lambda issue: (issue.start, issue.end, issue.reason))
    return issues


def parse_uri_reference(
    uri: t.Union[str, bytes],
    encoding: str = "utf-8",
) -> t.List[ParseIssue]:
    """Strictly parse a URI reference and return all problems found.

    The input is checked *before* any automatic percent-encoding happens;
    empty components and missing components remain distinct, and error ranges
    always refer to the original input (positions are not moved by
    normalization).

    :param uri: The URI reference as text, or as bytes encoded with
        ``encoding``.
    :param encoding: The encoding used to decode ``bytes`` input.
    :returns: A list of :class:`ParseIssue` objects, ordered stably by their
        position. An empty list means the reference is syntactically valid.
    """
    if isinstance(uri, bytes):
        try:
            text = uri.decode(encoding)
        except UnicodeDecodeError as error:
            return [
                ParseIssue(
                    "uri",
                    ENCODING_ERROR,
                    error.start,
                    error.end,
                    unit="byte",
                    value=uri[error.start : error.end].decode("latin-1"),
                )
            ]
    else:
        text = uri
    return _check_text(text)


def strict_uri_reference(
    uri: t.Union[str, bytes],
    encoding: str = "utf-8",
) -> URIReference:
    """Parse strictly, raising :class:`StrictParseError` on any problem.

    On success this returns the same kind of object as
    :func:`rfc3986.uri_reference`; that lenient interface (and its automatic
    percent-encoding) is intentionally left untouched.

    :param uri: The URI reference as text, or as bytes.
    :param encoding: The encoding used to decode ``bytes`` input.
    :raises StrictParseError: If one or more problems are found.
    """
    issues = parse_uri_reference(uri, encoding)
    if issues:
        raise StrictParseError(issues)
    return URIReference.from_string(uri, encoding)
