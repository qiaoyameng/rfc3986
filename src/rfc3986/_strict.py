"""Strict URI parsing with source-localized syntax errors."""

import codecs
import re
import unicodedata
import typing as t

from . import abnf_regexp
from . import exceptions
from . import misc

INVALID_CHARACTER = "invalid character"
INVALID_PERCENT_ESCAPE = "invalid percent escape"
INVALID_AUTHORITY = "invalid authority"
INVALID_PORT = "invalid port"
INVALID_PATH = "invalid path"
CONTROL_CHARACTER = "control character"
ENCODING_ERROR = "encoding error"

_UNRESERVED_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789._~-"
)
_UNRESERVED_RE = r"A-Za-z0-9\._~\-"
_SUB_DELIMITERS_CHARS = "!$&'()*+,;="
_PCHAR_CHARS = _UNRESERVED_CHARS + _SUB_DELIMITERS_CHARS + ":@"
_PATH_CHARACTERS = set(_PCHAR_CHARS + "/")
_QUERY_CHARACTERS = set(_PCHAR_CHARS + "/?")
_HOST_CHARACTERS = set(_UNRESERVED_CHARS + _SUB_DELIMITERS_CHARS)
_USERINFO_CHARACTERS = set(
    _UNRESERVED_CHARS + _SUB_DELIMITERS_CHARS + ":"
)

_ZONE_ID = (
    "(?:["
    + _UNRESERVED_RE
    + "]|%[A-Fa-f0-9]{2})+"
)
_IP_LITERAL = re.compile(
    r"^\[(?:"
    + abnf_regexp.IPv6_RE
    + r"(?:%25"
    + _ZONE_ID
    + r")?|"
    + abnf_regexp.IPv_FUTURE_RE
    + r")\]$"
)


class _DecodedURI(t.NamedTuple):
    text: str
    positions: t.List[int]
    is_bytes: bool


def validate_uri_reference(
    uri_string: t.Union[str, bytes],
    encoding: str = "utf-8",
) -> None:
    """Validate source text before parsing and auto-encoding it."""
    decoded = _decode(uri_string, encoding)
    errors = _find_errors(decoded)
    if errors:
        raise exceptions.InvalidURIError(uri_string, errors)


def _decode(
    uri_string: t.Union[str, bytes],
    encoding: str,
) -> _DecodedURI:
    if isinstance(uri_string, str):
        positions = list(range(len(uri_string) + 1))
        return _DecodedURI(uri_string, positions, False)

    codecs.lookup(encoding)
    decoder = codecs.getincrementaldecoder(encoding)(
        errors="surrogateescape"
    )
    text = decoder.decode(uri_string, True)
    positions = [0]
    for character in text:
        code_point = ord(character)
        if 0xDC80 <= code_point <= 0xDCFF:
            size = 1
        else:
            try:
                size = len(character.encode(encoding))
            except UnicodeEncodeError:
                size = 1
        positions.append(positions[-1] + size)
    return _DecodedURI(text, positions, True)


def _find_errors(decoded: _DecodedURI) -> t.List[exceptions.URIErrorDetail]:
    match = misc.URI_MATCHER.match(decoded.text)
    if match is None:
        return []

    errors: t.List[exceptions.URIErrorDetail] = []
    components = match.groupdict()

    authority_span = match.span("authority")
    if components["authority"] is not None:
        errors.extend(
            _authority_errors(
                components["authority"],
                authority_span[0],
                decoded,
            )
        )

    for component, allowed in (
        ("path", _PATH_CHARACTERS),
        ("query", _QUERY_CHARACTERS),
        ("fragment", _QUERY_CHARACTERS),
    ):
        value = components[component]
        if value is not None:
            errors.extend(
                _component_errors(
                    component,
                    value,
                    match.span(component)[0],
                    allowed,
                    decoded,
                )
            )

    path = components["path"]
    if path is not None:
        path_span = match.span("path")
        if components["authority"] is not None:
            if path and not path.startswith("/"):
                errors.append(
                    _error(
                        "path",
                        INVALID_PATH,
                        path_span[0],
                        path_span[1],
                        decoded,
                    )
                )
        elif components["scheme"] is None and path:
            first_segment = path.split("/", 1)[0]
            if not path.startswith("/") and ":" in first_segment:
                colon = first_segment.index(":")
                errors.append(
                    _error(
                        "path",
                        INVALID_PATH,
                        path_span[0] + colon,
                        path_span[0] + colon + 1,
                        decoded,
                    )
                )

    return sorted(errors, key=lambda error: error.start)


def _component_errors(
    component: str,
    value: str,
    offset: int,
    allowed: t.AbstractSet[str],
    decoded: _DecodedURI,
    allow_percent: bool = True,
) -> t.List[exceptions.URIErrorDetail]:
    errors: t.List[exceptions.URIErrorDetail] = []
    index = 0

    while index < len(value):
        character = value[index]
        reason = _character_reason(character, allowed, decoded.is_bytes)

        if allow_percent and _is_percent_escape(value, index):
            index += 3
            continue

        if allow_percent and character == "%":
            end = _invalid_percent_end(value, index)
            errors.append(
                _error(
                    component,
                    INVALID_PERCENT_ESCAPE,
                    offset + index,
                    offset + end,
                    decoded,
                )
            )
            index = end
            continue

        if reason is None:
            index += 1
            continue

        start = index
        index += 1
        while index < len(value):
            next_character = value[index]
            if allow_percent and next_character == "%":
                break
            next_reason = _character_reason(
                next_character, allowed, decoded.is_bytes
            )
            if next_reason != reason:
                break
            index += 1

        errors.append(
            _error(
                component,
                reason,
                offset + start,
                offset + index,
                decoded,
            )
        )

    return errors


def _character_reason(
    character: str,
    allowed: t.AbstractSet[str],
    is_bytes: bool,
) -> t.Optional[str]:
    code_point = ord(character)
    if is_bytes and 0xDC80 <= code_point <= 0xDCFF:
        return ENCODING_ERROR
    if (
        code_point <= 0x1F
        or code_point == 0x7F
        or unicodedata.category(character) == "Cc"
    ):
        return CONTROL_CHARACTER
    if character in allowed:
        return None
    return INVALID_CHARACTER


def _is_percent_escape(value: str, index: int) -> bool:
    return (
        index + 2 < len(value)
        and value[index] == "%"
        and value[index + 1] in "0123456789abcdefABCDEF"
        and value[index + 2] in "0123456789abcdefABCDEF"
    )


def _invalid_percent_end(value: str, index: int) -> int:
    end = index + 1
    if end < len(value) and value[end] in "0123456789abcdefABCDEF":
        end += 1
    if end - index == 2 and (
        end == len(value) or value[end] == "%"
    ):
        end -= 1
    return end


def _authority_errors(
    authority: str,
    offset: int,
    decoded: _DecodedURI,
) -> t.List[exceptions.URIErrorDetail]:
    userinfo: t.Optional[str] = None
    userinfo_end = 0
    rest = authority

    if "@" in authority:
        userinfo, rest = authority.rsplit("@", 1)
        userinfo_end = len(userinfo) + 1

    host = rest
    port: t.Optional[str] = None
    host_start = userinfo_end
    port_start = 0
    errors: t.List[exceptions.URIErrorDetail] = []

    if rest.startswith("["):
        closing = rest.find("]", 1)
        if userinfo is not None:
            errors.extend(
                _component_errors(
                    "userinfo",
                    userinfo,
                    offset,
                    _USERINFO_CHARACTERS,
                    decoded,
                )
            )
        if closing == -1:
            errors.append(
                _error(
                    "host",
                    INVALID_AUTHORITY,
                    offset + host_start,
                    offset + len(authority),
                    decoded,
                )
            )
            return errors

        host = rest[: closing + 1]
        suffix = rest[closing + 1 :]
        if suffix.startswith(":"):
            port = suffix[1:]
            port_start = host_start + len(host) + 1
        elif suffix:
            suffix_colon = suffix.find(":")
            invalid_end = (
                len(suffix)
                if suffix_colon == -1
                else suffix_colon
            )
            errors.append(
                _error(
                    "host",
                    INVALID_AUTHORITY,
                    offset + host_start + len(host),
                    offset + host_start + len(host) + invalid_end,
                    decoded,
                )
            )
            return errors
    elif ":" in rest:
        host, port = rest.split(":", 1)
        port_start = host_start + len(host) + 1

    if userinfo is not None:
        errors.extend(
            _component_errors(
                "userinfo",
                userinfo,
                offset,
                _USERINFO_CHARACTERS,
                decoded,
            )
        )

    if host:
        host_errors = _host_errors(host, offset + host_start, decoded)
        errors.extend(host_errors)

    if port is not None:
        errors.extend(_port_errors(port, offset + port_start, decoded))

    return errors


def _host_errors(
    host: str,
    offset: int,
    decoded: _DecodedURI,
) -> t.List[exceptions.URIErrorDetail]:
    if host.startswith("["):
        if _IP_LITERAL.match(host):
            return []
        return [
            _error(
                "host",
                INVALID_AUTHORITY,
                offset,
                offset + len(host),
                decoded,
            )
        ]

    errors = _component_errors(
        "host",
        host,
        offset,
        _HOST_CHARACTERS,
        decoded,
        allow_percent=True,
    )
    if misc.IPv4_MATCHER.match(host) and not _valid_ipv4(host):
        errors.append(
            _error(
                "host",
                INVALID_AUTHORITY,
                offset,
                offset + len(host),
                decoded,
            )
        )
    return errors


def _port_errors(
    port: str,
    offset: int,
    decoded: _DecodedURI,
) -> t.List[exceptions.URIErrorDetail]:
    if not port:
        return []
    errors = _component_errors(
        "port",
        port,
        offset,
        set("0123456789"),
        decoded,
        allow_percent=False,
    )
    if any(error.reason == INVALID_CHARACTER for error in errors):
        errors = [
            error._replace(
                reason=INVALID_PORT
            )
            if error.reason == INVALID_CHARACTER
            else error
            for error in errors
        ]
    if port.isascii() and port.isdigit():
        if len(port) <= 5 and int(port) <= 65535:
            return []
        errors.append(
            _error(
                "port",
                INVALID_PORT,
                offset,
                offset + len(port),
                decoded,
            )
        )
    return errors


def _valid_ipv4(host: str) -> bool:
    return all(0 <= int(part) <= 255 for part in host.split("."))


def _error(
    component: str,
    reason: str,
    start: int,
    end: int,
    decoded: _DecodedURI,
) -> exceptions.URIErrorDetail:
    unit = "bytes" if decoded.is_bytes else "characters"
    return exceptions.URIErrorDetail(
        component,
        reason,
        decoded.positions[start],
        decoded.positions[end],
        unit,
        _source_value(decoded, start, end),
    )


def _source_value(
    decoded: _DecodedURI,
    start: int,
    end: int,
) -> str:
    if not decoded.is_bytes:
        return decoded.text[start:end]

    value = ""
    for character in decoded.text[start:end]:
        code_point = ord(character)
        if 0xDC80 <= code_point <= 0xDCFF:
            value += "\ufffd"
        else:
            value += character
    return value
