"""URL and domain normalization. Pure functions, no network access."""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL = re.compile(r"^[a-z0-9_-]{1,63}$")

ErrorCode = Literal["invalid_url", "unsupported_scheme", "too_long"]


class UrlError(ValueError):
    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code)
        self.code: ErrorCode = code


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    url: str
    scheme: str
    host: str
    host_unicode: str
    port: int | None
    has_userinfo: bool
    sha256: str


def url_sha256(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _ip_literal(host: str) -> str | None:
    """Return the canonical form if host is an IP literal, else None."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _normalize_host(raw_host: str) -> tuple[str, str]:
    """Return (ascii_host, unicode_host) or raise UrlError('invalid_url')."""
    host = raw_host.strip().lower().rstrip(".")
    if not host:
        raise UrlError("invalid_url")
    ip = _ip_literal(host)
    if ip is not None:
        return ip, ip
    try:
        ascii_host = host.encode("idna").decode("ascii")
        unicode_host = ascii_host.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise UrlError("invalid_url") from exc
    if not all(_LABEL.match(label) for label in ascii_host.split(".")):
        raise UrlError("invalid_url")
    return ascii_host, unicode_host


def normalize_url(raw: str) -> NormalizedUrl:
    text = raw.strip()
    if len(text) > MAX_URL_LENGTH:
        raise UrlError("too_long")
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise UrlError("invalid_url") from exc
    scheme = parts.scheme.lower()
    if not scheme:
        raise UrlError("invalid_url")
    if scheme not in ALLOWED_SCHEMES:
        raise UrlError("unsupported_scheme")
    if parts.hostname is None:
        raise UrlError("invalid_url")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlError("invalid_url") from exc

    host, host_unicode = _normalize_host(parts.hostname)
    if port == DEFAULT_PORTS[scheme]:
        port = None

    has_userinfo = "@" in parts.netloc
    userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if has_userinfo else ""
    host_part = f"[{host}]" if ":" in host else host
    netloc = f"{userinfo}{host_part}" + (f":{port}" if port is not None else "")
    url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return NormalizedUrl(
        url=url,
        scheme=scheme,
        host=host,
        host_unicode=host_unicode,
        port=port,
        has_userinfo=has_userinfo,
        sha256=url_sha256(url),
    )


def normalize_domain(raw: str) -> str:
    text = raw.strip()
    if not text or any(ch in text for ch in "/:") or any(ch.isspace() for ch in text):
        raise UrlError("invalid_url")
    return _normalize_host(text)[0]


def host_suffixes(host: str) -> list[str]:
    """Host plus its parent domains with at least two labels. IP literals return [host]."""
    if _ip_literal(host) is not None:
        return [host]
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]
