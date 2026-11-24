"""Parsers for the threat-intel and top-sites feeds. Pure functions over downloaded content."""

import csv
import io
import zipfile
from dataclasses import dataclass, field

from openverdict.models.url import UrlError, normalize_domain, normalize_url

_URLHAUS_MIN_COLUMNS = 6


@dataclass(slots=True)
class ParsedFeed:
    urls: dict[str, str] = field(default_factory=dict)  # normalized URL -> meta
    hosts: set[str] = field(default_factory=set)
    skipped: int = 0


def _content_lines(text: str) -> list[str]:
    stripped = (line.strip() for line in text.splitlines())
    return [line for line in stripped if line and not line.startswith("#")]


def parse_urlhaus_csv(text: str) -> ParsedFeed:
    feed = ParsedFeed()
    for row in csv.reader(_content_lines(text)):
        if row and row[0] == "id":
            continue
        if len(row) < _URLHAUS_MIN_COLUMNS:
            feed.skipped += 1
            continue
        try:
            url = normalize_url(row[2])
        except UrlError:
            feed.skipped += 1
            continue
        feed.urls[url.url] = f"{row[5]}, {row[1][:10]}"
        feed.hosts.add(url.host)
    return feed


def parse_url_lines(text: str) -> ParsedFeed:
    feed = ParsedFeed()
    for line in _content_lines(text):
        try:
            url = normalize_url(line)
        except UrlError:
            feed.skipped += 1
            continue
        feed.urls[url.url] = ""
        feed.hosts.add(url.host)
    return feed


def parse_domain_lines(text: str) -> set[str]:
    domains = set()
    for line in _content_lines(text):
        try:
            domains.add(normalize_domain(line))
        except UrlError:
            continue
    return domains


def parse_tranco(content: bytes, limit: int) -> list[str]:
    """Top `limit` domains from a Tranco list given as a zip (first member) or plain CSV."""
    if content.startswith(b"PK"):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            content = archive.read(archive.namelist()[0])
    domains: list[str] = []
    for row in csv.reader(io.StringIO(content.decode("utf-8", errors="replace"))):
        if len(domains) >= limit:
            break
        if len(row) < 2:
            continue
        try:
            domains.append(normalize_domain(row[1]))
        except UrlError:
            continue
    return domains
