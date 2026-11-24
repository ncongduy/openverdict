"""Signals computed from the URL text alone. Can only ever say `suspicious`."""

import ipaddress
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

from openverdict.models.url import NormalizedUrl
from openverdict.models.verdict import DetectorFinding, Verdict

THRESHOLD = 3

DEFAULT_BRANDS: tuple[str, ...] = (
    "paypal",
    "microsoft",
    "office365",
    "outlook",
    "icloud",
    "google",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "docusign",
    "salesforce",
    "onedrive",
    "sharepoint",
    "wellsfargo",
    "coinbase",
    "binance",
    "metamask",
)

DEFAULT_RISKY_TLDS = frozenset(
    {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim"}
    | {"work", "rest", "fit", "support", "cam"}
)


@dataclass(frozen=True, slots=True)
class Signal:
    name: str
    weight: int


def _is_ip_literal(host: str) -> bool:
    if host.isdigit():
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _mixed_script(label: str) -> bool:
    scripts = {
        unicodedata.name(ch, "UNKNOWN").split(" ")[0]
        for ch in label
        if not (ch.isdigit() or ch in "-_")
    }
    return len(scripts) > 1


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _brand_signals(labels: list[str], brands: Sequence[str]) -> list[Signal]:
    domain_label = labels[-2] if len(labels) >= 2 else labels[0]
    tokens = [token for label in labels[:-1] for token in label.split("-") if token]
    lookalike = combo = False
    for brand in brands:
        if domain_label == brand:
            continue
        for token in tokens:
            if token == brand:
                combo = True
            elif len(token) >= 5 and 1 <= _edit_distance(token, brand) <= 2:
                lookalike = True
    signals = []
    if lookalike:
        signals.append(Signal("brand_lookalike", 3))
    if combo:
        signals.append(Signal("brand_combo", 2))
    return signals


def score_url(
    url: NormalizedUrl, brands: Sequence[str], risky_tlds: frozenset[str]
) -> list[Signal]:
    """Fired signals in a fixed order: host shape, authority, brand, size, TLD."""
    signals: list[Signal] = []
    if _is_ip_literal(url.host):
        signals.append(Signal("ip_literal_host", 3))
        if url.has_userinfo:
            signals.append(Signal("at_in_authority", 3))
        if len(url.url) > 200:
            signals.append(Signal("long_url", 1))
        return signals

    unicode_labels = url.host_unicode.split(".")
    if any(_mixed_script(label) for label in unicode_labels):
        signals.append(Signal("mixed_script_host", 3))
    if any(label.startswith("xn--") for label in url.host.split(".")):
        signals.append(Signal("punycode_host", 2))
    if url.has_userinfo:
        signals.append(Signal("at_in_authority", 3))
    signals.extend(_brand_signals(unicode_labels, brands))
    if len(unicode_labels) - 2 > 4:
        signals.append(Signal("deep_subdomains", 1))
    if len(url.url) > 200:
        signals.append(Signal("long_url", 1))
    if unicode_labels[-1] in risky_tlds:
        signals.append(Signal("risky_tld", 1))
    return signals


class HeuristicsDetector:
    name = "heuristics"

    def __init__(
        self,
        brands: Sequence[str] = DEFAULT_BRANDS,
        risky_tlds: frozenset[str] = DEFAULT_RISKY_TLDS,
    ) -> None:
        self._brands = brands
        self._risky_tlds = risky_tlds

    async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]:
        return [self._finding(url) for url in urls]

    def _finding(self, url: NormalizedUrl) -> DetectorFinding | None:
        signals = score_url(url, self._brands, self._risky_tlds)
        total = sum(s.weight for s in signals)
        if total < THRESHOLD:
            return None
        detail = ", ".join(f"{s.name}+{s.weight}" for s in signals) + f" (score {total})"
        return DetectorFinding(self.name, Verdict.SUSPICIOUS, detail)
