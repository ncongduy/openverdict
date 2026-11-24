"""The interface every URL detector implements."""

from collections.abc import Sequence
from typing import Protocol

from openverdict.models.url import NormalizedUrl
from openverdict.models.verdict import DetectorFinding


class UrlDetector(Protocol):
    name: str

    async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]:
        """Return one finding (or None) per input URL, in input order."""
        ...
