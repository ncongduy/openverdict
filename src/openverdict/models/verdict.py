"""Verdicts, detector findings and the rules that combine them."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Verdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


# Higher wins when combining findings.
_SEVERITY = {Verdict.UNKNOWN: 0, Verdict.SAFE: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}


@dataclass(frozen=True, slots=True)
class DetectorFinding:
    detector: str
    verdict: Verdict
    detail: str


@dataclass(slots=True)
class UrlResult:
    url: str
    normalized_url: str | None
    verdict: Verdict | None
    checked_at: datetime
    reasons: list[DetectorFinding] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    error: str | None = None


def combine(findings: Iterable[DetectorFinding]) -> Verdict:
    """Most severe wins: malicious > suspicious > safe > unknown (no findings)."""
    return max((f.verdict for f in findings), key=_SEVERITY.__getitem__, default=Verdict.UNKNOWN)


class OverrideOutcome(StrEnum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    COVERAGE_GAP = "coverage_gap"
    AGREEMENT = "agreement"


def classify_override(engine: Verdict, analyst: Verdict) -> OverrideOutcome:
    if engine is Verdict.UNKNOWN:
        return OverrideOutcome.COVERAGE_GAP
    if analyst is Verdict.SAFE and engine in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        return OverrideOutcome.FALSE_POSITIVE
    if analyst is Verdict.MALICIOUS and engine is Verdict.SAFE:
        return OverrideOutcome.FALSE_NEGATIVE
    return OverrideOutcome.AGREEMENT
