from openverdict.models.verdict import DetectorFinding as F
from openverdict.models.verdict import OverrideOutcome as O
from openverdict.models.verdict import Verdict as V
from openverdict.models.verdict import classify_override, combine


def test_combine():
    assert combine([]) is V.UNKNOWN
    assert combine([F("allowlist", V.SAFE, "")]) is V.SAFE
    assert combine([F("allowlist", V.SAFE, ""), F("heuristics", V.SUSPICIOUS, "")]) is V.SUSPICIOUS
    worst = [F("heuristics", V.SUSPICIOUS, ""), F("urlhaus", V.MALICIOUS, "")]
    assert combine(worst) is V.MALICIOUS


def test_classify_override():
    assert classify_override(V.MALICIOUS, V.SAFE) is O.FALSE_POSITIVE
    assert classify_override(V.SUSPICIOUS, V.SAFE) is O.FALSE_POSITIVE
    assert classify_override(V.SAFE, V.MALICIOUS) is O.FALSE_NEGATIVE
    assert classify_override(V.UNKNOWN, V.MALICIOUS) is O.COVERAGE_GAP
    assert classify_override(V.UNKNOWN, V.SAFE) is O.COVERAGE_GAP
    assert classify_override(V.SUSPICIOUS, V.MALICIOUS) is O.AGREEMENT
    assert classify_override(V.SAFE, V.SAFE) is O.AGREEMENT
    assert O.FALSE_POSITIVE.value == "false_positive"
