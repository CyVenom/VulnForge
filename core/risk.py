"""
VulnForge Risk Score
Turns severity counts into a 0-100 score.

The raw score is a weighted sum (critical 10, high 7, medium 4, low 1). The old
code simply capped that sum at 100, so ten highs and two hundred highs both
scored 100. Now scores up to 50 are exactly the raw sum (so existing scores and
the CI threshold at 40 are unchanged), and above 50 the extra risk keeps
counting but with diminishing returns, approaching 100 without being flat.
"""
import math

WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
LINEAR_UNTIL = 50
CURVE_SCALE = 100.0


def raw_score(severity_counts: dict) -> int:
    """Weighted sum. Unknown severity labels count as zero instead of crashing."""
    return sum(WEIGHTS.get(str(sev).lower(), 0) * int(n) for sev, n in severity_counts.items())


def risk_score(severity_counts: dict) -> int:
    raw = raw_score(severity_counts)
    if raw <= LINEAR_UNTIL:
        return raw
    headroom = 100 - LINEAR_UNTIL
    return min(100, round(LINEAR_UNTIL + headroom * (1 - math.exp(-(raw - LINEAR_UNTIL) / CURVE_SCALE))))
