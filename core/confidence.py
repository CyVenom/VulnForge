"""
VulnForge Confidence
Shared helpers for deciding how sure a finding is, so noisy guesses can be
filtered out instead of reported as facts.

Levels, weakest to strongest:
  low        a hint (e.g. version unknown, or a version-based CVE list)
  medium     version-based match where backported fixes are plausible
  high       deterministic check (header absent, content validator passed,
             version in an affected range on non-packaged software)
  confirmed  a tool actively reported the host as vulnerable
"""
import re

LEVELS = ["low", "medium", "high", "confirmed"]

# Markers that a version string comes from a distro package, where security
# fixes are routinely backported without changing the upstream version number.
DISTRO_MARKERS = re.compile(
    r"ubuntu|debian|\+deb\d|deb\d+u\d|centos|red ?hat|rhel|fedora|\.el\d|amazon linux|"
    r"suse|opensuse|alpine|raspbian|\bubuntu\d",
    re.I,
)


def rank(level: str | None) -> int:
    try:
        return LEVELS.index((level or "high").lower())
    except ValueError:
        return LEVELS.index("high")


def meets(level: str | None, minimum: str | None) -> bool:
    return rank(level) >= rank(minimum or "low")


def looks_distro_packaged(*texts: str | None) -> bool:
    return any(t and DISTRO_MARKERS.search(t) for t in texts)


RISK_RE = re.compile(r"Risk factor:\s*(CRITICAL|HIGH|MEDIUM|LOW)", re.I)


def parse_vuln_script(script_id: str, output: str) -> dict | None:
    """
    Interpret an nmap NSE script result. Returns {"severity", "confidence"}
    when the script actually reports a vulnerability, else None. Mentioning a
    CVE id is not enough: many scripts print "NOT VULNERABLE" or merely list
    version-based candidates.
    """
    up = (output or "").upper()
    if not up.strip():
        return None
    if "NOT VULNERABLE" in up or "COULDN'T FIND" in up or up.lstrip().startswith("ERROR"):
        return None

    m = RISK_RE.search(output)
    severity = m.group(1).lower() if m else "high"

    if script_id == "vulners":
        # Version-based candidate list; useful as a lead, not as a finding.
        return {"severity": "medium", "confidence": "low"} if "CVE-" in up else None
    if "LIKELY VULNERABLE" in up:
        return {"severity": severity, "confidence": "medium"}
    if re.search(r"\bVULNERABLE\b", up):
        return {"severity": severity, "confidence": "confirmed"}
    return None
