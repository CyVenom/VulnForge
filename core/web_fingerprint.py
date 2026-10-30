"""
VulnForge Web Fingerprinting
Read-only GraphQL endpoint discovery (with introspection exposure check) and
CMS/framework fingerprinting (WordPress, Drupal, Joomla). Every request is a
plain GET, or a POST carrying a harmless `__typename` / `__schema` query. No
mutations, no credentials, no payloads.
"""
import asyncio
import json
import logging
import re
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger("vulnforge.web_fingerprint")

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/", "/v1/graphql", "/query",
    "/graphiql", "/api", "/gql",
]

GRAPHQL_TYPENAME_QUERY = {"query": "{__typename}"}
GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name} types{name}}}"}

# CMS -> regexes applied to the landing page body and headers
CMS_SIGNATURES = {
    "WordPress": [
        re.compile(r"/wp-content/", re.I),
        re.compile(r"/wp-includes/", re.I),
        re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress', re.I),
    ],
    "Drupal": [
        re.compile(r"Drupal\.settings", re.I),
        re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal', re.I),
        re.compile(r"/sites/(default|all)/(files|modules|themes)/", re.I),
    ],
    "Joomla": [
        re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla', re.I),
        re.compile(r"/media/system/js/", re.I),
        re.compile(r"/components/com_", re.I),
    ],
}

GENERATOR_VERSION = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']'
    r"(WordPress|Drupal|Joomla)[!\s]*([\d.]+)?",
    re.I,
)

# EOL cut-offs are deliberately conservative: a version below these has
# been unsupported upstream for years, regardless of backported patches.
CMS_MIN_SUPPORTED_MAJOR = {"WordPress": (5, 0), "Drupal": (9, 0), "Joomla": (4, 0)}


def _version_tuple(version: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(p) for p in version.split(".") if p != "")
    except ValueError:
        return None


async def check_graphql(session: aiohttp.ClientSession, base_url: str, findings: list):
    """Find GraphQL endpoints and report whether introspection is enabled."""

    async def probe(path: str):
        url = urljoin(base_url, path)
        try:
            async with session.post(url, json=GRAPHQL_TYPENAME_QUERY, allow_redirects=False) as resp:
                if resp.status >= 500 or resp.status in (404, 405):
                    return
                body = await resp.text(errors="replace")
            data = json.loads(body)
        except Exception:
            return

        if not isinstance(data, dict) or not isinstance(data.get("data"), dict):
            return
        if "__typename" not in data["data"]:
            return

        findings.append({
            "title": f"GraphQL Endpoint Discovered: {path}",
            "severity": "info",
            "description": f"{url} accepts GraphQL queries.",
            "remediation": "Confirm this endpoint is intended to be public and is covered by authentication and rate limiting.",
            "category": "graphql",
            "evidence": f"POST {url} {{__typename}} -> {data['data']}",
        })

        try:
            async with session.post(url, json=GRAPHQL_INTROSPECTION_QUERY, allow_redirects=False) as resp:
                intro = json.loads(await resp.text(errors="replace"))
        except Exception:
            return

        schema = (intro.get("data") or {}).get("__schema") if isinstance(intro, dict) else None
        if schema:
            type_names = [t.get("name") for t in schema.get("types", []) if not str(t.get("name", "")).startswith("__")]
            findings.append({
                "title": f"GraphQL Introspection Enabled: {path}",
                "severity": "medium",
                "description": (
                    "The full GraphQL schema is queryable by anyone, giving attackers a "
                    "complete map of types, queries and mutations."
                ),
                "remediation": "Disable introspection in production, or restrict it to authenticated developers.",
                "category": "graphql",
                "evidence": f"{url} returned {len(type_names)} schema types, e.g. {', '.join(type_names[:8])}",
            })

    await asyncio.gather(*[probe(p) for p in GRAPHQL_PATHS])


async def check_cms(session: aiohttp.ClientSession, base_url: str, response_data: dict, findings: list):
    """Fingerprint WordPress/Drupal/Joomla from the landing page and a few well-known files."""
    body = response_data.get("body_snippet", "")
    headers = {k.lower(): v for k, v in response_data.get("headers", {}).items()}

    detected: str | None = None
    if "drupal" in headers.get("x-generator", "").lower() or "x-drupal-cache" in headers:
        detected = "Drupal"
    else:
        for cms, patterns in CMS_SIGNATURES.items():
            if any(p.search(body) for p in patterns):
                detected = cms
                break

    if not detected:
        return

    version: str | None = None
    match = GENERATOR_VERSION.search(body)
    if match and match.group(1).lower() == detected.lower():
        version = match.group(2)

    async def fetch(path: str, limit: int = 4000) -> tuple[int, str]:
        try:
            async with session.get(urljoin(base_url, path), allow_redirects=False) as resp:
                return resp.status, (await resp.text(errors="replace"))[:limit]
        except Exception:
            return 0, ""

    if detected == "WordPress":
        status, text = await fetch("/readme.html")
        m = re.search(r"Version\s+([\d.]+)", text)
        if status == 200 and m and not version:
            version = m.group(1)
        users_status, users_text = await fetch("/wp-json/wp/v2/users", limit=200_000)
        if users_status == 200:
            try:
                users = json.loads(users_text)
            except ValueError:
                users = []
            users = users if isinstance(users, list) else []
            slugs = [u.get("slug") for u in users if isinstance(u, dict) and u.get("slug")]
            if slugs:
                findings.append({
                    "title": "WordPress User Enumeration via REST API",
                    "severity": "medium",
                    "description": "The REST API lists user accounts to unauthenticated visitors, which feeds username guessing and credential stuffing.",
                    "remediation": "Block unauthenticated access to /wp-json/wp/v2/users (security plugin or a filter on rest_endpoints).",
                    "category": "cms",
                    "evidence": f"GET /wp-json/wp/v2/users returned usernames: {', '.join(slugs[:5])}",
                })
    elif detected == "Drupal":
        status, text = await fetch("/CHANGELOG.txt")
        m = re.search(r"Drupal\s+([\d.]+)", text)
        if status == 200 and m:
            version = version or m.group(1)
            findings.append({
                "title": "Drupal CHANGELOG.txt Exposed",
                "severity": "low",
                "description": "CHANGELOG.txt reveals the exact installed Drupal version.",
                "remediation": "Deny access to CHANGELOG.txt and other core text files at the web server.",
                "category": "cms",
                "evidence": f"GET /CHANGELOG.txt -> Drupal {m.group(1)}",
            })
    elif detected == "Joomla":
        status, text = await fetch("/administrator/manifests/files/joomla.xml")
        m = re.search(r"<version>([\d.]+)</version>", text)
        if status == 200 and m:
            version = version or m.group(1)
            findings.append({
                "title": "Joomla Version Manifest Exposed",
                "severity": "low",
                "description": "joomla.xml reveals the exact installed Joomla version.",
                "remediation": "Deny access to /administrator/manifests/ for unauthenticated users.",
                "category": "cms",
                "evidence": f"GET /administrator/manifests/files/joomla.xml -> Joomla {m.group(1)}",
            })

    findings.append({
        "title": f"CMS Detected: {detected}" + (f" {version}" if version else ""),
        "severity": "info",
        "description": f"The site appears to run {detected}" + (f" version {version}." if version else " (version not disclosed)."),
        "remediation": "Keep the CMS core, themes and plugins patched; hide version strings where possible.",
        "category": "cms",
        "evidence": f"Fingerprinted from landing page markup ({detected})",
    })

    if version:
        parsed = _version_tuple(version)
        floor = CMS_MIN_SUPPORTED_MAJOR[detected]
        if parsed and parsed < floor:
            findings.append({
                "title": f"Outdated {detected} Version: {version}",
                "severity": "high",
                "description": f"{detected} {version} is older than {'.'.join(map(str, floor))} and no longer receives upstream security fixes.",
                "remediation": f"Upgrade {detected} to a currently supported release.",
                "category": "cms",
                "evidence": f"Detected version {version}",
            })
