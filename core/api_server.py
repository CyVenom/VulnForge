"""
VulnForge REST API
A small aiohttp server for starting scans and reading results remotely.

Safety model:
  * Bearer token required on everything except /health. The token comes from
    the VULNFORGE_API_TOKEN environment variable (16+ chars), never from a
    file, and is compared in constant time.
  * Binds to 127.0.0.1 unless the operator explicitly allows remote binding.
  * The token holder is the operator, so scan requests skip the interactive
    prompt. Blocked reserved-IP ranges are still refused by the scanner.
  * Bounded: request bodies are capped, concurrent scans are capped, and one
    target can only have one scan in flight.

Endpoints:
  GET  /health                       liveness (no auth)
  GET  /scans?target=&limit=         scan history
  GET  /scans/{scan_id}              full stored result
  GET  /targets/{target}/trend       risk trend for a target
  POST /scans                        {"target": "...", "scan_types": [...]} -> 202 + job
  GET  /jobs/{job_id}                job status
"""
import asyncio
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Any

from aiohttp import web

from .history import ScanHistory
from .trends import build_trend

logger = logging.getLogger("vulnforge.api")

TOKEN_ENV = "VULNFORGE_API_TOKEN"
MIN_TOKEN_LEN = 16
MAX_BODY = 16 * 1024
MAX_JOBS_KEPT = 200
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/_]{0,253}$")
VALID_SCAN_TYPES = {"port", "service", "os", "vuln", "ssl", "web"}
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}

TOKEN_KEY = web.AppKey("token", str)
STATE_KEY = web.AppKey("state", object)


class ApiConfigError(Exception):
    pass


def check_bind(host: str, allow_remote: bool) -> None:
    if host not in LOCAL_HOSTS and not allow_remote:
        raise ApiConfigError(
            f"Refusing to bind to {host!r}: the API is localhost-only unless you pass --allow-remote "
            f"(put it behind TLS and a firewall if you do)."
        )


def load_token(env: dict | None = None) -> str:
    token = (env if env is not None else os.environ).get(TOKEN_ENV, "")
    if len(token) < MIN_TOKEN_LEN:
        raise ApiConfigError(f"Set {TOKEN_ENV} to a secret of at least {MIN_TOKEN_LEN} characters before starting the API.")
    return token


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path == "/health":
        return await handler(request)
    supplied = request.headers.get("Authorization", "")
    expected = "Bearer " + request.app[TOKEN_KEY]
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        return web.json_response({"error": "unauthorized"}, status=401, headers={"WWW-Authenticate": "Bearer"})
    return await handler(request)


@web.middleware
async def error_middleware(request: web.Request, handler):
    try:
        return await handler(request)
    except web.HTTPException as exc:
        return web.json_response({"error": exc.reason}, status=exc.status)
    except Exception:
        logger.exception("Unhandled API error")
        return web.json_response({"error": "internal error"}, status=500)


class ApiState:
    def __init__(self, config: dict, scanner: Any, max_concurrent: int):
        self.config = config
        self.scanner = scanner
        self.history = ScanHistory(config)
        self.jobs: dict[str, dict] = {}
        self.running_targets: set[str] = set()
        self.max_concurrent = max_concurrent
        self.tasks: set[asyncio.Task] = set()

    def prune(self) -> None:
        while len(self.jobs) > MAX_JOBS_KEPT:
            oldest = next(iter(self.jobs))
            if self.jobs[oldest]["status"] in ("queued", "running"):
                break
            del self.jobs[oldest]


# ---------------- handlers ----------------
async def health(request):
    return web.json_response({"status": "ok"})


async def list_scans(request):
    st: ApiState = request.app[STATE_KEY]
    try:
        limit = max(1, min(int(request.query.get("limit", 20)), 200))
    except ValueError:
        raise web.HTTPBadRequest(reason="limit must be an integer")
    return web.json_response({"scans": st.history.list_scans(request.query.get("target"), limit)})


async def get_scan(request):
    st: ApiState = request.app[STATE_KEY]
    result = st.history.get_result(request.match_info["scan_id"])
    if result is None:
        raise web.HTTPNotFound(reason="scan not found")
    return web.json_response(result, dumps=lambda o: json.dumps(o, default=str))


async def get_trend(request):
    st: ApiState = request.app[STATE_KEY]
    results = st.history.list_results(request.match_info["target"], 10)
    if not results:
        raise web.HTTPNotFound(reason="no history for target")
    t = build_trend(results)
    return web.json_response({
        "points": t["points"], "direction": t["direction"], "sparkline": t["sparkline"],
        "new_since_previous": [f.get("title") for f in t["new_since_previous"]],
        "resolved_since_previous": [f.get("title") for f in t["resolved_since_previous"]],
    })


async def start_scan(request):
    st: ApiState = request.app[STATE_KEY]
    try:
        body = await request.json()
    except ValueError:
        raise web.HTTPBadRequest(reason="body must be JSON")
    if not isinstance(body, dict):
        raise web.HTTPBadRequest(reason="body must be a JSON object")

    target = body.get("target")
    if not isinstance(target, str) or not TARGET_RE.match(target):
        raise web.HTTPBadRequest(reason="target missing or malformed")
    scan_types = body.get("scan_types")
    if scan_types is not None:
        if not isinstance(scan_types, list) or not set(scan_types) <= VALID_SCAN_TYPES:
            raise web.HTTPBadRequest(reason=f"scan_types must be a list drawn from {sorted(VALID_SCAN_TYPES)}")

    if target in st.running_targets:
        raise web.HTTPConflict(reason="a scan for this target is already in progress")
    if len(st.running_targets) >= st.max_concurrent:
        raise web.HTTPTooManyRequests(reason="too many concurrent scans")

    job_id = uuid.uuid4().hex[:12]
    st.jobs[job_id] = {"job_id": job_id, "target": target, "status": "queued",
                       "created": datetime.now().isoformat(timespec="seconds")}
    st.running_targets.add(target)
    st.prune()
    st.scanner.audit.record("api_scan_started", target=target, detail={"job_id": job_id})

    task = asyncio.create_task(_run_job(st, job_id, target, scan_types))
    st.tasks.add(task)
    task.add_done_callback(st.tasks.discard)
    return web.json_response(st.jobs[job_id], status=202, headers={"Location": f"/jobs/{job_id}"})


async def _run_job(st: ApiState, job_id: str, target: str, scan_types: list | None) -> None:
    job = st.jobs[job_id]
    job["status"] = "running"
    try:
        result = await st.scanner.scan(
            target=target, scan_types=scan_types, output_formats=["json"],
            skip_auth_check=True,  # token holder is the operator
        )
        job.update(status="completed", scan_id=result.scan_id, risk_score=result.summary.get("risk_score", 0))
    except Exception as exc:
        logger.error(f"API scan job {job_id} failed: {exc}", exc_info=True)
        job.update(status="error", error=type(exc).__name__)
    finally:
        st.running_targets.discard(target)


async def get_job(request):
    job = request.app[STATE_KEY].jobs.get(request.match_info["job_id"])
    if job is None:
        raise web.HTTPNotFound(reason="job not found")
    return web.json_response(job)


def create_app(config: dict, scanner: Any, token: str, max_concurrent: int = 2) -> web.Application:
    app = web.Application(middlewares=[error_middleware, auth_middleware], client_max_size=MAX_BODY)
    app[TOKEN_KEY] = token
    app[STATE_KEY] = ApiState(config, scanner, max_concurrent)
    app.add_routes([
        web.get("/health", health),
        web.get("/scans", list_scans),
        web.get("/scans/{scan_id}", get_scan),
        web.get("/targets/{target:.+}/trend", get_trend),
        web.post("/scans", start_scan),
        web.get("/jobs/{job_id}", get_job),
    ])
    return app
