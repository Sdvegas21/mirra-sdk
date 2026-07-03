"""The gateway HTTP server — the frozen v1 contract over a network boundary.

Endpoints (JSON in / JSON out, bearer auth on everything except /v1/health):

    GET  /v1/health
    POST /v1/identity/resolve     {principal}
    POST /v1/memory/remember      {principal, subject_id, content}
    POST /v1/memory/recall        {principal, subject_id, query?}
    POST /v1/execution/authorize  {principal, sink_type, target, arguments?, provenance?}
    POST /v1/execution/verify     {principal, record}
    POST /v1/interact             {principal, subject_id, message}

Every tenant is served by its own WrappedAgent composition rooted in the
tenant's isolated home directory — the identical core the SDK edge uses,
constructed through mirra.wrap(). Stdlib-only (no web framework dependency).
"""

from __future__ import annotations

import dataclasses
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

import mirra
from mirra_core_contract import DecisionRecord

from .mission_control import MissionControlEmitter
from .tenants import RateLimiter, Tenant, TenantRegistry


def _default_hosted_agent(message: str, context: dict) -> str:
    """Reference hosted agent: proves per-relationship context over the wire."""
    history = context["history"]
    if not history:
        return f"Hello {context['subject_id']} — we haven't met before."
    return (
        f"Welcome back {context['subject_id']} — I remember {len(history)} "
        f"interaction(s) with you."
    )


class GatewayServer:
    """Routes authenticated tenant requests onto per-tenant wrapped cores."""

    def __init__(
        self,
        registry: TenantRegistry,
        profile: str = "dev_balanced",
        agent_factory: Optional[Callable[[Tenant], Any]] = None,
        rate_limiter: Optional[RateLimiter] = None,
        mission_control: Optional[MissionControlEmitter] = None,
    ):
        self._registry = registry
        self._profile = profile
        self._agent_factory = agent_factory or (lambda tenant: _default_hosted_agent)
        self._limiter = rate_limiter or RateLimiter()
        self._mission_control = mission_control
        self._wrapped: dict[tuple[str, str], Any] = {}
        self._lock = threading.Lock()

    # -- core plumbing ---------------------------------------------------------

    def _wrapped_for(self, tenant: Tenant, principal: str):
        key = (tenant.tenant_id, principal)
        with self._lock:
            if key not in self._wrapped:
                self._wrapped[key] = mirra.wrap(
                    self._agent_factory(tenant),
                    principal=f"{tenant.tenant_id}:{principal}",
                    home=tenant.home,
                    profile=self._profile,
                )
            return self._wrapped[key]

    # -- request handling ------------------------------------------------------

    def handle(self, method: str, path: str, bearer: Optional[str], body: dict) -> tuple[int, dict]:
        if method == "GET" and path == "/v1/health":
            return 200, {"status": "ok", "edge": "gateway", "contract": "v1"}

        tenant = self._registry.authenticate(bearer)
        if tenant is None:
            return 401, {"error": "invalid or missing bearer key"}
        if not self._limiter.allow(tenant.tenant_id):
            return 429, {"error": "rate limit exceeded"}

        try:
            return self._route(tenant, method, path, body)
        except mirra.MemoryUnavailable as exc:
            return 503, {"error": f"memory backend unavailable: {exc}"}
        except (KeyError, TypeError, ValueError) as exc:
            return 400, {"error": f"bad request: {exc}"}

    def _route(self, tenant: Tenant, method: str, path: str, body: dict) -> tuple[int, dict]:
        if method != "POST":
            return 405, {"error": "method not allowed"}

        principal = str(body["principal"])
        wrapped = self._wrapped_for(tenant, principal)

        if path == "/v1/identity/resolve":
            return 200, {"identity": dataclasses.asdict(wrapped.identity)}

        if path == "/v1/memory/remember":
            scroll = wrapped.remember(str(body["subject_id"]), body["content"])
            return 200, {"scroll": dataclasses.asdict(scroll)}

        if path == "/v1/memory/recall":
            scrolls = wrapped.recall(str(body["subject_id"]), body.get("query"))
            return 200, {"scrolls": [dataclasses.asdict(s) for s in scrolls]}

        if path == "/v1/execution/authorize":
            record = wrapped.execute(
                sink_type=str(body["sink_type"]),
                target=str(body["target"]),
                arguments=body.get("arguments") or {},
                provenance=body.get("provenance") or {},
            )
            verification = wrapped.verify_decision(record)
            if self._mission_control is not None:
                self._mission_control.emit(tenant.tenant_id, record, verification)
            return 200, {
                "record": dataclasses.asdict(record),
                "verification": dataclasses.asdict(verification),
            }

        if path == "/v1/execution/verify":
            record = DecisionRecord(**body["record"])
            return 200, {"verification": dataclasses.asdict(wrapped.verify_decision(record))}

        if path == "/v1/interact":
            response = wrapped.interact(str(body["subject_id"]), str(body["message"]))
            return 200, {"response": response}

        return 404, {"error": f"unknown endpoint {path}"}


def make_server(gateway: GatewayServer, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Bind the gateway to an HTTP server (loopback by default)."""

    class Handler(BaseHTTPRequestHandler):
        def _respond(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
                if not isinstance(body, dict):
                    raise ValueError("body must be a JSON object")
            except Exception as exc:
                self._send(400, {"error": f"invalid JSON: {exc}"})
                return

            auth = self.headers.get("Authorization") or ""
            bearer = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else None
            status, payload = gateway.handle(self.command, self.path, bearer, body)
            self._send(status, payload)

        def _send(self, status: int, payload: dict) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            self._respond()

        def do_POST(self) -> None:  # noqa: N802
            self._respond()

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

    return ThreadingHTTPServer((host, port), Handler)
