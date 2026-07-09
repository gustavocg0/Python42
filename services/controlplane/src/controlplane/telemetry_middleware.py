"""Per-request OTel span middleware (AC-91; consumed by the observability agent).

One span per request with method/path/status attributes. Handlers run inside
the span context, so their logs (soc_telemetry JSON formatter) carry
trace/span ids, and audit/security events correlate to the request trace.
Tenant context itself lives in the soc_tenancy contextvar, scoped to the
request task — it cannot bleed across requests.
"""

from __future__ import annotations

from opentelemetry import trace


def install_request_spans(app, service_name: str) -> None:
    tracer = trace.get_tracer(service_name)

    @app.middleware("http")
    async def _request_span(request, call_next):
        with tracer.start_as_current_span(f"{request.method} {request.url.path}") as span:
            span.set_attribute("http.request.method", request.method)
            span.set_attribute("url.path", request.url.path)
            response = await call_next(request)
            span.set_attribute("http.response.status_code", response.status_code)
            return response
