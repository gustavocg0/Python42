"""Internal controlplane entrypoint: `python -m controlplane.internal_main`.

Serves ONLY /internal/v1 + health probes on CP_INTERNAL_HOST:CP_INTERNAL_PORT
(default 127.0.0.1:8101). Deployments must keep this listener on the internal
network (compose internal network / K8s NetworkPolicy) — the HMAC service
token auth is the second layer, not the only one (SEC-40).
"""

from __future__ import annotations

import uvicorn

from controlplane.config import Settings
from controlplane.internal_app import SERVICE_NAME, create_internal_app
from soc_telemetry import configure_json_logging, init_telemetry


def main() -> None:
    settings = Settings.from_env()
    configure_json_logging(SERVICE_NAME)
    init_telemetry(SERVICE_NAME)
    app = create_internal_app(settings)
    uvicorn.run(app, host=settings.internal_host, port=settings.internal_port, log_config=None)


if __name__ == "__main__":
    main()
