"""Public controlplane-api entrypoint: `python -m controlplane.main`.

Serves the PUBLIC surface on CP_HOST:CP_PORT (default 0.0.0.0:8001).
The internal surface is a separate process — `python -m
controlplane.internal_main` — so internal routes are never reachable through
the public listener (SEC-30/40). Run both in compose/K8s.
"""

from __future__ import annotations

import uvicorn

from controlplane.app import SERVICE_NAME, create_public_app
from controlplane.config import Settings
from soc_telemetry import configure_json_logging, init_telemetry


def main() -> None:
    settings = Settings.from_env()
    configure_json_logging(SERVICE_NAME)
    init_telemetry(SERVICE_NAME)
    app = create_public_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_config=None)


if __name__ == "__main__":
    main()
