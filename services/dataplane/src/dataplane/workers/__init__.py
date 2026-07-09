"""Data-plane pipeline workers (design §2/§4).

One module per worker process:
- ``dataplane.workers.normalizer``  — pipe:raw -> ES + pipe:normalized (+ asset obs)
- ``dataplane.workers.detector``    — pipe:normalized -> pipe:detections (detection-engineering)
- ``dataplane.workers.alerter``     — pipe:detections -> alerts + pipe:alerts.triage
- ``dataplane.workers.triager``     — pipe:alerts.triage -> triage fields (ai-platform)
- ``dataplane.workers.asset_dedup`` — pipe:asset.observations -> assets

Shared, self-contained runtime helpers live in ``dataplane.workers.common``.
"""
