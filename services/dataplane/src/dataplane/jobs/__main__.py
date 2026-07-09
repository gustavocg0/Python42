"""Entry point: ``python -m dataplane.jobs`` (see package docstring)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from dataplane.jobs.runner import build_jobs, run_job_once, run_loop
from dataplane.jobs.tasks import JobContext
from dataplane.workers.common import (
    build_runtime,
    install_stop_signal_handlers,
    load_platform_config,
)

logger = logging.getLogger("dataplane.jobs")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m dataplane.jobs", description="data-plane jobs-scheduler"
    )
    parser.add_argument(
        "--once",
        metavar="JOB",
        help="run a single job by name and exit (tests/CI/runbooks)",
    )
    parser.add_argument("--list", action="store_true", help="list registered jobs and exit")
    return parser.parse_args(argv)


async def _amain(argv: list[str]) -> int:
    args = _parse_args(argv)
    jobs = build_jobs()
    if args.list:
        for job in jobs:
            print(f"{job.name}\tevery {job.interval_seconds}s")
        return 0

    runtime = await build_runtime(with_es=True)
    try:
        config = await load_platform_config(
            runtime.pool,
            {
                "billable_window_days": runtime.settings.billable_window_days,
                "dlq_retention_days": runtime.settings.dlq_retention_days,
                "trial_purge_after_days": runtime.settings.trial_purge_after_days,
                "heartbeat_interval_seconds": runtime.settings.heartbeat_interval_seconds,
                "agent_offline_after_missed_heartbeats": (
                    runtime.settings.agent_offline_after_missed_heartbeats
                ),
            },
        )
        ctx = JobContext(
            pool=runtime.pool,
            redis=runtime.redis,
            es=runtime.es,
            settings=runtime.settings,
            config=config,
        )
        if args.once:
            by_name = {job.name: job for job in jobs}
            job = by_name.get(args.once)
            if job is None:
                print(f"unknown job {args.once!r}; known: {sorted(by_name)}", file=sys.stderr)
                return 2
            ran = await run_job_once(ctx, job)
            return 0 if ran else 1

        stop = asyncio.Event()
        install_stop_signal_handlers(stop)
        logger.info("jobs-scheduler starting (%d jobs)", len(jobs))
        await run_loop(ctx, jobs, stop)
        logger.info("jobs-scheduler stopped")
        return 0
    finally:
        await runtime.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(asyncio.run(_amain(sys.argv[1:])))


if __name__ == "__main__":
    main()
