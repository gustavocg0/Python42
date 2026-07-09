"use client";

import { useQuery } from "@tanstack/react-query";
import * as dp from "@/lib/api/dataplane";
import { LoadingState } from "@/components/EmptyState";
import { QuotaDisplay } from "@/components/alerts/QuotaDisplay";
import { useEntitlements } from "@/lib/hooks";
import { formatDateTime, humanize } from "@/lib/format";

/** AC-88 usage vs quota (with 80% warning) + AC-18 read-only entitlements. */
export default function UsagePage() {
  const usageQuery = useQuery({
    queryKey: ["ingest-usage"],
    queryFn: dp.ingestUsage,
    refetchInterval: 30_000,
  });
  const entitlementsQuery = useEntitlements();
  const quotaQuery = useQuery({
    queryKey: ["deep-investigation-quota"],
    queryFn: dp.deepInvestigationQuota,
  });

  const usage = usageQuery.data;
  const ent = entitlementsQuery.data;
  const pct =
    usage && usage.events_per_min_limit > 0
      ? Math.min(
          100,
          Math.round((usage.events_per_min_current / usage.events_per_min_limit) * 100),
        )
      : 0;

  return (
    <div>
      <h1>Usage &amp; plan</h1>

      {/* Copy per ux spec §2.7 (AC-88). */}
      {usage?.warning_active ? (
        <div className="banner banner-warning banner-inline" role="alert">
          You&apos;re sending data close to your plan&apos;s limit (
          {usage.events_per_min_current.toLocaleString()} of{" "}
          {usage.events_per_min_limit.toLocaleString()} events/min). If you go
          over, we&apos;ll ask senders to slow down and retry — nothing is
          silently lost.
        </div>
      ) : null}
      {usage && usage.throttled_batches_24h > 0 ? (
        <div className="banner banner-warning banner-inline" role="status">
          Some data senders are being asked to slow down and retry (
          {usage.throttled_batches_24h} batches in the last 24 h). Data is
          delayed, not lost.
        </div>
      ) : null}

      <h2>Event ingestion</h2>
      {usageQuery.isPending ? (
        <LoadingState label="Loading usage…" />
      ) : usage ? (
        <div className="card">
          <p>
            <strong>{usage.events_per_min_current.toLocaleString()}</strong> of{" "}
            {usage.events_per_min_limit.toLocaleString()} events/minute ({pct}%)
          </p>
          <div
            className="meter"
            role="meter"
            aria-valuemin={0}
            aria-valuemax={usage.events_per_min_limit}
            aria-valuenow={usage.events_per_min_current}
            aria-label="Current ingest rate versus plan limit"
          >
            <div
              className={`meter-fill${pct >= 80 ? " warn" : ""}`}
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="card-row" style={{ marginTop: "0.75rem" }}>
            <div className="card">
              <div className="stat-value">{usage.throttled_batches_24h}</div>
              <div className="stat-label">Batches slowed down (last 24h)</div>
            </div>
            <div className="card">
              <div className="stat-value">{usage.rejected_events_24h}</div>
              <div className="stat-label">Events rejected (last 24h)</div>
            </div>
          </div>
        </div>
      ) : (
        <p className="muted">Usage data is briefly unavailable.</p>
      )}

      <h2>AI deep investigations</h2>
      {quotaQuery.data ? (
        <QuotaDisplay quota={quotaQuery.data} />
      ) : (
        <LoadingState label="Loading quota…" />
      )}

      <h2>Your plan</h2>
      {entitlementsQuery.isPending ? (
        <LoadingState label="Loading plan…" />
      ) : ent ? (
        <div className="card">
          <dl className="kv">
            <dt>Plan</dt>
            <dd>{humanize(ent.plan)}</dd>
            {ent.trial_expires_at ? (
              <>
                <dt>Trial expires</dt>
                <dd>{formatDateTime(ent.trial_expires_at)}</dd>
              </>
            ) : null}
            <dt>Endpoint cap</dt>
            <dd>{ent.entitlements.endpoint_cap} devices</dd>
            <dt>Event retention</dt>
            <dd>{ent.entitlements.retention_days} days</dd>
            <dt>Deep investigations</dt>
            <dd>
              {ent.entitlements.deep_investigation_daily_quota === -1
                ? "Unlimited"
                : `${ent.entitlements.deep_investigation_daily_quota} per day`}
            </dd>
            <dt>Ingest limit</dt>
            <dd>
              {ent.entitlements.ingest_events_per_min.toLocaleString()} events/minute
            </dd>
            <dt>Response mode</dt>
            <dd>
              {humanize(ent.entitlements.response_mode)}
              <span className="muted small">
                {" "}
                — the platform recommends actions; it never acts on your
                devices automatically on this plan.
              </span>
            </dd>
          </dl>
          <p className="muted small">As of {formatDateTime(ent.as_of)}.</p>
        </div>
      ) : (
        <p className="muted">Plan details are briefly unavailable.</p>
      )}
    </div>
  );
}
