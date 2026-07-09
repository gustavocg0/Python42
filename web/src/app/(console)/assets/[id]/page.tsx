"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import { AgentStatusBadge } from "@/components/Badges";
import { JsonView } from "@/components/JsonView";
import { LoadingState } from "@/components/EmptyState";
import { SplitDialog } from "@/components/assets/SplitDialog";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { useIsAdmin } from "@/lib/hooks";
import { formatDateTime } from "@/lib/format";

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;
  const [showSplit, setShowSplit] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);

  const assetQuery = useQuery({
    queryKey: ["asset", id],
    queryFn: () => dp.getAsset(id),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["asset", id] });
    queryClient.invalidateQueries({ queryKey: ["assets"] });
    queryClient.invalidateQueries({ queryKey: ["billable-count"] });
  };

  const split = useMutation({
    mutationFn: (vars: { identityIds: string[]; reason: string }) =>
      dp.splitAsset(id, vars.identityIds, vars.reason),
    onSuccess: () => {
      setShowSplit(false);
      invalidate();
      pushToast({ kind: "success", message: "Asset split into two records." });
    },
    onError: (err) => {
      setShowSplit(false);
      pushToast({ kind: "error", message: `Split failed: ${friendlyMessage(err)}` });
    },
  });

  const revoke = useMutation({
    mutationFn: (deviceId: string) => dp.revokeDevice(deviceId),
    onSuccess: () => {
      setConfirmRevoke(false);
      invalidate();
      pushToast({
        kind: "success",
        message:
          "Device revoked. Its agent will be rejected at its next connection (within a minute).",
      });
    },
    onError: (err) => {
      setConfirmRevoke(false);
      pushToast({ kind: "error", message: `Revoke failed: ${friendlyMessage(err)}` });
    },
  });

  if (assetQuery.isPending) return <LoadingState label="Loading asset…" />;
  if (assetQuery.isError) {
    return (
      <div>
        <h1>Asset not found</h1>
        <p className="muted">
          This asset does not exist or is no longer available.{" "}
          <Link href="/assets">Back to assets</Link>
        </p>
      </div>
    );
  }

  const asset = assetQuery.data;

  return (
    <div>
      <p className="small">
        <Link href="/assets">← Assets</Link>
      </p>
      <h1>{asset.hostname}</h1>
      <p>
        <AgentStatusBadge status={asset.agent_status} />{" "}
        {asset.billable ? (
          <span className="badge">Billable</span>
        ) : (
          <span className="badge state-closed">Not billable</span>
        )}
      </p>

      <div className="card-row">
        <section className="card" aria-labelledby="asset-info">
          <h2 id="asset-info" style={{ marginTop: 0 }}>
            Device
          </h2>
          <dl className="kv">
            <dt>OS</dt>
            <dd>
              {asset.os_name} ({asset.os_version})
            </dd>
            <dt>Sources</dt>
            <dd>{asset.sources.join(", ")}</dd>
            <dt>First seen</dt>
            <dd>{formatDateTime(asset.first_seen)}</dd>
            <dt>Last seen</dt>
            <dd>{formatDateTime(asset.last_seen)}</dd>
            <dt>Created via</dt>
            <dd>{asset.created_via}</dd>
          </dl>
        </section>

        {asset.agent ? (
          <section className="card" aria-labelledby="agent-info">
            <h2 id="agent-info" style={{ marginTop: 0 }}>
              Agent
            </h2>
            <dl className="kv">
              <dt>Device ID</dt>
              <dd>
                <code>{asset.agent.device_id}</code>
              </dd>
              <dt>Version</dt>
              <dd>{asset.agent.version}</dd>
              <dt>Last heartbeat</dt>
              <dd>{formatDateTime(asset.agent.last_heartbeat_at)}</dd>
            </dl>
            {isAdmin && asset.agent_status !== "revoked" ? (
              confirmRevoke ? (
                <p>
                  <span className="form-error">
                    Revoke this device? Its telemetry stops and it becomes
                    non-billable.
                  </span>{" "}
                  <button
                    type="button"
                    className="btn btn-danger btn-small"
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(asset.agent!.device_id)}
                  >
                    Yes, revoke
                  </button>{" "}
                  <button
                    type="button"
                    className="btn btn-small"
                    onClick={() => setConfirmRevoke(false)}
                  >
                    Cancel
                  </button>
                </p>
              ) : (
                <button
                  type="button"
                  className="btn btn-danger btn-small"
                  disabled={readOnly}
                  onClick={() => setConfirmRevoke(true)}
                >
                  Revoke device…
                </button>
              )
            ) : null}
          </section>
        ) : null}
      </div>

      {/* AC-24: all contributing sources/identifiers, so merges are auditable. */}
      <section aria-labelledby="identities-heading">
        <h2 id="identities-heading">Identities</h2>
        <p className="muted small">
          Every identifier that has been matched to this device. Multiple
          sources reporting the same device are merged into one billable asset.
        </p>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">Type</th>
                <th scope="col">Value</th>
              </tr>
            </thead>
            <tbody>
              {asset.identities.map((ident) => (
                <tr key={ident.id ?? `${ident.identifier_type}:${ident.value}`}>
                  <td>{ident.source}</td>
                  <td>{ident.identifier_type}</td>
                  <td>
                    <code>{ident.value}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {isAdmin && asset.identities.length > 1 ? (
          <p style={{ marginTop: "0.75rem" }}>
            <button
              type="button"
              className="btn"
              disabled={readOnly}
              onClick={() => setShowSplit(true)}
            >
              This is actually two devices — split…
            </button>
          </p>
        ) : null}
      </section>

      <section aria-labelledby="merge-audit-heading">
        <h2 id="merge-audit-heading">Merge history</h2>
        {asset.merge_audit.length === 0 ? (
          <p className="muted">No merges — this asset came from a single source.</p>
        ) : (
          <>
            <p className="muted small">
              Why records were combined into this asset (AC-24 audit trail).
            </p>
            <ul>
              {asset.merge_audit.map((m, i) => (
                <li key={i}>
                  <span className="muted small">{formatDateTime(m.at)}</span> —
                  rule <code>{m.rule}</code>, by {m.actor}
                  <details className="disclosure" style={{ marginTop: "0.3rem" }}>
                    <summary>Merged identity details</summary>
                    <div className="disclosure-body">
                      <JsonView data={m.merged_identity} label="Merged identity" />
                    </div>
                  </details>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <p className="small">
        <Link href={`/alerts?host=${encodeURIComponent(asset.hostname)}`}>
          View alerts for this host
        </Link>
      </p>

      {showSplit ? (
        <SplitDialog
          asset={asset}
          pending={split.isPending}
          onCancel={() => setShowSplit(false)}
          onSubmit={(identityIds, reason) => split.mutate({ identityIds, reason })}
        />
      ) : null}
    </div>
  );
}
