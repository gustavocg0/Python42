"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage, isApiError } from "@/lib/api/errors";
import type { CloseReason, Investigation } from "@/lib/api/types";
import {
  AiBadge,
  PriorityBadge,
  SeverityBadge,
  StateBadge,
} from "@/components/Badges";
import { CloseDialog } from "@/components/alerts/CloseDialog";
import { InvestigationResult } from "@/components/alerts/InvestigationResult";
import { QuotaDisplay } from "@/components/alerts/QuotaDisplay";
import { JsonView } from "@/components/JsonView";
import { LoadingState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { formatDateTime, humanize } from "@/lib/format";
import { techniqueDescription, techniqueName, techniqueUrl } from "@/lib/mitre";
import { parseTriageSummary } from "@/lib/triage";

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;
  const [showCloseDialog, setShowCloseDialog] = useState(false);
  const [quotaError, setQuotaError] = useState<string | null>(null);
  const [latestRun, setLatestRun] = useState<Investigation | null>(null);

  const alertQuery = useQuery({
    queryKey: ["alert", id],
    queryFn: () => dp.getAlert(id),
    // Triage may still be pending; poll briefly until it settles (AC-48/50).
    refetchInterval: (query) =>
      query.state.data?.triage.status === "pending" ? 10_000 : false,
  });

  const quotaQuery = useQuery({
    queryKey: ["deep-investigation-quota"],
    queryFn: dp.deepInvestigationQuota,
  });

  const runsQuery = useQuery({
    queryKey: ["deep-investigations", id],
    queryFn: () => dp.listDeepInvestigations(id),
  });

  const invalidateAlert = () => {
    queryClient.invalidateQueries({ queryKey: ["alert", id] });
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
  };

  const transition = useMutation({
    mutationFn: (action: "acknowledge" | "reopen") =>
      action === "acknowledge" ? dp.acknowledgeAlert(id) : dp.reopenAlert(id),
    onSuccess: invalidateAlert,
    onError: (err, action) =>
      pushToast({
        kind: "error",
        message: friendlyMessage(err),
        retry: () => transition.mutate(action),
      }),
  });

  const close = useMutation({
    mutationFn: (vars: { reason: CloseReason; comment?: string }) =>
      dp.closeAlert(id, vars.reason, vars.comment),
    onSuccess: () => {
      setShowCloseDialog(false);
      invalidateAlert();
    },
    onError: (err, vars) => {
      setShowCloseDialog(false);
      pushToast({
        kind: "error",
        message: friendlyMessage(err),
        retry: () => close.mutate(vars),
      });
    },
  });

  const investigate = useMutation({
    mutationFn: () => dp.runDeepInvestigation(id),
    onSuccess: (result) => {
      setQuotaError(null);
      setLatestRun(result);
      queryClient.setQueryData(["deep-investigation-quota"], result.quota);
      queryClient.invalidateQueries({ queryKey: ["deep-investigations", id] });
    },
    onError: (err) => {
      if (isApiError(err) && err.code === "QUOTA_EXCEEDED_DEEP_INVESTIGATION") {
        // AC-54 / ux spec §2.6: show reset time as UTC anchor + localized;
        // no quota was consumed by the failed attempt.
        const localized =
          typeof err.details?.resets_at === "string"
            ? ` (${formatDateTime(err.details.resets_at)}, your time)`
            : "";
        setQuotaError(
          `You've used all deep investigations for today. Your allowance resets at 00:00 UTC${localized}.`,
        );
        queryClient.invalidateQueries({ queryKey: ["deep-investigation-quota"] });
      } else if (isApiError(err) && err.code === "ENTITLEMENT_DENIED") {
        setQuotaError("Deep investigation isn't in your current plan.");
      } else {
        pushToast({
          kind: "error",
          message: friendlyMessage(err),
          retry: () => investigate.mutate(),
        });
      }
    },
  });

  if (alertQuery.isPending) return <LoadingState label="Loading alert…" />;
  if (alertQuery.isError) {
    return (
      <div>
        <h1>Alert not found</h1>
        <p className="muted">
          This alert does not exist or is no longer available.{" "}
          <Link href="/alerts">Back to the queue</Link>
        </p>
      </div>
    );
  }

  const alert = alertQuery.data;
  const quota = quotaQuery.data;
  const canRun = !quota || quota.limit === -1 || quota.remaining > 0;
  const runs = runsQuery.data?.items ?? [];
  const displayRuns = latestRun
    ? [latestRun, ...runs.filter((r) => r.investigation_id !== latestRun.investigation_id)]
    : runs;

  return (
    <div>
      <p className="small">
        <Link href="/alerts">← Alert queue</Link>
      </p>
      <h1>{alert.rule.title}</h1>
      {/* ux spec §2.2: labeled chips; collapse when rule and AI agree. */}
      <p>
        <PriorityBadge score={alert.priority_score} withBand />{" "}
        {alert.triage.status === "completed" && alert.triage.ai_severity ? (
          alert.triage.ai_severity === alert.rule.severity ? (
            <>
              <SeverityBadge severity={alert.rule.severity} />{" "}
              <span className="muted small">rule and AI agree</span>
            </>
          ) : (
            <>
              <SeverityBadge severity={alert.rule.severity} label="Detection rule" />{" "}
              <SeverityBadge severity={alert.triage.ai_severity} label="AI assessment" />
            </>
          )
        ) : (
          <SeverityBadge severity={alert.rule.severity} label="Detection rule" />
        )}{" "}
        <StateBadge state={alert.state} />
      </p>
      {alert.triage.status === "completed" &&
      alert.triage.ai_severity &&
      alert.triage.ai_severity !== alert.rule.severity ? (
        <p className="muted small">
          The detection rule and the AI reviewer rated this differently. The
          queue position (priority {alert.priority_score}) takes both into
          account.
        </p>
      ) : null}

      <p>
        {alert.state === "new" ? (
          <button
            type="button"
            className="btn"
            disabled={readOnly || transition.isPending}
            onClick={() => transition.mutate("acknowledge")}
          >
            Acknowledge
          </button>
        ) : null}{" "}
        {alert.state !== "closed" ? (
          <button
            type="button"
            className="btn"
            disabled={readOnly}
            onClick={() => setShowCloseDialog(true)}
          >
            Close…
          </button>
        ) : (
          <button
            type="button"
            className="btn"
            disabled={readOnly || transition.isPending}
            onClick={() => transition.mutate("reopen")}
          >
            Reopen
          </button>
        )}
      </p>

      {/* Summary card — labeled AI-generated (AC-49); three parsed sections
          per ux spec §1.1/§2.1; headings come from the client, not the model. */}
      <section className="card" aria-labelledby="triage-heading">
        <h2 id="triage-heading" style={{ marginTop: 0 }}>
          Summary <AiBadge />
        </h2>
        {alert.triage.status === "completed" && alert.triage.summary ? (
          <>
            {(() => {
              const parsed = parseTriageSummary(alert.triage.summary);
              return parsed ? (
                <>
                  <h3>What happened</h3>
                  <p className="plain-text">{parsed.whatHappened}</p>
                  <h3>Why it matters</h3>
                  <p className="plain-text">{parsed.whyItMatters}</p>
                  <h3>Do this next</h3>
                  <p className="plain-text">{parsed.doThisNext}</p>
                </>
              ) : (
                <p className="plain-text">{alert.triage.summary}</p>
              );
            })()}
            <p className="small muted">
              Written by AI model {alert.triage.model_id ?? "unknown"} at{" "}
              {formatDateTime(alert.triage.completed_at)}. It can be wrong —
              check the evidence below before taking major action.
            </p>
          </>
        ) : alert.triage.status === "pending" ? (
          <p className="muted">
            AI summary on the way — usually under 2 minutes. The alert is
            fully actionable in the meantime.
          </p>
        ) : (
          <p className="muted">
            An AI summary isn&apos;t available for this alert. The information
            below comes directly from the detection rule.
          </p>
        )}
      </section>

      <div className="card-row">
        <section className="card" aria-labelledby="entity-heading">
          <h2 id="entity-heading" style={{ marginTop: 0 }}>
            Affected
          </h2>
          <dl className="kv">
            <dt>Host</dt>
            <dd>
              {alert.entity.asset_id ? (
                <Link href={`/assets/${encodeURIComponent(alert.entity.asset_id)}`}>
                  {alert.entity.hostname ?? alert.entity.asset_id}
                </Link>
              ) : (
                (alert.entity.hostname ?? "—")
              )}
            </dd>
            <dt>User</dt>
            <dd>{alert.entity.user ?? "—"}</dd>
            <dt>Occurrences</dt>
            <dd>{alert.occurrence_count}</dd>
            <dt>First seen</dt>
            <dd>{formatDateTime(alert.first_seen)}</dd>
            <dt>Last seen</dt>
            <dd>{formatDateTime(alert.last_seen)}</dd>
          </dl>
        </section>

        <section className="card" aria-labelledby="score-heading">
          <h2 id="score-heading" style={{ marginTop: 0 }}>
            Priority score: {alert.priority_score}
          </h2>
          <dl className="kv">
            <dt>Rule severity</dt>
            <dd>{alert.priority_inputs.rule_severity}</dd>
            <dt>AI severity (raw)</dt>
            <dd>{alert.priority_inputs.ai_severity ?? "not available"}</dd>
            <dt>AI severity used for scoring</dt>
            <dd>{alert.priority_inputs.ai_severity_effective ?? "rule severity"}</dd>
            <dt>Occurrences</dt>
            <dd>{alert.priority_inputs.occurrence_count}</dd>
            <dt>Agent status</dt>
            <dd>{alert.priority_inputs.agent_status}</dd>
            <dt>Formula version</dt>
            <dd>{alert.priority_inputs.priority_formula_version}</dd>
          </dl>
        </section>
      </div>

      {/* ux spec §3.1: plain sentence leads; name · ID de-emphasized below. */}
      {alert.rule.mitre_technique_ids.length > 0 ? (
        <section aria-labelledby="mitre-heading">
          <h2 id="mitre-heading">Attack technique(s)</h2>
          <ul>
            {alert.rule.mitre_technique_ids.map((t) => (
              <li key={t} style={{ marginBottom: "0.5rem" }}>
                <div>{techniqueDescription(t)}</div>
                <div className="muted small">
                  {techniqueName(t) ? `${techniqueName(t)} · ` : ""}
                  {t} —{" "}
                  <a href={techniqueUrl(t)} target="_blank" rel="noreferrer noopener">
                    Learn more (MITRE ATT&amp;CK) ↗
                  </a>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {/* Progressive disclosure: raw evidence expandable, never hidden (AC-49). */}
      <h2>Evidence</h2>
      <details className="disclosure">
        <summary>
          Linked events ({alert.event_refs.length}) — raw detection data
        </summary>
        <div className="disclosure-body">
          <p className="muted small">
            References to the normalized events that triggered this alert.
          </p>
          <JsonView data={alert.event_refs} label="Linked event references" />
        </div>
      </details>
      <details className="disclosure">
        <summary>Rule details</summary>
        <div className="disclosure-body">
          <dl className="kv">
            <dt>Rule</dt>
            <dd>
              {alert.rule.id} v{alert.rule.version}
            </dd>
            <dt>Severity</dt>
            <dd>{alert.rule.severity}</dd>
          </dl>
        </div>
      </details>

      {alert.siblings.length > 0 ? (
        <section aria-labelledby="siblings-heading">
          <h2 id="siblings-heading">Related alerts (same incident)</h2>
          <p className="muted small">
            These alerts happened on the same host around the same time and are
            grouped together.{" "}
            {alert.correlation_group_id ? (
              <Link
                href={`/alerts?correlation_group_id=${encodeURIComponent(alert.correlation_group_id)}`}
              >
                View the group in the queue
              </Link>
            ) : null}
          </p>
          <ul>
            {alert.siblings.map((s) => (
              <li key={s.id}>
                <SeverityBadge severity={s.rule.severity} />{" "}
                <Link href={`/alerts/${encodeURIComponent(s.id)}`}>
                  {s.rule.title}
                </Link>{" "}
                <StateBadge state={s.state} />
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section aria-labelledby="di-heading">
        <h2 id="di-heading">Deep investigation</h2>
        {quota ? <QuotaDisplay quota={quota} /> : null}
        {quotaError ? (
          <p className="form-error" role="alert">
            {quotaError}
          </p>
        ) : null}
        <button
          type="button"
          className="btn btn-primary"
          disabled={readOnly || investigate.isPending || !canRun}
          onClick={() => investigate.mutate()}
        >
          {investigate.isPending
            ? "Running…"
            : quota && quota.limit !== -1 && quota.remaining > 0
              ? `Run deep investigation (${quota.remaining} of ${quota.limit} left today)`
              : "Run deep investigation"}
        </button>
        {displayRuns.length === 0 ? (
          <p className="muted small" style={{ marginTop: "0.5rem" }}>
            Past deep investigations for this alert will be listed here. You
            haven&apos;t run one yet.
          </p>
        ) : (
          displayRuns.map((run) => (
            <InvestigationResult key={run.investigation_id} inv={run} />
          ))
        )}
      </section>

      {alert.history.length > 0 ? (
        <section aria-labelledby="history-heading">
          <h2 id="history-heading">Action history</h2>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Who</th>
                  <th scope="col">Action</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {alert.history.map((h) => (
                  <tr key={h.id}>
                    <td>{formatDateTime(h.at)}</td>
                    <td>
                      {h.actor.type}: {h.actor.id}
                    </td>
                    <td>{humanize(h.action_type)}</td>
                    <td>{h.reason_code ? humanize(h.reason_code) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {alert.close_reason ? (
        <p className="muted small">
          Closed as {humanize(alert.close_reason)} by {alert.closed_by ?? "unknown"}{" "}
          at {formatDateTime(alert.closed_at)}.
        </p>
      ) : null}

      {showCloseDialog ? (
        <CloseDialog
          count={1}
          pending={close.isPending}
          onCancel={() => setShowCloseDialog(false)}
          onSubmit={(reason, comment) => close.mutate({ reason, comment })}
        />
      ) : null}
    </div>
  );
}
