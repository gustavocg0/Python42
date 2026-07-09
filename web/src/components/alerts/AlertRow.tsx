"use client";

import Link from "next/link";
import type { Alert } from "@/lib/api/types";
import { formatRelative, humanize } from "@/lib/format";
import { triageOneLiner } from "@/lib/triage";
import { AiBadge, PriorityBadge, SeverityBadge, StateBadge } from "../Badges";

/**
 * One queue row (AC-72): priority, severity, title, AI one-liner (or rule
 * title when triage is unavailable), host/user, occurrence count, first/last
 * seen, state. All event-derived and AI strings render as plain text (SEC-31).
 */
export function AlertRow({
  alert,
  selected,
  onToggleSelect,
  onAcknowledge,
  onRequestClose,
  actionsDisabled,
}: {
  alert: Alert;
  selected: boolean;
  onToggleSelect: (id: string) => void;
  onAcknowledge: (id: string) => void;
  onRequestClose: (id: string) => void;
  actionsDisabled?: boolean;
}) {
  const triaged = alert.triage.status === "completed" && alert.triage.summary;
  // ux spec §2.1: first sentence of "What happened"; rule title when no triage.
  const oneLiner = triaged
    ? triageOneLiner(alert.triage.summary as string)
    : alert.rule.title;
  // ux spec §2.2: rule chip always; compact AI tag only when AI disagrees.
  const aiDiffers =
    alert.triage.status === "completed" &&
    alert.triage.ai_severity !== null &&
    alert.triage.ai_severity !== alert.rule.severity;

  return (
    <tr className={selected ? "selected" : undefined} data-testid="alert-row">
      <td>
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onToggleSelect(alert.id)}
          aria-label={`Select alert: ${alert.rule.title}`}
        />
      </td>
      <td>
        <PriorityBadge score={alert.priority_score} />
      </td>
      <td>
        <SeverityBadge severity={alert.rule.severity} />
        {aiDiffers ? (
          <span className={`badge sev-${alert.triage.ai_severity}`} style={{ marginLeft: "0.25rem" }}>
            AI: {humanize(alert.triage.ai_severity as string)}
          </span>
        ) : null}
      </td>
      <td>
        <Link href={`/alerts/${encodeURIComponent(alert.id)}`}>
          {alert.rule.title}
        </Link>
        <div className="one-liner muted small">
          {triaged ? <AiBadge compact /> : null} <span>{oneLiner}</span>
        </div>
      </td>
      <td>
        <div>{alert.entity.hostname ?? "—"}</div>
        <div className="muted small">{alert.entity.user ?? ""}</div>
      </td>
      <td>{alert.occurrence_count}</td>
      <td className="small">
        <div title={alert.first_seen}>first {formatRelative(alert.first_seen)}</div>
        <div title={alert.last_seen}>last {formatRelative(alert.last_seen)}</div>
      </td>
      <td>
        <StateBadge state={alert.state} />
      </td>
      <td>
        {alert.state === "new" ? (
          <button
            type="button"
            className="btn btn-small"
            disabled={actionsDisabled}
            onClick={() => onAcknowledge(alert.id)}
          >
            Acknowledge
          </button>
        ) : null}{" "}
        {alert.state !== "closed" ? (
          <button
            type="button"
            className="btn btn-small"
            disabled={actionsDisabled}
            onClick={() => onRequestClose(alert.id)}
          >
            Close
          </button>
        ) : null}
      </td>
    </tr>
  );
}
