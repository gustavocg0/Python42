import type { AgentStatus, AlertState, Severity } from "@/lib/api/types";
import { humanize } from "@/lib/format";
import { priorityBand } from "@/lib/triage";

export function SeverityBadge({
  severity,
  label,
}: {
  severity: Severity;
  label?: string;
}) {
  return (
    <span className={`badge sev-${severity}`}>
      {label ? `${label}: ` : ""}
      {humanize(severity)}
    </span>
  );
}

export function PriorityBadge({
  score,
  withBand,
}: {
  score: number;
  /** ux spec §2.2: "Priority {n}" with a scanning band label. */
  withBand?: boolean;
}) {
  const tier =
    score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low";
  return (
    <span
      className={`badge priority sev-${tier}`}
      aria-label={`Priority score ${score} out of 100${withBand ? ` — ${priorityBand(score)}` : ""}`}
      title={priorityBand(score)}
    >
      {withBand ? `Priority ${score} — ${priorityBand(score)}` : score}
    </span>
  );
}

export function StateBadge({ state }: { state: AlertState }) {
  return <span className={`badge state-${state}`}>{humanize(state)}</span>;
}

export function AgentStatusBadge({ status }: { status: AgentStatus }) {
  return <span className={`badge agent-${status}`}>{humanize(status)}</span>;
}

/** Tooltip copy per ux spec §2.1. */
const AI_TOOLTIP =
  "This summary was written by an AI model from this alert's detection data. It can be wrong. Check the evidence below before taking major action.";

/** AC-49: AI output must be visibly labeled as AI-generated. */
export function AiBadge({ compact }: { compact?: boolean }) {
  return (
    <span className="badge ai-badge" title={AI_TOOLTIP}>
      {compact ? "AI" : "AI-generated"}
    </span>
  );
}
