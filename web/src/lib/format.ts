/** Date/number formatting helpers. All API timestamps are RFC3339 UTC. */

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffMs = Date.now() - then;
  const future = diffMs < 0;
  const s = Math.round(Math.abs(diffMs) / 1000);
  let text: string;
  if (s < 60) text = `${s}s`;
  else if (s < 3600) text = `${Math.round(s / 60)}m`;
  else if (s < 86400) text = `${Math.round(s / 3600)}h`;
  else text = `${Math.round(s / 86400)}d`;
  return future ? `in ${text}` : `${text} ago`;
}

export function isPast(iso: string | null | undefined): boolean {
  if (!iso) return false;
  const t = new Date(iso).getTime();
  return !Number.isNaN(t) && t < Date.now();
}

/** "false_positive" -> "False positive" */
export function humanize(value: string): string {
  const withSpaces = value.replace(/[_-]+/g, " ").trim();
  return withSpaces.charAt(0).toUpperCase() + withSpaces.slice(1);
}
