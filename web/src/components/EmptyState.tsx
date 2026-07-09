import Link from "next/link";

/**
 * AC-71: empty states explain what will appear and link to the relevant
 * onboarding step — no blank tables or unexplained spinners.
 */
export function EmptyState({
  title,
  body,
  ctaHref,
  ctaLabel,
}: {
  title: string;
  body: string;
  ctaHref?: string;
  ctaLabel?: string;
}) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      <p>{body}</p>
      {ctaHref && ctaLabel ? (
        <Link className="btn btn-primary" href={ctaHref}>
          {ctaLabel}
        </Link>
      ) : null}
    </div>
  );
}

export function LoadingState({ label }: { label: string }) {
  return (
    <p className="loading-state" role="status">
      {label}
    </p>
  );
}
