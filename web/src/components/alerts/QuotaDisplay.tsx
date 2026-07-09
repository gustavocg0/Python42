import type { DeepInvestigationQuota } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";

/**
 * Deep-investigation quota state (AC-53/54): remaining runs and, when
 * exhausted, the reset time (00:00 UTC daily).
 */
export function QuotaDisplay({ quota }: { quota: DeepInvestigationQuota }) {
  if (quota.limit === -1) {
    return (
      <p className="muted small" data-testid="quota-display">
        Deep investigations: unlimited on your plan.
      </p>
    );
  }
  if (quota.remaining <= 0) {
    // ux spec §2.6: show BOTH the 00:00 UTC anchor and the localized time.
    return (
      <p className="form-error small" data-testid="quota-display" role="status">
        You&apos;ve used all {quota.limit} deep investigations for today. Your
        allowance resets at 00:00 UTC ({formatDateTime(quota.resets_at)}, your
        time).
      </p>
    );
  }
  return (
    <p className="muted small" data-testid="quota-display">
      {quota.remaining} of {quota.limit} deep investigations left today
      (resets at 00:00 UTC — {formatDateTime(quota.resets_at)}, your time).
    </p>
  );
}
