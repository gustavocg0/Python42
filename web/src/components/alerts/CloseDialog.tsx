"use client";

import { useState } from "react";
import { CLOSE_REASONS, type CloseReason } from "@/lib/api/types";
import { Dialog } from "../Dialog";

// Labels per ux spec §2.3, mapped to the contract's close reasons (AC-45).
const REASON_LABELS: Record<CloseReason, string> = {
  resolved: "Fixed — I dealt with it",
  false_positive: "False alarm — this was not a real problem",
  expected_behavior: "Expected behavior — this is normal in my environment",
  duplicate: "Duplicate — already covered by another alert",
};

/**
 * Close-alert dialog. A close reason is REQUIRED (AC-45); the submit button
 * stays disabled until one is chosen.
 */
export function CloseDialog({
  count,
  onSubmit,
  onCancel,
  pending,
}: {
  count: number;
  onSubmit: (reason: CloseReason, comment?: string) => void;
  onCancel: () => void;
  pending?: boolean;
}) {
  const [reason, setReason] = useState<CloseReason | null>(null);
  const [comment, setComment] = useState("");

  return (
    <Dialog
      title={count === 1 ? "Close alert" : `Close ${count} alerts`}
      onClose={onCancel}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (reason) onSubmit(reason, comment.trim() || undefined);
        }}
      >
        <fieldset>
          <legend>Why are you closing {count === 1 ? "this alert" : "these alerts"}?</legend>
          {CLOSE_REASONS.map((r) => (
            <div className="radio-option" key={r}>
              <input
                type="radio"
                id={`close-reason-${r}`}
                name="close-reason"
                value={r}
                checked={reason === r}
                onChange={() => setReason(r)}
              />
              <label htmlFor={`close-reason-${r}`}>{REASON_LABELS[r]}</label>
            </div>
          ))}
        </fieldset>
        <div className="field">
          <label htmlFor="close-comment">Comment (optional)</label>
          <textarea
            id="close-comment"
            rows={2}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>
        <div className="dialog-actions">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={!reason || pending}
          >
            {pending ? "Closing…" : "Close alert" + (count > 1 ? "s" : "")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
