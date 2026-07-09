"use client";

import { useState } from "react";
import type { Asset } from "@/lib/api/types";
import { Dialog } from "../Dialog";

/**
 * Manual asset merge (AC-25): admin selects >=2 assets and must give a
 * reason. The correction is pinned server-side against auto re-split.
 */
export function MergeDialog({
  assets,
  onSubmit,
  onCancel,
  pending,
}: {
  assets: Asset[];
  onSubmit: (reason: string) => void;
  onCancel: () => void;
  pending?: boolean;
}) {
  const [reason, setReason] = useState("");

  return (
    <Dialog title={`Merge ${assets.length} assets into one`} onClose={onCancel}>
      <p className="muted small">
        These records will become a single billable asset. This is
        forward-looking and will be remembered so they are not automatically
        split again.
      </p>
      <ul>
        {assets.map((a) => (
          <li key={a.id}>
            {a.hostname} <span className="muted small">({a.os_name})</span>
          </li>
        ))}
      </ul>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (reason.trim()) onSubmit(reason.trim());
        }}
      >
        <div className="field">
          <label htmlFor="merge-reason">Why are these the same device? (required)</label>
          <textarea
            id="merge-reason"
            rows={2}
            required
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        <div className="dialog-actions">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={!reason.trim() || pending}
          >
            {pending ? "Merging…" : "Merge assets"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
