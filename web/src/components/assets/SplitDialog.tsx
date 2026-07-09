"use client";

import { useState } from "react";
import type { Asset } from "@/lib/api/types";
import { Dialog } from "../Dialog";

/**
 * Manual asset split (AC-25): admin picks the identities to move to a new
 * asset and must give a reason. Pins prevent automatic re-merge.
 */
export function SplitDialog({
  asset,
  onSubmit,
  onCancel,
  pending,
}: {
  asset: Asset;
  onSubmit: (identityIds: string[], reason: string) => void;
  onCancel: () => void;
  pending?: boolean;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState("");

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const valid =
    selected.size >= 1 &&
    selected.size < asset.identities.length &&
    reason.trim().length > 0;

  return (
    <Dialog title="Split this asset" onClose={onCancel}>
      <p className="muted small">
        Choose the identifier(s) that actually belong to a different device.
        They will move to a new asset record, and the two will not be
        automatically merged again.
      </p>
      <fieldset>
        <legend>Identifiers to move to a new asset</legend>
        {asset.identities.map((ident) => (
          <div className="radio-option" key={ident.id}>
            <input
              type="checkbox"
              id={`split-${ident.id}`}
              checked={selected.has(ident.id)}
              onChange={() => toggle(ident.id)}
            />
            <label htmlFor={`split-${ident.id}`}>
              <code>{ident.value}</code>{" "}
              <span className="muted small">
                ({ident.identifier_type}, from {ident.source})
              </span>
            </label>
          </div>
        ))}
      </fieldset>
      {selected.size === asset.identities.length ? (
        <p className="form-error small">
          At least one identifier must stay on this asset.
        </p>
      ) : null}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) onSubmit([...selected], reason.trim());
        }}
      >
        <div className="field">
          <label htmlFor="split-reason">Why is this a different device? (required)</label>
          <textarea
            id="split-reason"
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
          <button type="submit" className="btn btn-primary" disabled={!valid || pending}>
            {pending ? "Splitting…" : "Split asset"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
