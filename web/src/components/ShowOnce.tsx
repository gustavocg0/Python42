"use client";

import { useState } from "react";

/**
 * Show-once secret display (ingest keys AC-29, enrollment tokens AC-56).
 * The secret lives only in component state for the current view — it is
 * never written to localStorage or anywhere persistent (SEC-2).
 */
export function ShowOnceSecret({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard unavailable (permissions/HTTP): user can select the text.
    }
  }

  return (
    <div className="show-once">
      <p className="show-once-warning" role="alert">
        <strong>{label} — shown only once.</strong> Copy it now; you will not be
        able to see it again. {hint ?? ""}
      </p>
      <div className="show-once-value">
        <code>{value}</code>
        <button type="button" className="btn btn-small" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}
