"use client";

import { useEffect, useRef, type ReactNode } from "react";

/**
 * Accessible modal dialog: role=dialog + aria-modal, labelled by its title,
 * focuses the panel on open, closes on Escape, restores focus on close.
 */
export function Dialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useRef(`dlg-${Math.random().toString(36).slice(2, 9)}`);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previouslyFocused?.focus?.();
    };
  }, [onClose]);

  return (
    <div className="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={panelRef}
        className="dialog-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId.current}
        tabIndex={-1}
      >
        <div className="dialog-header">
          <h2 id={titleId.current}>{title}</h2>
          <button
            type="button"
            className="btn btn-ghost"
            aria-label="Close dialog"
            onClick={onClose}
          >
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
