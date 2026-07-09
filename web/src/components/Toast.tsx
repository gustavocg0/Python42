"use client";

/**
 * Minimal accessible toast system. Errors from failed actions surface here
 * with an optional Retry action (AC-73: retryable error toast, never a
 * silently lost action). Announced via aria-live.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export interface ToastInput {
  message: string;
  kind?: "error" | "success" | "info";
  /** When provided, the toast shows a Retry button and does not auto-dismiss. */
  retry?: () => void;
}

interface ToastItem extends ToastInput {
  id: number;
}

interface ToastContextValue {
  pushToast: (t: ToastInput) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const pushToast = useCallback(
    (input: ToastInput) => {
      const id = nextId.current++;
      setToasts((prev) => [...prev.slice(-4), { ...input, id }]);
      if (!input.retry) {
        setTimeout(() => dismiss(id), 6000);
      }
    },
    [dismiss],
  );

  const value = useMemo(() => ({ pushToast }), [pushToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-region" role="region" aria-label="Notifications">
        <div aria-live="polite" aria-atomic="false">
          {toasts.map((t) => (
            <div key={t.id} className={`toast toast-${t.kind ?? "info"}`} role="status">
              <span className="toast-message">{t.message}</span>
              <span className="toast-actions">
                {t.retry ? (
                  <button
                    type="button"
                    className="btn btn-small"
                    onClick={() => {
                      dismiss(t.id);
                      t.retry?.();
                    }}
                  >
                    Retry
                  </button>
                ) : null}
                <button
                  type="button"
                  className="btn btn-small btn-ghost"
                  aria-label="Dismiss notification"
                  onClick={() => dismiss(t.id)}
                >
                  ×
                </button>
              </span>
            </div>
          ))}
        </div>
      </div>
    </ToastContext.Provider>
  );
}
