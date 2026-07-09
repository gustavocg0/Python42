"use client";

/**
 * Tenant read-only ("frozen") state. Two sources of truth:
 *  1. Proactive: GET /v1/me tenant status (trial expired / abuse frozen).
 *  2. Reactive: any API call answering 403 TENANT_FROZEN (the authoritative
 *     enforcement signal) flips the banner mode immediately.
 * UI disabling is a courtesy — the server is always the enforcement (AC-17).
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { TenantInfo } from "@/lib/api/types";
import { isPast } from "@/lib/format";

export type FrozenCause = "trial" | "abuse" | null;

interface TenantStateValue {
  frozenCause: FrozenCause;
  /** Called by the central API handler on 403 TENANT_FROZEN. */
  reportFrozen: (cause: "trial" | "abuse" | undefined) => void;
  /** Derive proactive state from /v1/me tenant info. */
  syncFromTenant: (tenant: TenantInfo) => void;
}

const TenantStateContext = createContext<TenantStateValue | null>(null);

export function useTenantState(): TenantStateValue {
  const ctx = useContext(TenantStateContext);
  if (!ctx) throw new Error("useTenantState must be used inside <TenantStateProvider>");
  return ctx;
}

export function frozenCauseFromTenant(tenant: TenantInfo): FrozenCause {
  if (tenant.abuse_frozen) return "abuse";
  if (tenant.status === "frozen") return "trial";
  if (tenant.trial_expires_at && isPast(tenant.trial_expires_at)) return "trial";
  return null;
}

export function TenantStateProvider({ children }: { children: ReactNode }) {
  const [frozenCause, setFrozenCause] = useState<FrozenCause>(null);

  const reportFrozen = useCallback((cause: "trial" | "abuse" | undefined) => {
    setFrozenCause(cause ?? "trial");
  }, []);

  const syncFromTenant = useCallback((tenant: TenantInfo) => {
    setFrozenCause(frozenCauseFromTenant(tenant));
  }, []);

  const value = useMemo(
    () => ({ frozenCause, reportFrozen, syncFromTenant }),
    [frozenCause, reportFrozen, syncFromTenant],
  );

  return (
    <TenantStateContext.Provider value={value}>{children}</TenantStateContext.Provider>
  );
}
