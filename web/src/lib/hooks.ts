"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import * as cp from "@/lib/api/controlplane";
import { useTenantState } from "@/components/TenantState";

/** Session/auth state via GET /v1/me (session cookie is HttpOnly — SEC-2). */
export function useMe() {
  const { syncFromTenant } = useTenantState();
  const query = useQuery({
    queryKey: ["me"],
    queryFn: cp.me,
    staleTime: 60_000,
    retry: false,
  });

  useEffect(() => {
    if (query.data?.tenant) syncFromTenant(query.data.tenant);
  }, [query.data, syncFromTenant]);

  return query;
}

export function useIsAdmin(): boolean {
  const { data } = useMe();
  return data?.user.role === "admin";
}

export function useEntitlements() {
  return useQuery({
    queryKey: ["entitlements"],
    queryFn: cp.entitlements,
    staleTime: 60_000,
  });
}
