"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { AppShell } from "@/components/AppShell";
import { isApiError } from "@/lib/api/errors";
import { useMe } from "@/lib/hooks";

/**
 * Auth guard for all console routes. Session state comes from GET /v1/me
 * (HttpOnly cookie — SEC-2); 401 redirects to login.
 */
export default function ConsoleLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { data: me, isPending, error } = useMe();

  useEffect(() => {
    if (error && isApiError(error) && error.status === 401) {
      router.replace("/login");
    }
  }, [error, router]);

  if (isPending) {
    return (
      <p className="loading-state" style={{ padding: "2rem" }} role="status">
        Loading your console…
      </p>
    );
  }

  if (error || !me) {
    return (
      <p className="loading-state" style={{ padding: "2rem" }} role="status">
        Redirecting to sign-in…
      </p>
    );
  }

  return <AppShell me={me}>{children}</AppShell>;
}
