"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Suspense } from "react";
import * as cp from "@/lib/api/controlplane";

function StatusInner() {
  const searchParams = useSearchParams();
  const accountId =
    searchParams.get("account_id") ??
    (() => {
      try {
        return sessionStorage.getItem("signup_account_id");
      } catch {
        return null;
      }
    })();

  const { data, isError } = useQuery({
    queryKey: ["provisioning-status", accountId],
    queryFn: () => cp.provisioningStatus(accountId as string),
    enabled: Boolean(accountId),
    // Poll until terminal state (verify -> ready target is <=60s p95, AC-3).
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state === "ready" || state === "provisioning_failed" ? false : 2500;
    },
  });

  if (!accountId) {
    return (
      <div className="auth-card">
        <h1>Setting up your workspace</h1>
        <p>
          Your email is verified and your workspace is being prepared. This
          usually takes under a minute — then you can{" "}
          <Link href="/login">sign in</Link>.
        </p>
      </div>
    );
  }

  if (data?.state === "provisioning_failed") {
    // AC-5: "we're on it" — no half-provisioned tenant is reachable.
    return (
      <div className="auth-card">
        <h1>We hit a snag — we&apos;re on it</h1>
        <p>
          Something went wrong while setting up your workspace. Our team has
          been alerted automatically and is fixing it. You will receive an
          email as soon as your workspace is ready. No action is needed from
          you.
        </p>
      </div>
    );
  }

  if (data?.state === "ready") {
    return (
      <div className="auth-card">
        <h1>Your workspace is ready</h1>
        <p>Everything is set up. Sign in to start onboarding your devices.</p>
        <Link className="btn btn-primary" href="/login">
          Sign in
        </Link>
      </div>
    );
  }

  return (
    <div className="auth-card">
      <h1>Setting up your workspace…</h1>
      <p role="status">
        {isError
          ? "Checking again in a moment…"
          : data?.state === "pending_verification"
            ? "Waiting for email verification."
            : "Creating your tenant, storage, and starter detection rules. This usually takes under a minute."}
      </p>
    </div>
  );
}

export default function ProvisioningStatusPage() {
  return (
    <div className="auth-page">
      <Suspense>
        <StatusInner />
      </Suspense>
    </div>
  );
}
