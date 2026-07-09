"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { Suspense, useState, type FormEvent } from "react";
import * as cp from "@/lib/api/controlplane";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage, isApiError } from "@/lib/api/errors";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await cp.login(email, password);
      queryClient.setQueryData(["me"], { user: result.user, tenant: result.tenant });
      const next = searchParams.get("next");
      if (next && next.startsWith("/") && !next.startsWith("//")) {
        router.replace(next);
        return;
      }
      // AC-70: guide new tenants into onboarding; others go to the queue.
      try {
        const onboarding = await dp.onboardingStatus();
        const incomplete = onboarding.steps.some((s) => s.state === "todo");
        router.replace(incomplete ? "/onboarding" : "/alerts");
      } catch {
        router.replace("/alerts");
      }
    } catch (err) {
      if (isApiError(err) && err.status === 401) {
        setError("That email and password combination did not work.");
      } else {
        setError(friendlyMessage(err));
      }
      setBusy(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Sign in</h1>
        <form onSubmit={onSubmit} noValidate>
          <div className="field">
            <label htmlFor="email">Work email</label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error ? (
            <p className="form-error" role="alert">
              {error}
            </p>
          ) : null}
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="small" style={{ marginTop: "1rem" }}>
          New here? <Link href="/signup">Start a free trial</Link>
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
