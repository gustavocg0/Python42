"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import * as cp from "@/lib/api/controlplane";
import { friendlyMessage, isApiError } from "@/lib/api/errors";

type Phase = "verifying" | "failed";

function VerifyInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  const accountIdParam = searchParams.get("account_id");
  const [phase, setPhase] = useState<Phase>("verifying");
  const [error, setError] = useState<string | null>(null);
  const [resendEmail, setResendEmail] = useState("");
  const [resent, setResent] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current || !token) return;
    started.current = true;
    (async () => {
      try {
        await cp.verifySignup(token);
        const accountId =
          accountIdParam ??
          (() => {
            try {
              return sessionStorage.getItem("signup_account_id");
            } catch {
              return null;
            }
          })();
        router.replace(
          accountId
            ? `/signup/status?account_id=${encodeURIComponent(accountId)}`
            : "/signup/status",
        );
      } catch (err) {
        if (isApiError(err) && err.code === "VERIFICATION_EXPIRED") {
          setError(
            "This verification link has expired. Enter your email below and we will send a fresh one.",
          );
        } else if (isApiError(err) && err.code === "VERIFICATION_ALREADY_USED") {
          setError(
            "This link was already used. If your account is ready, just sign in. Otherwise request a new link below.",
          );
        } else {
          setError(friendlyMessage(err));
        }
        setPhase("failed");
      }
    })();
  }, [token, accountIdParam, router]);

  if (!token) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>Missing verification link</h1>
          <p>
            Open the verification link from your email. If it is not working,
            request a new one from the signup page.
          </p>
        </div>
      </div>
    );
  }

  if (phase === "verifying") {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>Verifying…</h1>
          <p role="status">Confirming your email address. This takes a moment.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Verification problem</h1>
        <p className="form-error" role="alert">
          {error}
        </p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            await cp.resendVerification(resendEmail);
            setResent(true);
          }}
        >
          <div className="field">
            <label htmlFor="resend-email">Work email</label>
            <input
              id="resend-email"
              type="email"
              required
              value={resendEmail}
              onChange={(e) => setResendEmail(e.target.value)}
            />
          </div>
          <button className="btn btn-primary" type="submit" disabled={resent}>
            {resent ? "Sent — check your inbox" : "Resend verification email"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense>
      <VerifyInner />
    </Suspense>
  );
}
