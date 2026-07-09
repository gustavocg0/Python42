"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import * as cp from "@/lib/api/controlplane";
import { friendlyMessage, isApiError } from "@/lib/api/errors";

type Phase = "form" | "email_sent";

export default function SignupPage() {
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [challengeRequired, setChallengeRequired] = useState(false);
  const [challengeResponse, setChallengeResponse] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<Phase>("form");

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await cp.signup({
        org_name: orgName,
        email,
        password,
        ...(challengeRequired && challengeResponse
          ? { challenge_response: challengeResponse }
          : {}),
      });
      // account_id is an opaque, non-secret identifier used only to poll
      // provisioning status after email verification (session storage, not
      // localStorage-persisted secrets — SEC-2 concerns credentials only).
      try {
        sessionStorage.setItem("signup_account_id", result.account_id);
      } catch {
        /* private-mode storage failures are non-fatal */
      }
      setPhase("email_sent");
    } catch (err) {
      if (isApiError(err)) {
        switch (err.code) {
          case "PASSWORD_POLICY_VIOLATION":
            setError(
              "Please choose a longer password: at least 12 characters.",
            );
            break;
          case "PASSWORD_BREACHED":
            setError(
              "That password has appeared in known data breaches. Please choose a different one.",
            );
            break;
          case "DOMAIN_ALREADY_REGISTERED":
            setError(
              "Your organization already has an account for this email domain. Ask your admin to invite you.",
            );
            break;
          case "SIGNUP_CHALLENGE_REQUIRED":
            setChallengeRequired(true);
            setError(
              "One more check is needed to confirm you are human. Complete the challenge below and submit again.",
            );
            break;
          case "VALIDATION_ERROR":
            setError("Please check the highlighted fields and try again.");
            break;
          default:
            setError(friendlyMessage(err));
        }
      } else {
        setError(friendlyMessage(err));
      }
    } finally {
      setBusy(false);
    }
  }

  if (phase === "email_sent") {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>Check your email</h1>
          <p>
            We sent a verification link to <strong>{email}</strong>. Click it
            within 24 hours to finish creating your account.
          </p>
          <p className="muted small">
            Nothing arriving? Check spam, or{" "}
            <button
              type="button"
              className="btn btn-small"
              onClick={() => cp.resendVerification(email)}
            >
              resend the email
            </button>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Start your free trial</h1>
        <p className="muted small">
          14 days, full features, no payment details needed.
        </p>
        <form onSubmit={onSubmit} noValidate>
          <div className="field">
            <label htmlFor="org">Organization name</label>
            <input
              id="org"
              type="text"
              required
              minLength={2}
              maxLength={120}
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
            />
          </div>
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
              autoComplete="new-password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <p className="field-hint">At least 12 characters.</p>
          </div>
          {challengeRequired ? (
            <div className="field">
              <label htmlFor="challenge">Verification challenge</label>
              <input
                id="challenge"
                type="text"
                value={challengeResponse}
                onChange={(e) => setChallengeResponse(e.target.value)}
              />
              <p className="field-hint">
                Enter the challenge answer to confirm you are human.
              </p>
            </div>
          ) : null}
          {error ? (
            <p className="form-error" role="alert">
              {error}
            </p>
          ) : null}
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? "Creating account…" : "Create account"}
          </button>
        </form>
        <p className="small" style={{ marginTop: "1rem" }}>
          Already have an account? <Link href="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
