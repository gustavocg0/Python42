"use client";

import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import type {
  EnrollmentTokenCreated,
  IngestKeyCreated,
  OnboardingStep,
  OnboardingStepId,
} from "@/lib/api/types";
import { ShowOnceSecret } from "@/components/ShowOnce";
import { useIsAdmin } from "@/lib/hooks";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";

const STEP_ORDER: OnboardingStepId[] = [
  "install_agent",
  "create_ingest_key",
  "first_event",
  "view_queue",
];

function StepState({ step }: { step: OnboardingStep | undefined }) {
  const done = step?.state === "done";
  return (
    <span className={`step-state ${done ? "done" : "todo"}`}>
      {done ? "Done" : "To do"}
    </span>
  );
}

function InstallAgentStep() {
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const { pushToast } = useToast();
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null);
  const [name, setName] = useState("Initial rollout");

  const create = useMutation({
    mutationFn: () => dp.createEnrollmentToken(name),
    onSuccess: setCreated,
    onError: (err) => pushToast({ kind: "error", message: friendlyMessage(err) }),
  });

  if (!isAdmin) {
    return (
      <p className="muted">
        A tenant admin needs to generate the enrollment token for installing
        agents. Ask your admin, then check back here.
      </p>
    );
  }

  return (
    <div>
      <p>
        Generate an install token, then run one command on each Windows device
        — by hand or through GPO/Intune. The token works for all your devices
        until it expires.
      </p>
      {created ? (
        <>
          <ShowOnceSecret
            label="Enrollment token"
            value={created.token}
            hint={`Copy this now — we only show it once. Expires ${new Date(created.expires_at).toLocaleString()}.`}
          />
          <h3>Install command</h3>
          <p className="muted small">
            Run as administrator, or deploy silently via GPO/Intune.
          </p>
          <div className="show-once-value">
            <code>{created.install_command}</code>
            <button
              type="button"
              className="btn btn-small"
              onClick={() => navigator.clipboard.writeText(created.install_command)}
            >
              Copy
            </button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
          className="form"
        >
          <div className="field">
            <label htmlFor="et-name">Token name</label>
            <input
              id="et-name"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <p className="field-hint">
              For example: &quot;Office laptops&quot; — helps you recognize it later.
            </p>
          </div>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={create.isPending || frozenCause !== null}
          >
            {create.isPending ? "Generating…" : "Generate token"}
          </button>
        </form>
      )}
      <p className="small muted" style={{ marginTop: "0.5rem" }}>
        Manage tokens later under{" "}
        <Link href="/settings/enrollment-tokens">Enrollment tokens</Link>.
      </p>
    </div>
  );
}

function IngestKeyStep() {
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const { pushToast } = useToast();
  const [created, setCreated] = useState<IngestKeyCreated | null>(null);
  const [name, setName] = useState("Log forwarder");

  const create = useMutation({
    mutationFn: () => dp.createIngestKey(name),
    onSuccess: setCreated,
    onError: (err) => pushToast({ kind: "error", message: friendlyMessage(err) }),
  });

  if (!isAdmin) {
    return (
      <p className="muted">
        Optional, and admin-only: an ingest key lets other systems (like a log
        forwarder) send events to the platform.
      </p>
    );
  }

  return (
    <div>
      <p>
        Have a firewall or server that writes JSON logs? Create an ingest key
        and POST them to us — no agent needed. Skipping this never blocks your
        setup.
      </p>
      {created ? (
        <ShowOnceSecret
          label="Ingest key"
          value={created.key}
          hint="Store it in your log forwarder's configuration."
        />
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
          className="form"
        >
          <div className="field">
            <label htmlFor="ik-name">Key name</label>
            <input
              id="ik-name"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={create.isPending || frozenCause !== null}
          >
            {create.isPending ? "Creating…" : "Create ingest key"}
          </button>
        </form>
      )}
      <p className="small muted" style={{ marginTop: "0.5rem" }}>
        Manage keys later under <Link href="/settings/ingest-keys">Ingest keys</Link>.
      </p>
    </div>
  );
}

export default function OnboardingPage() {
  useQueryClient();
  // Live step states (AC-70): poll while any step is still to-do.
  const { data, isPending } = useQuery({
    queryKey: ["onboarding"],
    queryFn: dp.onboardingStatus,
    refetchInterval: (query) =>
      query.state.data?.steps.every((s) => s.state === "done") ? false : 5000,
  });

  const byId = new Map(data?.steps.map((s) => [s.id, s]));
  const step = (id: OnboardingStepId) => byId.get(id);

  return (
    <div>
      <h1>Get protected in about 15 minutes</h1>
      <p className="muted">
        Four steps to your first prioritized alerts. Steps complete
        automatically as data starts flowing.
      </p>
      {isPending ? (
        <p className="loading-state" role="status">
          Loading your checklist…
        </p>
      ) : null}
      <ol className="checklist">
        {STEP_ORDER.map((id) => {
          const s = step(id);
          const done = s?.state === "done";
          return (
            <li key={id} id={id} className={done ? "step-done" : undefined}>
              <div className="card">
                {id === "install_agent" && (
                  <>
                    <h3>
                      Install the agent on your devices <StepState step={s} />
                    </h3>
                    <InstallAgentStep />
                  </>
                )}
                {id === "create_ingest_key" && (
                  <>
                    <h3>
                      Optional: send logs from other tools <StepState step={s} />
                    </h3>
                    <IngestKeyStep />
                  </>
                )}
                {id === "first_event" && (
                  <>
                    <h3>
                      Confirm data is arriving <StepState step={s} />
                    </h3>
                    <p className="muted">
                      {done
                        ? "First event received. Detection rules are now watching your environment."
                        : "This step completes itself the moment your first event arrives — nothing to do but wait, usually under a minute after install."}
                    </p>
                  </>
                )}
                {id === "view_queue" && (
                  <>
                    <h3>
                      See your alert queue <StepState step={s} />
                    </h3>
                    <p className="muted">
                      This is your home screen from now on. Alerts are sorted
                      so the most important one is always on top.
                    </p>
                    <Link className="btn btn-primary" href="/alerts">
                      Open alert queue
                    </Link>
                  </>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
