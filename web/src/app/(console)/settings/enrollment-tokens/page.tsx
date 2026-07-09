"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import type { EnrollmentTokenCreated } from "@/lib/api/types";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { ShowOnceSecret } from "@/components/ShowOnce";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { useIsAdmin } from "@/lib/hooks";
import { formatDateTime, isPast } from "@/lib/format";

export default function EnrollmentTokensPage() {
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;

  const [name, setName] = useState("");
  const [expiresInHours, setExpiresInHours] = useState<string>("");
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);

  const tokensQuery = useQuery({
    queryKey: ["enrollment-tokens"],
    queryFn: dp.listEnrollmentTokens,
    enabled: isAdmin,
  });

  const create = useMutation({
    mutationFn: (vars: { name: string; hours?: number }) =>
      dp.createEnrollmentToken(vars.name, vars.hours),
    onSuccess: (result) => {
      setCreated(result);
      setName("");
      queryClient.invalidateQueries({ queryKey: ["enrollment-tokens"] });
    },
    onError: (err) =>
      pushToast({ kind: "error", message: `Create failed: ${friendlyMessage(err)}` }),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => dp.revokeEnrollmentToken(id),
    onSuccess: () => {
      setRevokeTarget(null);
      queryClient.invalidateQueries({ queryKey: ["enrollment-tokens"] });
      pushToast({ kind: "success", message: "Token revoked." });
    },
    onError: (err) => {
      setRevokeTarget(null);
      pushToast({ kind: "error", message: friendlyMessage(err) });
    },
  });

  if (!isAdmin) {
    return (
      <div>
        <h1>Enrollment tokens</h1>
        <p className="muted">Only tenant admins can manage enrollment tokens.</p>
      </div>
    );
  }

  function onCreate(e: FormEvent) {
    e.preventDefault();
    const hours = expiresInHours ? Number(expiresInHours) : undefined;
    create.mutate({ name, hours });
  }

  const tokens = tokensQuery.data?.items ?? [];

  return (
    <div>
      <h1>Enrollment tokens</h1>
      <p className="muted">
        Enrollment tokens let the agent installer register devices to your
        tenant. Tokens can enroll many devices (for GPO/Intune rollouts) until
        they expire or you revoke them.
      </p>

      <section className="card" aria-labelledby="create-token-heading">
        <h2 id="create-token-heading" style={{ marginTop: 0 }}>
          Generate a token
        </h2>
        <form className="form" onSubmit={onCreate}>
          <div className="field">
            <label htmlFor="tok-name">Token name</label>
            <input
              id="tok-name"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. HQ laptops rollout"
            />
          </div>
          <div className="field">
            <label htmlFor="tok-hours">Expires in (hours, optional)</label>
            <input
              id="tok-hours"
              type="number"
              min={1}
              value={expiresInHours}
              onChange={(e) => setExpiresInHours(e.target.value)}
              placeholder="72 (default)"
            />
          </div>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={create.isPending || readOnly}
          >
            {create.isPending ? "Generating…" : "Generate token"}
          </button>
        </form>
        {created ? (
          <>
            <ShowOnceSecret
              label="Enrollment token"
              value={created.token}
              hint={`It expires ${formatDateTime(created.expires_at)}.`}
            />
            <h3>Install command</h3>
            <p className="muted small">
              Run as administrator on each device, or deploy silently via
              GPO/Intune.
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
        ) : null}
      </section>

      {tokensQuery.isPending ? (
        <LoadingState label="Loading tokens…" />
      ) : tokens.length === 0 ? (
        <EmptyState
          title="No enrollment tokens yet"
          body="Generate a token above to start installing agents on your devices."
        />
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Created</th>
                <th scope="col">Expires</th>
                <th scope="col">Devices enrolled</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => {
                const expired = isPast(t.expires_at);
                return (
                  <tr key={t.id}>
                    <td>
                      {t.name}
                      {t.revoked ? (
                        <span className="badge agent-revoked" style={{ marginLeft: "0.4rem" }}>
                          Revoked
                        </span>
                      ) : expired ? (
                        <span className="badge state-closed" style={{ marginLeft: "0.4rem" }}>
                          Expired
                        </span>
                      ) : null}
                    </td>
                    <td className="small">{formatDateTime(t.created_at)}</td>
                    <td className="small">{formatDateTime(t.expires_at)}</td>
                    <td>{t.enrollment_count}</td>
                    <td>
                      {t.revoked || expired ? null : revokeTarget === t.id ? (
                        <>
                          <button
                            type="button"
                            className="btn btn-danger btn-small"
                            disabled={revoke.isPending}
                            onClick={() => revoke.mutate(t.id)}
                          >
                            Confirm revoke
                          </button>{" "}
                          <button
                            type="button"
                            className="btn btn-small"
                            onClick={() => setRevokeTarget(null)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-small"
                          disabled={readOnly}
                          onClick={() => setRevokeTarget(t.id)}
                        >
                          Revoke…
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
