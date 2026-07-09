"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import type { IngestKeyCreated } from "@/lib/api/types";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { ShowOnceSecret } from "@/components/ShowOnce";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { useIsAdmin } from "@/lib/hooks";
import { formatDateTime, formatRelative } from "@/lib/format";

export default function IngestKeysPage() {
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;

  const [name, setName] = useState("");
  const [created, setCreated] = useState<IngestKeyCreated | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);

  const keysQuery = useQuery({
    queryKey: ["ingest-keys"],
    queryFn: dp.listIngestKeys,
    enabled: isAdmin,
  });

  const create = useMutation({
    mutationFn: (n: string) => dp.createIngestKey(n),
    onSuccess: (result) => {
      setCreated(result);
      setName("");
      queryClient.invalidateQueries({ queryKey: ["ingest-keys"] });
    },
    onError: (err) =>
      pushToast({ kind: "error", message: `Create failed: ${friendlyMessage(err)}` }),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => dp.revokeIngestKey(id),
    onSuccess: () => {
      setRevokeTarget(null);
      queryClient.invalidateQueries({ queryKey: ["ingest-keys"] });
      pushToast({
        kind: "success",
        message: "Key revoked. It stops working within a minute.",
      });
    },
    onError: (err) => {
      setRevokeTarget(null);
      pushToast({ kind: "error", message: friendlyMessage(err) });
    },
  });

  if (!isAdmin) {
    return (
      <div>
        <h1>Ingest keys</h1>
        <p className="muted">Only tenant admins can manage ingest keys.</p>
      </div>
    );
  }

  function onCreate(e: FormEvent) {
    e.preventDefault();
    create.mutate(name);
  }

  const keys = keysQuery.data?.items ?? [];

  return (
    <div>
      <h1>Ingest keys</h1>
      <p className="muted">
        Ingest keys let other systems (log forwarders, scripts) send JSON
        events to the platform over TLS. Each key is tenant-bound and can be
        revoked at any time.
      </p>

      <section className="card" aria-labelledby="create-key-heading">
        <h2 id="create-key-heading" style={{ marginTop: 0 }}>
          Create a key
        </h2>
        <form className="form" onSubmit={onCreate}>
          <div className="field">
            <label htmlFor="key-name">Key name</label>
            <input
              id="key-name"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Firewall log forwarder"
            />
          </div>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={create.isPending || readOnly}
          >
            {create.isPending ? "Creating…" : "Create key"}
          </button>
        </form>
        {created ? (
          <ShowOnceSecret
            label={`Ingest key "${created.name}"`}
            value={created.key}
            hint="Put it in the sender's configuration as the X-Ingest-Key header."
          />
        ) : null}
      </section>

      {keysQuery.isPending ? (
        <LoadingState label="Loading keys…" />
      ) : keys.length === 0 ? (
        <EmptyState
          title="No ingest keys yet"
          body="Create a key above to let an existing log source send events. If you only use the endpoint agent, you don't need one."
        />
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Created</th>
                <th scope="col">Last used</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="small">{formatDateTime(k.created_at)}</td>
                  <td className="small">
                    {k.last_used_at ? formatRelative(k.last_used_at) : "never"}
                  </td>
                  <td>
                    {revokeTarget === k.id ? (
                      <>
                        <button
                          type="button"
                          className="btn btn-danger btn-small"
                          disabled={revoke.isPending}
                          onClick={() => revoke.mutate(k.id)}
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
                        onClick={() => setRevokeTarget(k.id)}
                      >
                        Revoke…
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
