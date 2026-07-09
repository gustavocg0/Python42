"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import * as dp from "@/lib/api/dataplane";
import type { AuditListParams } from "@/lib/api/types";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { JsonView } from "@/components/JsonView";
import { useIsAdmin } from "@/lib/hooks";
import { formatDateTime, humanize } from "@/lib/format";

function toRfc3339(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export default function AuditLogPage() {
  const isAdmin = useIsAdmin();
  const [filters, setFilters] = useState<AuditListParams>({});

  const query = useInfiniteQuery({
    queryKey: ["audit-logs", filters],
    queryFn: ({ pageParam }) =>
      dp.listAuditLogs({ ...filters, cursor: pageParam ?? undefined, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled: isAdmin,
  });

  const records = useMemo(
    () => query.data?.pages.flatMap((p) => p.items) ?? [],
    [query.data],
  );

  if (!isAdmin) {
    return (
      <div>
        <h1>Audit log</h1>
        <p className="muted">Only tenant admins can view the audit log.</p>
      </div>
    );
  }

  return (
    <div>
      <h1>Audit log</h1>
      <p className="muted">
        Every state-changing action in your tenant — who did what, when, and
        what changed. Records are append-only and retained at least a year.
      </p>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Audit filters">
        <div className="field">
          <label htmlFor="au-actor">Actor</label>
          <input
            id="au-actor"
            type="text"
            placeholder="user / device / system id"
            defaultValue={filters.actor ?? ""}
            onBlur={(e) =>
              setFilters((f) => ({ ...f, actor: e.target.value || undefined }))
            }
          />
        </div>
        <div className="field">
          <label htmlFor="au-action">Action type</label>
          <input
            id="au-action"
            type="text"
            placeholder="e.g. alert_close"
            defaultValue={filters.action_type ?? ""}
            onBlur={(e) =>
              setFilters((f) => ({ ...f, action_type: e.target.value || undefined }))
            }
          />
        </div>
        <div className="field">
          <label htmlFor="au-from">From</label>
          <input
            id="au-from"
            type="datetime-local"
            onBlur={(e) => setFilters((f) => ({ ...f, from: toRfc3339(e.target.value) }))}
          />
        </div>
        <div className="field">
          <label htmlFor="au-to">To</label>
          <input
            id="au-to"
            type="datetime-local"
            onBlur={(e) => setFilters((f) => ({ ...f, to: toRfc3339(e.target.value) }))}
          />
        </div>
      </form>

      {query.isPending ? (
        <LoadingState label="Loading audit records…" />
      ) : records.length === 0 ? (
        <EmptyState
          title="No audit records match"
          body="A record of every change in this tenant — sign-ins, key creation, alert actions — appears here. Nothing matching has happened yet."
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Action</th>
                  <th scope="col">Target</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Changes</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id}>
                    <td className="small">{formatDateTime(r.at)}</td>
                    <td className="small">
                      {r.actor.type}: <code>{r.actor.id}</code>
                    </td>
                    <td>{humanize(r.action_type)}</td>
                    <td className="small">
                      {r.target.type}: <code>{r.target.id}</code>
                    </td>
                    <td className="small">{r.reason_code ? humanize(r.reason_code) : "—"}</td>
                    <td>
                      {r.before || r.after ? (
                        <details>
                          <summary className="small">before / after</summary>
                          <JsonView
                            data={{ before: r.before ?? null, after: r.after ?? null }}
                            label="Change details"
                          />
                        </details>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {query.hasNextPage ? (
            <div className="load-more">
              <button
                type="button"
                className="btn"
                disabled={query.isFetchingNextPage}
                onClick={() => query.fetchNextPage()}
              >
                {query.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}
