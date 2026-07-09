"use client";

import { useRouter, useSearchParams } from "next/navigation";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type InfiniteData,
} from "@tanstack/react-query";
import { Suspense, useCallback, useMemo, useState } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import type {
  Alert,
  AlertListParams,
  AlertSort,
  AlertState,
  CloseReason,
  Paginated,
  Severity,
} from "@/lib/api/types";
import { AlertRow } from "@/components/alerts/AlertRow";
import { CloseDialog } from "@/components/alerts/CloseDialog";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
const STATES: AlertState[] = ["new", "acknowledged", "closed"];
const BULK_LIMIT = 50;

/** AC-44/72: filters live in the URL so any filtered view is shareable. */
function useAlertFilters(): [AlertListParams, (next: AlertListParams) => void] {
  const searchParams = useSearchParams();
  const router = useRouter();

  const params = useMemo<AlertListParams>(() => {
    const getAll = (k: string) => searchParams.getAll(k);
    const get = (k: string) => searchParams.get(k) ?? undefined;
    return {
      state: getAll("state").filter((s): s is AlertState =>
        (STATES as string[]).includes(s),
      ),
      severity: getAll("severity").filter((s): s is Severity =>
        (SEVERITIES as string[]).includes(s),
      ),
      ai_severity: getAll("ai_severity").filter((s): s is Severity =>
        (SEVERITIES as string[]).includes(s),
      ),
      rule_id: get("rule_id"),
      host: get("host"),
      correlation_group_id: get("correlation_group_id"),
      from: get("from"),
      to: get("to"),
      sort: (get("sort") as AlertSort | undefined) ?? "-priority",
    };
  }, [searchParams]);

  const setParams = useCallback(
    (next: AlertListParams) => {
      const sp = new URLSearchParams();
      for (const s of next.state ?? []) sp.append("state", s);
      for (const s of next.severity ?? []) sp.append("severity", s);
      for (const s of next.ai_severity ?? []) sp.append("ai_severity", s);
      if (next.rule_id) sp.set("rule_id", next.rule_id);
      if (next.host) sp.set("host", next.host);
      if (next.correlation_group_id)
        sp.set("correlation_group_id", next.correlation_group_id);
      if (next.from) sp.set("from", next.from);
      if (next.to) sp.set("to", next.to);
      if (next.sort && next.sort !== "-priority") sp.set("sort", next.sort);
      const qs = sp.toString();
      router.replace(qs ? `/alerts?${qs}` : "/alerts");
    },
    [router],
  );

  return [params, setParams];
}

function toRfc3339(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function toLocalInput(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

type AlertsCache = InfiniteData<Paginated<Alert>>;

function AlertQueue() {
  const [params, setParams] = useAlertFilters();
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [closeTarget, setCloseTarget] = useState<string[] | null>(null);

  const queryKey = useMemo(() => ["alerts", params] as const, [params]);

  const query = useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam }) =>
      dp.listAlerts({ ...params, cursor: pageParam ?? undefined, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });

  const alerts = useMemo(
    () => query.data?.pages.flatMap((p) => p.items) ?? [],
    [query.data],
  );

  // ux spec §2.4: distinguish "no data ever" from "all clear" empty states.
  const noAlertsAtAll = !query.isPending && alerts.length === 0;
  const onboardingQuery = useQuery({
    queryKey: ["onboarding"],
    queryFn: dp.onboardingStatus,
    enabled: noAlertsAtAll,
  });
  const dataFlowing =
    onboardingQuery.data?.steps.find((s) => s.id === "first_event")?.state === "done";

  // ---- optimistic update helpers (AC-73) ----

  function patchCachedAlerts(ids: Set<string>, patch: Partial<Alert>) {
    queryClient.setQueryData<AlertsCache>(queryKey, (old) =>
      old
        ? {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              items: page.items.map((a) =>
                ids.has(a.id) ? { ...a, ...patch } : a,
              ),
            })),
          }
        : old,
    );
  }

  async function snapshot(): Promise<AlertsCache | undefined> {
    await queryClient.cancelQueries({ queryKey });
    return queryClient.getQueryData<AlertsCache>(queryKey);
  }

  function rollback(prev: AlertsCache | undefined) {
    if (prev) queryClient.setQueryData(queryKey, prev);
  }

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["alerts"] });

  const ackMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      if (ids.length === 1) {
        await dp.acknowledgeAlert(ids[0] as string);
        return { succeeded: ids, failed: [] };
      }
      return dp.bulkAlertAction({ action: "acknowledge", alert_ids: ids });
    },
    onMutate: async (ids) => {
      const prev = await snapshot();
      patchCachedAlerts(new Set(ids), { state: "acknowledged" });
      return { prev };
    },
    onSuccess: (result) => {
      if (result.failed.length > 0) {
        pushToast({
          kind: "error",
          message: `${result.failed.length} alert(s) could not be acknowledged (they may have changed state). Refreshing.`,
        });
      }
      setSelected(new Set());
    },
    onError: (err, ids, ctx) => {
      rollback(ctx?.prev);
      pushToast({
        kind: "error",
        message: `Acknowledge failed: ${friendlyMessage(err)}`,
        retry: () => ackMutation.mutate(ids),
      });
    },
    onSettled: invalidate,
  });

  const closeMutation = useMutation({
    mutationFn: async (vars: {
      ids: string[];
      reason: CloseReason;
      comment?: string;
    }) => {
      if (vars.ids.length === 1) {
        await dp.closeAlert(vars.ids[0] as string, vars.reason, vars.comment);
        return { succeeded: vars.ids, failed: [] };
      }
      return dp.bulkAlertAction({
        action: "close",
        alert_ids: vars.ids,
        reason: vars.reason,
      });
    },
    onMutate: async (vars) => {
      const prev = await snapshot();
      patchCachedAlerts(new Set(vars.ids), {
        state: "closed",
        close_reason: vars.reason,
      });
      return { prev };
    },
    onSuccess: (result) => {
      if (result.failed.length > 0) {
        pushToast({
          kind: "error",
          message: `${result.failed.length} alert(s) could not be closed (they may have changed state). Refreshing.`,
        });
      }
      setCloseTarget(null);
      setSelected(new Set());
    },
    onError: (err, vars, ctx) => {
      rollback(ctx?.prev);
      setCloseTarget(null);
      pushToast({
        kind: "error",
        message: `Close failed: ${friendlyMessage(err)}`,
        retry: () => closeMutation.mutate(vars),
      });
    },
    onSettled: invalidate,
  });

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else if (next.size >= BULK_LIMIT) {
        pushToast({
          kind: "info",
          message: `You can act on at most ${BULK_LIMIT} alerts at once.`,
        });
        return prev;
      } else {
        next.add(id);
      }
      return next;
    });
  }

  const hasFilters =
    (params.state?.length ?? 0) > 0 ||
    (params.severity?.length ?? 0) > 0 ||
    (params.ai_severity?.length ?? 0) > 0 ||
    Boolean(params.rule_id || params.host || params.correlation_group_id || params.from || params.to);

  return (
    <div>
      <h1>Alerts</h1>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Alert filters">
        <div className="field">
          <span style={{ fontWeight: 600, fontSize: "0.92rem" }}>State</span>
          <div className="checkbox-group">
            {STATES.map((s) => (
              <label key={s}>
                <input
                  type="checkbox"
                  checked={params.state?.includes(s) ?? false}
                  onChange={(e) => {
                    const cur = new Set(params.state ?? []);
                    if (e.target.checked) cur.add(s);
                    else cur.delete(s);
                    setParams({ ...params, state: [...cur] });
                  }}
                />
                {s}
              </label>
            ))}
          </div>
        </div>
        <div className="field">
          <label htmlFor="f-severity">Rule severity</label>
          <select
            id="f-severity"
            value={params.severity?.[0] ?? ""}
            onChange={(e) =>
              setParams({
                ...params,
                severity: e.target.value ? [e.target.value as Severity] : [],
              })
            }
          >
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-host">Host</label>
          <input
            id="f-host"
            type="text"
            defaultValue={params.host ?? ""}
            onBlur={(e) => setParams({ ...params, host: e.target.value || undefined })}
          />
        </div>
        <div className="field">
          <label htmlFor="f-rule">Rule ID</label>
          <input
            id="f-rule"
            type="text"
            defaultValue={params.rule_id ?? ""}
            onBlur={(e) => setParams({ ...params, rule_id: e.target.value || undefined })}
          />
        </div>
        <div className="field">
          <label htmlFor="f-from">From</label>
          <input
            id="f-from"
            type="datetime-local"
            defaultValue={toLocalInput(params.from)}
            onBlur={(e) => setParams({ ...params, from: toRfc3339(e.target.value) })}
          />
        </div>
        <div className="field">
          <label htmlFor="f-to">To</label>
          <input
            id="f-to"
            type="datetime-local"
            defaultValue={toLocalInput(params.to)}
            onBlur={(e) => setParams({ ...params, to: toRfc3339(e.target.value) })}
          />
        </div>
        <div className="field">
          <label htmlFor="f-sort">Sort</label>
          <select
            id="f-sort"
            value={params.sort ?? "-priority"}
            onChange={(e) => setParams({ ...params, sort: e.target.value as AlertSort })}
          >
            <option value="-priority">Priority (high → low)</option>
            <option value="priority">Priority (low → high)</option>
            <option value="-last_seen">Last seen (newest)</option>
            <option value="last_seen">Last seen (oldest)</option>
          </select>
        </div>
        {hasFilters ? (
          <button type="button" className="btn" onClick={() => setParams({ sort: params.sort })}>
            Clear filters
          </button>
        ) : null}
      </form>

      {params.correlation_group_id ? (
        <p className="muted small">
          Showing alerts in correlation group{" "}
          <code>{params.correlation_group_id}</code>
        </p>
      ) : null}

      {selected.size > 0 ? (
        <div className="bulk-bar" role="toolbar" aria-label="Bulk actions">
          <span>
            {selected.size} selected (max {BULK_LIMIT})
          </span>
          <button
            type="button"
            className="btn btn-small"
            disabled={readOnly || ackMutation.isPending}
            onClick={() => ackMutation.mutate([...selected])}
          >
            Acknowledge
          </button>
          <button
            type="button"
            className="btn btn-small"
            disabled={readOnly || closeMutation.isPending}
            onClick={() => setCloseTarget([...selected])}
          >
            Close…
          </button>
          <button
            type="button"
            className="btn btn-small btn-ghost"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </button>
        </div>
      ) : null}

      {query.isPending ? (
        <LoadingState label="Loading alerts…" />
      ) : alerts.length === 0 ? (
        hasFilters ? (
          <div className="empty-state">
            <h3>No alerts match these filters</h3>
            <p>Try removing a filter, or widen the time range.</p>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setParams({ sort: params.sort })}
            >
              Clear filters
            </button>
          </div>
        ) : dataFlowing ? (
          <EmptyState
            title="All clear"
            body="Your devices are sending data and nothing suspicious has been detected. New alerts appear here automatically — most admins check once or twice a day."
          />
        ) : (
          <EmptyState
            title="No alerts yet"
            body="Alerts will appear here when we detect suspicious activity on your devices. Nothing is monitored yet because no device has sent data."
            ctaHref="/onboarding#install_agent"
            ctaLabel="Install the agent on your first device"
          />
        )
      ) : (
        <>
          <div className="table-wrap">
            <table className="data">
              <caption className="visually-hidden" style={{ display: "none" }}>
                Alert queue sorted by {params.sort ?? "-priority"}
              </caption>
              <thead>
                <tr>
                  <th scope="col" aria-label="Select" />
                  <th scope="col">Priority</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Alert</th>
                  <th scope="col">Host / user</th>
                  <th scope="col">Count</th>
                  <th scope="col">Seen</th>
                  <th scope="col">State</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <AlertRow
                    key={a.id}
                    alert={a}
                    selected={selected.has(a.id)}
                    onToggleSelect={toggleSelect}
                    onAcknowledge={(id) => ackMutation.mutate([id])}
                    onRequestClose={(id) => setCloseTarget([id])}
                    actionsDisabled={readOnly}
                  />
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

      {closeTarget ? (
        <CloseDialog
          count={closeTarget.length}
          pending={closeMutation.isPending}
          onCancel={() => setCloseTarget(null)}
          onSubmit={(reason, comment) =>
            closeMutation.mutate({ ids: closeTarget, reason, comment })
          }
        />
      ) : null}
    </div>
  );
}

export default function AlertsPage() {
  return (
    <Suspense>
      <AlertQueue />
    </Suspense>
  );
}
