"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Suspense, useCallback, useMemo, useState } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import type { AgentStatus, AssetListParams, AssetSource } from "@/lib/api/types";
import { AgentStatusBadge } from "@/components/Badges";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { MergeDialog } from "@/components/assets/MergeDialog";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { useIsAdmin } from "@/lib/hooks";
import { formatRelative } from "@/lib/format";

const AGENT_STATUSES: AgentStatus[] = [
  "enrolled",
  "healthy",
  "offline",
  "revoked",
  "none",
];

/** AC-21 filters, URL-shareable like the alert queue. */
function useAssetFilters(): [AssetListParams, (next: AssetListParams) => void] {
  const searchParams = useSearchParams();
  const router = useRouter();

  const params = useMemo<AssetListParams>(() => {
    const get = (k: string) => searchParams.get(k) ?? undefined;
    const billableRaw = get("billable");
    return {
      source: (get("source") as AssetSource | undefined) ?? undefined,
      agent_status: (get("agent_status") as AgentStatus | undefined) ?? undefined,
      billable:
        billableRaw === "true" ? true : billableRaw === "false" ? false : undefined,
      q: get("q"),
    };
  }, [searchParams]);

  const setParams = useCallback(
    (next: AssetListParams) => {
      const sp = new URLSearchParams();
      if (next.source) sp.set("source", next.source);
      if (next.agent_status) sp.set("agent_status", next.agent_status);
      if (next.billable !== undefined) sp.set("billable", String(next.billable));
      if (next.q) sp.set("q", next.q);
      const qs = sp.toString();
      router.replace(qs ? `/assets?${qs}` : "/assets");
    },
    [router],
  );

  return [params, setParams];
}

function CapBanner() {
  // AC-14/26: billable count + endpoint cap; rejection visibility at cap.
  const { data } = useQuery({
    queryKey: ["billable-count"],
    queryFn: dp.billableCount,
  });
  if (!data) return null;
  const atCap = data.billable_count >= data.endpoint_cap;
  const nearCap = !atCap && data.billable_count >= data.endpoint_cap * 0.8;
  return (
    <>
      <div className="card-row">
        <div className="card">
          <div className="stat-value">
            {data.billable_count} / {data.endpoint_cap}
          </div>
          <div className="stat-label">
            Billable endpoints (seen in the last {data.window_days} days) vs.
            your plan&apos;s cap
          </div>
        </div>
      </div>
      {/* Copy per ux spec §2.7 (AC-14 endpoint-cap banner). */}
      {atCap ? (
        <div className="banner banner-error banner-inline" role="alert">
          You&apos;ve reached your plan&apos;s limit of {data.endpoint_cap}{" "}
          devices, so new devices can&apos;t enroll. Remove devices you no
          longer use, or contact us to raise the limit.
        </div>
      ) : nearCap ? (
        <div className="banner banner-warning banner-inline" role="status">
          You&apos;re close to your plan&apos;s limit ({data.billable_count} of{" "}
          {data.endpoint_cap} devices). At the limit, new devices can&apos;t
          enroll.
        </div>
      ) : null}
    </>
  );
}

function AssetsInner() {
  const [params, setParams] = useAssetFilters();
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showMerge, setShowMerge] = useState(false);

  const query = useInfiniteQuery({
    queryKey: ["assets", params],
    queryFn: ({ pageParam }) =>
      dp.listAssets({ ...params, cursor: pageParam ?? undefined, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });

  const assets = useMemo(
    () => query.data?.pages.flatMap((p) => p.items) ?? [],
    [query.data],
  );
  const selectedAssets = assets.filter((a) => selected.has(a.id));

  const merge = useMutation({
    mutationFn: (reason: string) => dp.mergeAssets([...selected], reason),
    onSuccess: () => {
      setShowMerge(false);
      setSelected(new Set());
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      queryClient.invalidateQueries({ queryKey: ["billable-count"] });
      pushToast({ kind: "success", message: "Assets merged." });
    },
    onError: (err) => {
      setShowMerge(false);
      pushToast({
        kind: "error",
        message: `Merge failed: ${friendlyMessage(err)}`,
      });
    },
  });

  const hasFilters = Boolean(
    params.source || params.agent_status || params.billable !== undefined || params.q,
  );

  return (
    <div>
      <h1>Assets</h1>
      <CapBanner />
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Asset filters">
        <div className="field">
          <label htmlFor="af-q">Search hostname</label>
          <input
            id="af-q"
            type="text"
            defaultValue={params.q ?? ""}
            onBlur={(e) => setParams({ ...params, q: e.target.value || undefined })}
          />
        </div>
        <div className="field">
          <label htmlFor="af-source">Source</label>
          <select
            id="af-source"
            value={params.source ?? ""}
            onChange={(e) =>
              setParams({
                ...params,
                source: (e.target.value || undefined) as AssetSource | undefined,
              })
            }
          >
            <option value="">Any</option>
            <option value="agent">Agent</option>
            <option value="log_ingest">Log ingest</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="af-status">Agent status</label>
          <select
            id="af-status"
            value={params.agent_status ?? ""}
            onChange={(e) =>
              setParams({
                ...params,
                agent_status: (e.target.value || undefined) as AgentStatus | undefined,
              })
            }
          >
            <option value="">Any</option>
            {AGENT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="af-billable">Billable</label>
          <select
            id="af-billable"
            value={params.billable === undefined ? "" : String(params.billable)}
            onChange={(e) =>
              setParams({
                ...params,
                billable:
                  e.target.value === "" ? undefined : e.target.value === "true",
              })
            }
          >
            <option value="">Any</option>
            <option value="true">Billable</option>
            <option value="false">Not billable</option>
          </select>
        </div>
        {hasFilters ? (
          <button type="button" className="btn" onClick={() => setParams({})}>
            Clear filters
          </button>
        ) : null}
      </form>

      {isAdmin && selected.size >= 2 ? (
        <div className="bulk-bar" role="toolbar" aria-label="Asset actions">
          <span>{selected.size} assets selected</span>
          <button
            type="button"
            className="btn btn-small"
            disabled={readOnly}
            onClick={() => setShowMerge(true)}
          >
            Merge into one asset…
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
        <LoadingState label="Loading assets…" />
      ) : assets.length === 0 ? (
        hasFilters ? (
          <EmptyState
            title="No assets match these filters"
            body="Try removing a filter or clearing the search."
          />
        ) : (
          <EmptyState
            title="No devices yet"
            body="Every monitored device shows up here, deduplicated — this is also the count your plan is based on. It's empty because no agent is installed and no logs are arriving."
            ctaHref="/onboarding#install_agent"
            ctaLabel="Install the agent"
          />
        )
      ) : (
        <>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  {isAdmin ? <th scope="col" aria-label="Select" /> : null}
                  <th scope="col">Hostname</th>
                  <th scope="col">OS</th>
                  <th scope="col">Sources</th>
                  <th scope="col">Agent</th>
                  <th scope="col">First seen</th>
                  <th scope="col">Last seen</th>
                  <th scope="col">Billable</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.id} className={selected.has(a.id) ? "selected" : undefined}>
                    {isAdmin ? (
                      <td>
                        <input
                          type="checkbox"
                          checked={selected.has(a.id)}
                          aria-label={`Select asset ${a.hostname}`}
                          onChange={() =>
                            setSelected((prev) => {
                              const next = new Set(prev);
                              if (next.has(a.id)) next.delete(a.id);
                              else next.add(a.id);
                              return next;
                            })
                          }
                        />
                      </td>
                    ) : null}
                    <td>
                      <Link href={`/assets/${encodeURIComponent(a.id)}`}>
                        {a.hostname}
                      </Link>
                    </td>
                    <td>
                      {a.os_name}{" "}
                      <span className="muted small">{a.os_version}</span>
                    </td>
                    <td className="small">{a.sources.join(", ")}</td>
                    <td>
                      <AgentStatusBadge status={a.agent_status} />
                    </td>
                    <td className="small" title={a.first_seen}>
                      {formatRelative(a.first_seen)}
                    </td>
                    <td className="small" title={a.last_seen}>
                      {formatRelative(a.last_seen)}
                    </td>
                    <td>{a.billable ? "Yes" : "No"}</td>
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

      {showMerge && selectedAssets.length >= 2 ? (
        <MergeDialog
          assets={selectedAssets}
          pending={merge.isPending}
          onCancel={() => setShowMerge(false)}
          onSubmit={(reason) => merge.mutate(reason)}
        />
      ) : null}
    </div>
  );
}

export default function AssetsPage() {
  return (
    <Suspense>
      <AssetsInner />
    </Suspense>
  );
}
