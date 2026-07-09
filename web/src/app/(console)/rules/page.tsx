"use client";

import {
  useInfiniteQuery,
  useMutation,
  useQueryClient,
  type InfiniteData,
} from "@tanstack/react-query";
import { useMemo } from "react";
import * as dp from "@/lib/api/dataplane";
import { friendlyMessage } from "@/lib/api/errors";
import type { Paginated, Rule } from "@/lib/api/types";
import { SeverityBadge } from "@/components/Badges";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { useIsAdmin } from "@/lib/hooks";
import { techniqueUrl } from "@/lib/mitre";

type RulesCache = InfiniteData<Paginated<Rule>>;

export default function RulesPage() {
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const isAdmin = useIsAdmin();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;

  const query = useInfiniteQuery({
    queryKey: ["rules"],
    queryFn: ({ pageParam }) => dp.listRules(pageParam ?? undefined),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });

  const rules = useMemo(
    () => query.data?.pages.flatMap((p) => p.items) ?? [],
    [query.data],
  );

  const toggle = useMutation({
    mutationFn: (vars: { ruleId: string; enabled: boolean }) =>
      dp.setRuleEnabled(vars.ruleId, vars.enabled),
    onMutate: async (vars) => {
      await queryClient.cancelQueries({ queryKey: ["rules"] });
      const prev = queryClient.getQueryData<RulesCache>(["rules"]);
      queryClient.setQueryData<RulesCache>(["rules"], (old) =>
        old
          ? {
              ...old,
              pages: old.pages.map((page) => ({
                ...page,
                items: page.items.map((r) =>
                  r.id === vars.ruleId ? { ...r, enabled: vars.enabled } : r,
                ),
              })),
            }
          : old,
      );
      return { prev };
    },
    onError: (err, vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(["rules"], ctx.prev);
      pushToast({
        kind: "error",
        message: `Could not update rule: ${friendlyMessage(err)}`,
        retry: () => toggle.mutate(vars),
      });
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  return (
    <div>
      <h1>Detection rules</h1>
      <p className="muted">
        Managed detection content — rules are written and updated by our
        detection team; you can switch individual rules off for your
        organization if they are too noisy. Rule changes are audit-logged.
      </p>
      {query.isPending ? (
        <LoadingState label="Loading rules…" />
      ) : rules.length === 0 ? (
        <EmptyState
          title="No rules available yet"
          body="The managed rule pack loads automatically for every tenant. If this persists, contact support."
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Event classes</th>
                  <th scope="col">Techniques</th>
                  <th scope="col">Enabled</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <strong>{r.title}</strong>
                      <div className="muted small one-liner">{r.description}</div>
                      <div className="muted small">
                        <code>{r.id}</code> v{r.version}
                      </div>
                    </td>
                    <td>
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="small">{r.event_classes.join(", ")}</td>
                    <td className="small">
                      {r.mitre_technique_ids.map((t) => (
                        <a
                          key={t}
                          href={techniqueUrl(t)}
                          target="_blank"
                          rel="noreferrer noopener"
                          style={{ marginRight: "0.4rem" }}
                        >
                          {t}
                        </a>
                      ))}
                    </td>
                    <td>
                      {isAdmin ? (
                        <label style={{ display: "inline-flex", gap: "0.35rem" }}>
                          <input
                            type="checkbox"
                            role="switch"
                            checked={r.enabled}
                            disabled={readOnly || toggle.isPending}
                            aria-label={`${r.title}: ${r.enabled ? "enabled" : "disabled"}`}
                            onChange={(e) =>
                              toggle.mutate({ ruleId: r.id, enabled: e.target.checked })
                            }
                          />
                          {r.enabled ? "On" : "Off"}
                        </label>
                      ) : (
                        <span>{r.enabled ? "On" : "Off"}</span>
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
