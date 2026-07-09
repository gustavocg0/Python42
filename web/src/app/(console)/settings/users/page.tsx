"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import * as cp from "@/lib/api/controlplane";
import { friendlyMessage } from "@/lib/api/errors";
import type { Role } from "@/lib/api/types";
import { EmptyState, LoadingState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import { useTenantState } from "@/components/TenantState";
import { useMe } from "@/lib/hooks";
import { formatDateTime } from "@/lib/format";

export default function UsersPage() {
  const queryClient = useQueryClient();
  const { pushToast } = useToast();
  const { data: me } = useMe();
  const { frozenCause } = useTenantState();
  const readOnly = frozenCause !== null;
  const isAdmin = me?.user.role === "admin";

  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const usersQuery = useQuery({
    queryKey: ["users"],
    queryFn: cp.listUsers,
    enabled: isAdmin,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["users"] });

  const invite = useMutation({
    mutationFn: (vars: { email: string; role: Role }) =>
      cp.createUser(vars.email, vars.role),
    onSuccess: () => {
      setEmail("");
      invalidate();
      pushToast({ kind: "success", message: "Invite sent." });
    },
    onError: (err) =>
      pushToast({ kind: "error", message: `Invite failed: ${friendlyMessage(err)}` }),
  });

  const changeRole = useMutation({
    mutationFn: (vars: { userId: string; role: Role }) =>
      cp.updateUserRole(vars.userId, vars.role),
    onSuccess: () => {
      invalidate();
      pushToast({
        kind: "success",
        message: "Role updated. That user's sessions were signed out.",
      });
    },
    onError: (err) =>
      pushToast({ kind: "error", message: friendlyMessage(err) }),
  });

  const remove = useMutation({
    mutationFn: (userId: string) => cp.deleteUser(userId),
    onSuccess: () => {
      setDeleteTarget(null);
      invalidate();
      pushToast({ kind: "success", message: "User removed." });
    },
    onError: (err) => {
      setDeleteTarget(null);
      pushToast({ kind: "error", message: friendlyMessage(err) });
    },
  });

  if (!isAdmin) {
    return (
      <div>
        <h1>Users</h1>
        <p className="muted">
          Only tenant admins can manage users. Ask your admin if you need a
          role change. (Server-side checks enforce this too.)
        </p>
      </div>
    );
  }

  function onInvite(e: FormEvent) {
    e.preventDefault();
    invite.mutate({ email, role });
  }

  return (
    <div>
      <h1>Users</h1>
      <section className="card" aria-labelledby="invite-heading">
        <h2 id="invite-heading" style={{ marginTop: 0 }}>
          Invite a user
        </h2>
        <form className="form" onSubmit={onInvite}>
          <div className="field">
            <label htmlFor="inv-email">Work email</label>
            <input
              id="inv-email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="inv-role">Role</label>
            <select
              id="inv-role"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
            >
              <option value="analyst">
                Analyst — view everything, triage alerts
              </option>
              <option value="admin">
                Admin — everything, including users, keys, and tokens
              </option>
            </select>
          </div>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={invite.isPending || readOnly}
          >
            {invite.isPending ? "Sending…" : "Send invite"}
          </button>
        </form>
      </section>

      {usersQuery.isPending ? (
        <LoadingState label="Loading users…" />
      ) : (usersQuery.data ?? []).length === 0 ? (
        <EmptyState
          title="No users found"
          body="Invited users appear here once created."
        />
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Email</th>
                <th scope="col">Role</th>
                <th scope="col">Created</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(usersQuery.data ?? []).map((u) => {
                const isSelf = u.id === me?.user.id;
                return (
                  <tr key={u.id}>
                    <td>
                      {u.email}
                      {isSelf ? <span className="muted small"> (you)</span> : null}
                    </td>
                    <td>
                      <label className="visually-hidden" htmlFor={`role-${u.id}`} style={{ display: "none" }}>
                        Role for {u.email}
                      </label>
                      <select
                        id={`role-${u.id}`}
                        value={u.role}
                        disabled={isSelf || readOnly || changeRole.isPending}
                        onChange={(e) =>
                          changeRole.mutate({
                            userId: u.id,
                            role: e.target.value as Role,
                          })
                        }
                      >
                        <option value="analyst">analyst</option>
                        <option value="admin">admin</option>
                      </select>
                    </td>
                    <td className="small">{formatDateTime(u.created_at)}</td>
                    <td>
                      {isSelf ? null : deleteTarget === u.id ? (
                        <>
                          <button
                            type="button"
                            className="btn btn-danger btn-small"
                            disabled={remove.isPending}
                            onClick={() => remove.mutate(u.id)}
                          >
                            Confirm remove
                          </button>{" "}
                          <button
                            type="button"
                            className="btn btn-small"
                            onClick={() => setDeleteTarget(null)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-small"
                          disabled={readOnly}
                          onClick={() => setDeleteTarget(u.id)}
                        >
                          Remove…
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
