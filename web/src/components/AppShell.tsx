"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import * as cp from "@/lib/api/controlplane";
import type { Me, TenantInfo } from "@/lib/api/types";
import { useTenantState } from "./TenantState";

const NAV = [
  { href: "/onboarding", label: "Get started", adminOnly: false },
  { href: "/alerts", label: "Alerts", adminOnly: false },
  { href: "/assets", label: "Assets", adminOnly: false },
  { href: "/rules", label: "Detection rules", adminOnly: false },
  { href: "/settings/usage", label: "Usage & plan", adminOnly: false },
  { href: "/settings/users", label: "Users", adminOnly: true },
  { href: "/settings/ingest-keys", label: "Ingest keys", adminOnly: true },
  { href: "/settings/enrollment-tokens", label: "Enrollment tokens", adminOnly: true },
  { href: "/settings/audit", label: "Audit log", adminOnly: true },
] as const;

/** Banner copy per ux spec §2.7. */
function Banners({ tenant }: { tenant: TenantInfo }) {
  const { frozenCause } = useTenantState();
  if (!frozenCause) return null;

  if (frozenCause === "abuse") {
    return (
      <div className="banner banner-error" role="alert">
        <strong>This account is temporarily suspended.</strong> Data collection
        and changes are paused while we review unusual activity on this
        account. Your existing data is view-only. If you believe this is a
        mistake, contact support and we&apos;ll sort it out.
      </div>
    );
  }

  const expiredAt = tenant.trial_expires_at ? new Date(tenant.trial_expires_at) : null;
  const purgeAt = expiredAt
    ? new Date(expiredAt.getTime() + 30 * 24 * 60 * 60 * 1000)
    : null;
  const daysToPurge = purgeAt
    ? Math.max(0, Math.ceil((purgeAt.getTime() - Date.now()) / (24 * 60 * 60 * 1000)))
    : null;
  const nearPurge = daysToPurge !== null && daysToPurge <= 7;

  return (
    <div className={`banner ${nearPurge ? "banner-error" : "banner-warning"}`} role="alert">
      {nearPurge ? <strong>Deleted in {daysToPurge} days. </strong> : null}
      <strong>
        Your free trial ended
        {expiredAt ? ` ${expiredAt.toLocaleDateString()}` : ""}.
      </strong>{" "}
      Your alerts and asset data are safe and view-only, but we&apos;ve stopped
      collecting new data — your devices are not being monitored. To keep
      protection running, contact us to pick a plan.
      {purgeAt
        ? ` Unless you upgrade, all data will be permanently deleted on ${purgeAt.toLocaleDateString()}.`
        : ""}{" "}
      <a href="mailto:support@example.com?subject=Upgrade%20my%20plan">
        Contact us to upgrade
      </a>
    </div>
  );
}

export function AppShell({ me, children }: { me: Me; children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  const isAdmin = me.user.role === "admin";

  async function handleLogout() {
    try {
      await cp.logout();
    } finally {
      queryClient.clear();
      router.replace("/login");
    }
  }

  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="topbar">
        <span className="brand">SOC Console</span>
        <span className="tenant-name">{me.tenant.name}</span>
        <span className="spacer" />
        <span className="user-chip">
          {me.user.email} ({me.user.role})
        </span>
        <button type="button" className="btn btn-small" onClick={handleLogout}>
          Sign out
        </button>
      </header>
      <Banners tenant={me.tenant} />
      <div className="shell-body">
        <nav className="sidenav" aria-label="Main navigation">
          <ul>
            {NAV.filter((item) => !item.adminOnly || isAdmin).map((item) => {
              const active =
                pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={active ? "nav-link active" : "nav-link"}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <main id="main-content" className="main">
          {children}
        </main>
      </div>
    </div>
  );
}
