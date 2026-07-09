import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AlertRow } from "@/components/alerts/AlertRow";
import type { Alert } from "@/lib/api/types";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "al_1",
    tenant_id: "tn_1",
    state: "new",
    rule: {
      id: "win_susp_encoded_powershell",
      version: "1.2.0",
      title: "Suspicious encoded PowerShell",
      severity: "high",
      mitre_technique_ids: ["T1059.001"],
    },
    entity: { hostname: "fin-laptop-07", user: "sam.jones", asset_id: "as_1" },
    occurrence_count: 7,
    first_seen: "2026-07-08T09:00:00Z",
    last_seen: "2026-07-08T10:00:00Z",
    correlation_group_id: "cg_1",
    priority_score: 86,
    priority_inputs: {
      rule_severity: "high",
      ai_severity: "high",
      ai_severity_effective: "high",
      occurrence_count: 7,
      agent_status: "healthy",
      priority_formula_version: 1,
    },
    triage: {
      status: "completed",
      summary: "Plain language summary.",
      ai_severity: "high",
      model_id: "fast-1",
      completed_at: "2026-07-08T09:01:00Z",
      attempts: 1,
    },
    event_refs: [],
    close_reason: null,
    closed_by: null,
    closed_at: null,
    acknowledged_by: null,
    acknowledged_at: null,
    created_at: "2026-07-08T09:00:00Z",
    ...overrides,
  };
}

function renderRow(alert: Alert) {
  return render(
    <table>
      <tbody>
        <AlertRow
          alert={alert}
          selected={false}
          onToggleSelect={() => {}}
          onAcknowledge={() => {}}
          onRequestClose={() => {}}
        />
      </tbody>
    </table>,
  );
}

describe("AlertRow", () => {
  it("renders queue columns: priority, severity, title, one-liner, host/user, count, state", () => {
    renderRow(makeAlert());
    expect(screen.getByLabelText("Priority score 86 out of 100")).toBeInTheDocument();
    expect(screen.getByText("Suspicious encoded PowerShell")).toBeInTheDocument();
    expect(screen.getByText("Plain language summary.")).toBeInTheDocument();
    expect(screen.getByText("fin-laptop-07")).toBeInTheDocument();
    expect(screen.getByText("sam.jones")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("New")).toBeInTheDocument();
  });

  it("labels the AI one-liner with the AI chip (AC-49, ux spec §2.1)", () => {
    renderRow(makeAlert());
    const chip = screen.getByText("AI");
    expect(chip).toBeInTheDocument();
    expect(chip).toHaveAttribute("title", expect.stringContaining("AI model"));
  });

  it("falls back to the rule title without an AI label when triage is unavailable (AC-72)", () => {
    renderRow(
      makeAlert({
        triage: {
          status: "unavailable",
          summary: null,
          ai_severity: null,
          model_id: null,
          completed_at: null,
          attempts: 3,
        },
      }),
    );
    expect(screen.queryByText("AI")).not.toBeInTheDocument();
    // rule title appears both as link and as fallback one-liner
    expect(screen.getAllByText("Suspicious encoded PowerShell").length).toBeGreaterThan(1);
  });

  it("renders hostile AI/event strings as PLAIN TEXT — no HTML injection (SEC-31)", () => {
    const hostile =
      '<img src=x onerror="window.pwned=1"> **not markdown** <script>alert(1)</script>';
    const { container } = renderRow(
      makeAlert({
        triage: {
          status: "completed",
          summary: hostile,
          ai_severity: "low",
          model_id: "fast-1",
          completed_at: "2026-07-08T09:01:00Z",
          attempts: 1,
        },
        entity: { hostname: "<b>evil-host</b>", user: null, asset_id: null },
      }),
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    // The literal text must be visible, escaped.
    expect(screen.getByText(hostile)).toBeInTheDocument();
    expect(screen.getByText("<b>evil-host</b>")).toBeInTheDocument();
  });

  it("offers acknowledge only for new alerts and close for non-closed alerts", () => {
    renderRow(makeAlert({ state: "acknowledged" }));
    expect(screen.queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
  });
});
