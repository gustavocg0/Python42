import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { QuotaDisplay } from "@/components/alerts/QuotaDisplay";

describe("QuotaDisplay (AC-53/54)", () => {
  it("shows remaining runs and reset time", () => {
    render(
      <QuotaDisplay
        quota={{ limit: 5, remaining: 3, resets_at: "2026-07-09T00:00:00Z" }}
      />,
    );
    const el = screen.getByTestId("quota-display");
    expect(el.textContent).toContain("3 of 5 deep investigations left today");
  });

  it("shows exhausted state with the reset time (AC-54)", () => {
    render(
      <QuotaDisplay
        quota={{ limit: 5, remaining: 0, resets_at: "2026-07-09T00:00:00Z" }}
      />,
    );
    const el = screen.getByTestId("quota-display");
    expect(el.textContent).toContain("used all 5 deep investigations");
    // ux spec §2.6: both the UTC anchor and a localized rendering.
    expect(el.textContent).toContain("resets at 00:00 UTC");
    expect(el.textContent).toContain("your time");
  });

  it("shows unlimited for limit -1", () => {
    render(
      <QuotaDisplay
        quota={{ limit: -1, remaining: -1, resets_at: "2026-07-09T00:00:00Z" }}
      />,
    );
    expect(screen.getByTestId("quota-display").textContent).toContain("unlimited");
  });
});
