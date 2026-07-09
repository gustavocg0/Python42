import { describe, expect, it } from "vitest";
import { parseTriageSummary, priorityBand, triageOneLiner } from "@/lib/triage";

// Canonical fixture from docs/design/ux-alert-style.md §1.9 Example A.
const EXAMPLE_A = [
  "What happened: The computer fin-laptop-07 ran a PowerShell command at 09:42 UTC under the account sam.jones. The command was disguised so its contents could not be read directly, which is a common way to hide malicious activity.",
  "Why it matters: Normal software rarely hides its commands this way. If an attacker ran this, they may already have remote control of this computer.",
  "Do this next: Ask sam.jones whether they or your IT tools ran a script around 09:42 UTC. If not, disconnect fin-laptop-07 from the network now and change sam.jones's password.",
].join("\n");

describe("parseTriageSummary (ux spec §1.1)", () => {
  it("parses the three labeled lines", () => {
    const parsed = parseTriageSummary(EXAMPLE_A);
    expect(parsed).not.toBeNull();
    expect(parsed!.whatHappened).toMatch(/^The computer fin-laptop-07/);
    expect(parsed!.whyItMatters).toMatch(/^Normal software rarely/);
    expect(parsed!.doThisNext).toMatch(/^Ask sam\.jones/);
  });

  it("returns null for free-form text (renderer falls back to raw plain text)", () => {
    expect(parseTriageSummary("just a blob of text")).toBeNull();
    expect(parseTriageSummary("What happened: x\nWrong label: y\nDo this next: z")).toBeNull();
  });
});

describe("triageOneLiner (ux spec §2.1)", () => {
  it("returns the first sentence of the What-happened line", () => {
    expect(triageOneLiner(EXAMPLE_A)).toBe(
      "The computer fin-laptop-07 ran a PowerShell command at 09:42 UTC under the account sam.jones.",
    );
  });

  it("falls back to the first sentence of unstructured text", () => {
    expect(triageOneLiner("First sentence. Second sentence.")).toBe("First sentence.");
  });
});

describe("priorityBand (ux spec §2.2)", () => {
  it("maps score bands", () => {
    expect(priorityBand(100)).toBe("Act today");
    expect(priorityBand(85)).toBe("Act today");
    expect(priorityBand(84)).toBe("Look soon");
    expect(priorityBand(60)).toBe("Look soon");
    expect(priorityBand(59)).toBe("When you get to it");
    expect(priorityBand(40)).toBe("When you get to it");
    expect(priorityBand(26)).toBe("Low");
  });
});
