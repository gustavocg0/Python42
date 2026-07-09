/**
 * Triage-summary parsing per docs/design/ux-alert-style.md §1.1: summaries
 * are exactly three plain-text lines with fixed labels. The frontend parses
 * the prefixes and renders them as labeled sections; the headings come from
 * the client, never from model markup. Unparseable summaries fall back to
 * raw plain-text rendering (still SEC-31-safe).
 */

export interface ParsedTriageSummary {
  whatHappened: string;
  whyItMatters: string;
  doThisNext: string;
}

const LINE_PATTERNS: [keyof ParsedTriageSummary, RegExp][] = [
  ["whatHappened", /^What happened:\s*(\S.*)$/],
  ["whyItMatters", /^Why it matters:\s*(\S.*)$/],
  ["doThisNext", /^Do this next:\s*(\S.*)$/],
];

export function parseTriageSummary(summary: string): ParsedTriageSummary | null {
  const lines = summary.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  if (lines.length !== 3) return null;
  const result: Partial<ParsedTriageSummary> = {};
  for (let i = 0; i < 3; i++) {
    const entry = LINE_PATTERNS[i];
    const line = lines[i];
    if (!entry || line === undefined) return null;
    const [key, pattern] = entry;
    const match = pattern.exec(line);
    if (!match || match[1] === undefined) return null;
    result[key] = match[1];
  }
  return result as ParsedTriageSummary;
}

/**
 * Queue one-liner (ux spec §2.1): the first sentence of the "What happened"
 * line; falls back to the whole summary's first sentence.
 */
export function triageOneLiner(summary: string): string {
  const parsed = parseTriageSummary(summary);
  const source = parsed ? parsed.whatHappened : summary;
  const sentenceEnd = source.search(/[.?](\s|$)/);
  return sentenceEnd >= 0 ? source.slice(0, sentenceEnd + 1) : source;
}

/** Priority band labels (ux spec §2.2) — display-only, never affects sorting. */
export function priorityBand(score: number): string {
  if (score >= 85) return "Act today";
  if (score >= 60) return "Look soon";
  if (score >= 40) return "When you get to it";
  return "Low";
}
