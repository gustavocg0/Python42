# UX Spec: Plain-Language Alert Style & Console Presentation

- **Status:** v1 — 2026-07-08
- **Owner:** ux-designer (resolves PRD AC-48 note "ux-designer to define style guide")
- **Consumers:** ai-platform (triage prompt + output validation), frontend-architect (console rendering + microcopy), qa (AC-48 structure checks)
- **Inputs:** `docs/prd/platform-foundation-mvp.md` (§2 personas, E7 AC-48/49/50/53/54, E9 AC-70..76), `docs/contracts/api-contracts.md` §8–9, `docs/contracts/priority-score.md`
- Changes to the summary structure (§1.1) or QA checks (§1.8) require ai-platform + qa sign-off, because prompt templates and AC-48 tests pattern on them.

Design target for every rule in this document: **Sam, an IT generalist with
zero SOC experience, reading on a busy afternoon.** If a sentence needs
googling, it fails.

---

## 1. Triage-Summary Style Guide (for the ai-platform prompt)

### 1.1 Structure (mandatory, machine-checkable)

Every triage summary is **plain text** (no markdown — clients render triage
strings as plain text per SEC-31/33), exactly **three lines** separated by
single `\n`, each starting with a fixed label:

```
What happened: <≤50 words>
Why it matters: <≤40 words>
Do this next: <≤30 words>
```

- Total ≤ **120 words** (AC-48), counting the labels.
- Labels are exact, English, sentence case, followed by `: `. Never reordered,
  never omitted, never renamed. If the model has little to say, a line may be
  short — it may never be missing.
- No blank lines, no bullet characters, no markdown (`*`, `#`, `` ` ``, `[]()`),
  no URLs, no emojis, no exclamation marks.
- The frontend parses the three fixed prefixes and renders them as three
  labeled sections (the headings come from the client, not from model markup).

### 1.2 Line-by-line content rules

**What happened** — observable facts only, past tense:
- Name the device and account (see §1.5), the action, and the time
  (UTC, `HH:MM UTC`; the frontend shows a localized timestamp separately, so
  the summary stays stable text).
- If `occurrence_count > 1`, state it plainly: "This happened 7 times between
  09:42 and 10:15 UTC."
- Quote command/tool names in single quotes: `'whoami'`, `'PowerShell'`.
  Never reproduce encoded/base64 blobs, full command lines longer than ~6
  words, file hashes, or raw log content — that lives in the evidence section.

**Why it matters** — the "so what" for a non-expert:
- Explain what an attacker gains if this is real, in everyday words.
- Mention the innocent explanation when one commonly exists (see §1.6).
- Never restate the rule title or the technique ID here.

**Do this next** — exactly one concrete, doable action:
- MVP response mode is `recommend_only`: recommend human verification and
  manual steps only. Never claim the platform did or will do anything
  ("we blocked", "we quarantined" are banned).
- Verification-first pattern: "Ask <person> whether <innocent explanation>.
  If not, <containment step>." Containment steps Sam can actually do:
  disconnect from the network, change the password, sign the account out,
  uninstall the program, call your IT provider.
- One action, at most two sentences. Never a numbered list.

### 1.3 Reading level

- Target: **US grade 8 / CEFR B1** (Flesch-Kincaid grade ≤ 9, Flesch Reading
  Ease ≥ 55). This is a prompt instruction plus an offline eval check for
  ai-platform, not a runtime gate.
- Sentences ≤ 20 words; average ≤ 15. Active voice. One idea per sentence.
- Assume the reader knows what Windows, a password, and a server are — and
  nothing about attack terminology.

### 1.4 Banned jargon → required plain replacements

The model must not emit the left column in any summary line. Use the right
column (or an equivalent plain paraphrase). QA may spot-check with a
denylist scan (§1.8).

| Banned term | Use instead |
|---|---|
| lateral movement | "moving from one computer to another inside your network" |
| C2 / command and control | "a server controlled by the attacker" |
| beaconing / callback | "repeatedly contacting the same outside server" |
| exfiltration | "copying data out of your network" |
| persistence (mechanism) | "a way to keep access even after a restart" |
| privilege escalation | "gaining admin-level control" |
| credential dumping / credential access | "stealing stored passwords" |
| brute force | "guessing many passwords in a short time" |
| payload / dropper / implant / RAT | "malicious program" |
| reverse shell / shell access | "a remote-control connection to the computer" |
| obfuscated / encoded (unexplained) | "disguised so its contents can't be read directly" |
| process injection | "hiding malicious code inside a normal program" |
| living off the land / LOLBin | "using tools already built into Windows" |
| enumeration / recon / discovery | "looking around to learn what it can access" |
| IOC / indicator | "a known sign of an attack" |
| threat actor / adversary / TTP | "attacker" |
| endpoint / host (as nouns) | "computer" or "device" |
| compromised (unexplained) | "under an attacker's control" |
| mitigate / remediate | "fix" / "stop" |
| exploit (verb) | "take advantage of a flaw in" |
| phishing (alone) | "a fake email or message designed to trick someone" (the word may appear WITH this gloss) |
| zero-day / CVE-XXXX | "a software flaw" (CVE IDs belong in evidence, not the summary) |

Allowed without explanation: product/OS names (Windows, PowerShell, Remote
Desktop, Office), "sign-in", "admin", "server", "network", "password",
"malware" ("malicious software" preferred on first use).

### 1.5 Referencing hosts, users, and the tenant

- Use the exact values from `alert.entity`: "the computer fin-laptop-07",
  "the account sam.jones". Lowercase-as-given; never invent friendly names,
  never truncate, never guess the human behind an account ("ask sam.jones"
  not "ask Sam Jones" — the display name is unknown).
- Missing hostname: "one of your devices". Missing user: omit the account
  clause entirely (never "unknown user", which reads as scarier than it is).
- Service-account-looking names (`svc-*`, `*$`, `system`, `admin*`) may be
  described as "which looks like an automated service account" — hedged
  exactly like that, since it is an inference.
- Say "your network" / "your devices", never the org name (the org name is
  tenant data the prompt does not need — keeps prompts lean per AC-52).

### 1.6 Uncertainty phrasing

Alerts are leads, not verdicts. The summary must be honest without drowning
in hedges:

- Facts stay unhedged: "fin-laptop-07 ran a disguised PowerShell command"
  (that IS what was detected).
- Interpretation is hedged once, with a named innocent alternative when one
  is common: "This is a common attacker technique, but some IT management
  tools do the same thing."
- Allowed hedge patterns: "may", "can also be", "is often", "there is no
  sign yet of", "if this wasn't you/your IT tools".
- Banned: stacked hedges ("could possibly perhaps"), fake precision
  ("87% likely malicious"), "it appears that it seems", and unhedged verdicts
  ("this computer is infected") unless the evidence is definitional.

### 1.7 Tone rules

1. Calm and specific. Urgency comes from the severity chip and queue
   position, not from prose ("URGENT", "immediately!!!" are banned; "now" is
   allowed in the action line of high/critical alerts).
2. Never blame the named user; treat them as the first witness to ask.
3. Second person for the reader ("Ask…", "Check…"); the platform is "we"
   only for detection facts ("we flagged this because…" — sparingly).
4. No filler ("Please note that", "It is important to"), no apologies, no
   marketing.

### 1.8 QA structure checks (what AC-48 tests assert)

Deterministic checks (QA verifies structure and presence, not prose quality):

1. Exactly 3 lines split on `\n`; line 1 matches `^What happened: \S`, line 2
   `^Why it matters: \S`, line 3 `^Do this next: \S`.
2. Total whitespace-separated word count ≤ 120.
3. No characters from the markdown/format denylist: `` ` ``, `**`, `# `,
   `](`, `http://`, `https://`, no emoji codepoints, no `!`.
4. Case-insensitive denylist scan for §1.4 banned terms (exact-phrase match;
   "phishing" exempt when followed within the sentence by "trick").
5. Hostname/user in the summary, when present, exactly equal
   `entity.hostname` / `entity.user` (guards against model-invented entities).

ai-platform should run 1–4 as a post-generation validator and regenerate once
on failure; on second failure, fall back to `triage: unavailable` behavior
(AC-50) rather than shipping malformed text.

### 1.9 Full example summaries (AC-48 QA pattern targets)

**Example A — high severity** (rule `win_susp_encoded_powershell`, T1059.001,
host `fin-laptop-07`, user `sam.jones`, occurrence_count 1):

```
What happened: The computer fin-laptop-07 ran a PowerShell command at 09:42 UTC under the account sam.jones. The command was disguised so its contents could not be read directly, which is a common way to hide malicious activity.
Why it matters: Normal software rarely hides its commands this way. If an attacker ran this, they may already have remote control of this computer.
Do this next: Ask sam.jones whether they or your IT tools ran a script around 09:42 UTC. If not, disconnect fin-laptop-07 from the network now and change sam.jones's password.
```
(88 words)

**Example B — medium severity** (failed-logon burst rule, T1110, host
`hr-desktop-02`, user `m.rivera`, occurrence_count 24):

```
What happened: The account m.rivera on the computer hr-desktop-02 had 24 failed sign-in attempts between 14:05 and 14:15 UTC. No sign-in succeeded during or after the attempts.
Why it matters: Many failures in a short burst usually means a person or automated tool is guessing the password. Since none succeeded, there is no sign of a break-in yet.
Do this next: Ask m.rivera whether they had password trouble around 14:05 UTC. If they did not, change their password and watch this account for new alerts over the next few days.
```
(94 words)

**Example C — low severity** (account-discovery rule, T1033/T1087, host
`ops-server-01`, user `svc-backup`, occurrence_count 1):

```
What happened: The computer ops-server-01 ran 'whoami' at 03:12 UTC under the account svc-backup, which looks like an automated service account. This built-in Windows command shows which account is signed in and what it can access.
Why it matters: Admins and scheduled jobs use this command every day, but attackers also run it early on to learn what access they have. On its own, this is low risk.
Do this next: Check whether a backup job or scheduled task runs on ops-server-01 around 03:12 UTC. If nothing explains it, watch this computer for further alerts.
```
(97 words)

These three pass every check in §1.8 and are the canonical fixtures for QA
and for few-shot examples in the ai-platform prompt.

---

## 2. Alert Presentation Spec (for the web console)

### 2.1 AI-generated labeling (AC-49)

- Every rendered triage summary carries a persistent badge, text:
  **"AI-generated"** — placed on the summary card header, next to the heading
  **"Summary"**. Never abbreviate to an icon alone.
- The badge has an info affordance (hover/tap). Tooltip copy:
  > "This summary was written by an AI model from this alert's detection
  > data. It can be wrong. Check the evidence below before taking major
  > action."
- Queue rows (AC-72): the plain-language one-liner (first sentence of the
  "What happened" line) is prefixed with a small sparkle-style "AI" chip with
  the same tooltip. When `triage.status != completed`, show the rule title
  instead, with no AI chip.
- Triage unavailable (AC-50), summary card body:
  > "An AI summary isn't available for this alert. The information below
  > comes directly from the detection rule."
  Sub-line while `triage.status = pending`: "AI summary on the way — usually
  under 2 minutes." (Card renders immediately; never block the alert view.)

### 2.2 Severity display when AI and rule disagree

Data: `rule.severity` (authoritative for the `severity=` filter),
`triage.ai_severity` (raw model output per priority-score contract §2 —
display is never the clamped value), `priority_score` (already blends both).

- **Detail view:** always show two labeled chips side by side:
  `Detection rule: High` and `AI assessment: Medium`. When both exist and
  are equal, collapse to one chip `High` with subtext "rule and AI agree".
  When triage is absent, show only `Detection rule: High`.
- **Disagreement explainer** (shown only when they differ, one line under
  the chips):
  > "The detection rule and the AI reviewer rated this differently. The
  > queue position (priority {score}) takes both into account."
- **Queue rows:** show the rule-severity chip. If AI severity differs, append
  a compact secondary tag `AI: medium`. Never show AI severity alone
  anywhere — the rule's rating is never hidden (AC-49).
- **Priority score:** display as `Priority {n}` with band label for
  scanning: 85–100 "Act today", 60–84 "Look soon", 40–59 "When you get to
  it", 26–39 "Low". Bands are display-only (frontend constants), never sent
  to or produced by the model, and do not affect sorting (`-priority` per
  API contract §8).

### 2.3 Alert detail view — progressive disclosure order (AC-74)

Top to bottom; sections 5–8 render collapsed with a one-line preview and
count, so the raw data is always reachable in ≤ 2 clicks but never first:

1. **Header:** alert title (rule title), state chip, `Priority {n}` + band,
   severity chips per §2.2, "AI-generated" badge context.
2. **Summary card:** the three labeled sections parsed from the triage text
   ("What happened / Why it matters / Do this next" as rendered headings).
3. **Key facts strip:** computer (links to asset detail), account,
   occurrence count ("seen 7 times"), first seen / last seen (localized,
   with UTC on hover), agent status of the affected asset.
4. **Actions bar:** Acknowledge / Close (reason picker per AC-45: labels
   "Fixed", "False alarm", "Expected behavior", "Duplicate" mapping to
   `resolved|false_positive|expected_behavior|duplicate`) / Reopen; "Run
   deep investigation" with quota state per §2.6.
5. **Attack technique(s)** — collapsed; preview: first technique's plain
   sentence (§3). Expanded: all techniques per the §3 pattern.
6. **Related alerts** — collapsed; preview: "{n} related alerts on this
   computer" (correlation group, AC-43). Expanded: sibling list with
   priority, title, state.
7. **Evidence** — collapsed; preview: "{n} matched events". Expanded:
   normalized event list; each row expands again to raw JSON (monospace,
   copy button). This is the "never hides raw detection data" guarantee of
   AC-49 — the section header is always visible even when collapsed.
8. **Activity history** — collapsed; audit trail entries ("sam.jones closed
   this as False alarm — 2 Jul, 16:20").

Expansion state persists per user per section (not per alert).

### 2.4 Empty-state copy pattern (AC-71)

Formula for every empty view — three parts, always in this order:
**(1) what will appear here, (2) why it's empty right now, (3) one action
linking to the relevant onboarding step.** No blank tables, no bare spinners.

| View | Copy |
|---|---|
| Alert queue (no data ever) | "Alerts will appear here when we detect suspicious activity on your devices. Nothing is monitored yet because no device has sent data. → Install the agent on your first device" (links onboarding step 1) |
| Alert queue (data flowing, zero alerts) | "All clear. Your devices are sending data and nothing suspicious has been detected. New alerts appear here automatically — most admins check once or twice a day." (no action link) |
| Alert queue (filters match nothing) | "No alerts match these filters. → Clear filters" (distinct from onboarding empty state) |
| Asset inventory (empty) | "Every monitored device shows up here, deduplicated — this is also the count your plan is based on. It's empty because no agent is installed and no logs are arriving. → Install the agent" |
| Events/evidence not yet arrived (post-install) | "Waiting for the first data from {hostname}. This usually takes under a minute after install. → Troubleshoot agent install" |
| Audit log (empty) | "A record of every change in this tenant — sign-ins, key creation, alert actions — appears here. Nothing has happened yet." |
| Deep investigation history (empty) | "Past deep investigations for this alert will be listed here. You haven't run one yet." |
| Loading states | Skeleton rows + one line: "Loading your alerts…" — never a spinner without text; after 10 s add "Still working — this tenant may be busy. → Retry". |

### 2.5 Onboarding checklist microcopy (AC-70)

Checklist title: **"Get protected in about 15 minutes"**. Steps (IDs match
`GET /v1/onboarding/status`):

1. **`install_agent` — "Install the agent on your devices"**
   Body: "Generate an install token, then run one command on each Windows
   device — by hand or through GPO/Intune. The token works for all your
   devices until it expires." Buttons: "Generate token" → token modal
   ("Copy this now — we only show it once. Expires {date}."). Done state:
   "{n} devices enrolled".
2. **`create_ingest_key` — "Optional: send logs from other tools"**
   Body: "Have a firewall or server that writes JSON logs? Create an ingest
   key and POST them to us — no agent needed." Skippable, labeled
   "Optional"; skipping never blocks checklist completion UI. Done state:
   "Ingest key created".
3. **`first_event` — "Confirm data is arriving"** (auto-completes)
   Body (todo): "This step completes itself the moment your first event
   arrives — nothing to do but wait, usually under a minute after install."
   Done state: "First event received {relative time}".
4. **`view_queue` — "See your alert queue"**
   Body: "This is your home screen from now on. Alerts are sorted so the
   most important one is always on top." Button: "Open alert queue". Done
   on first visit.

Checklist collapses to a compact progress pill ("Setup 3/4") in the header
once ≥ 1 step is done; fully disappears 7 days after all steps complete.

### 2.6 Quota messaging — deep investigation (AC-53/54)

- Button idle state shows remaining quota inline: **"Run deep investigation
  ({remaining} of {limit} left today)"**. Pro/unlimited (`limit: -1`): no
  count shown.
- Quota exhausted (`QUOTA_EXCEEDED_DEEP_INVESTIGATION`, or `remaining: 0`
  known up front): button disabled, inline text:
  > "You've used all {limit} deep investigations for today. Your allowance
  > resets at 00:00 UTC ({localized time, e.g. '02:00 tomorrow, your
  > time'})."
  Compute the localized time from `details.resets_at` / `quota.resets_at`;
  always show BOTH the UTC anchor and the localized rendering. No quota is
  consumed by the failed attempt — never show a decremented count after a
  403.
- Stub result (`is_stub: true`): render the API's `summary` verbatim inside
  a card labeled **"Preview"** with sub-line "Full deep investigation is
  coming soon. This run confirmed your plan and quota." (Quota WAS consumed
  on success — show the updated `quota.remaining`.)
- Plan lacks the feature (`ENTITLEMENT_DENIED`): button visible but locked,
  text: "Deep investigation isn't in your current plan." (Server enforces;
  UI hiding is never the gate, AC-17.)

### 2.7 Banner copy — trial expired, frozen, ingest quota

Banners are full-width, dismiss-for-session only (they reappear next
session while the condition holds).

**Trial expired (AC-9 — read-only console, `TENANT_FROZEN` cause `trial`):**
> **"Your free trial ended {date}."** "Your alerts and asset data are safe
> and view-only, but we've stopped collecting new data — your devices are
> not being monitored. To keep protection running, contact us to pick a
> plan. Unless you upgrade, all data will be permanently deleted on
> {expiry + 30 days}."
> Button: "Contact us to upgrade" (mailto/support link — no payment flow in
> MVP). Style: warning (amber) until 7 days before purge, then danger (red)
> with "Deleted in {n} days" prefix.

**Abuse-frozen tenant (`TENANT_FROZEN`, `details.cause = "abuse"`):**
> **"This account is temporarily suspended."** "Data collection and changes
> are paused while we review unusual activity on this account. Your existing
> data is view-only. If you believe this is a mistake, contact support and
> we'll sort it out."
> Style: danger. Never state what triggered the freeze (SEC-39 —
> anti-gaming). All write actions render disabled with tooltip "Unavailable
> while the account is suspended."

**Ingest quota (AC-88 console notification at sustained 80%):**
> "You're sending data close to your plan's limit ({current} of {limit}
> events/min). If you go over, we'll ask senders to slow down and retry —
> nothing is silently lost." Link: "See usage". At actual throttling
> (429s observed via `throttled_batches_24h > 0`): "Some data senders are
> being asked to slow down and retry ({n} batches in the last 24 h). Data
> is delayed, not lost."

**Endpoint cap (AC-14 banner on asset inventory, `ENDPOINT_CAP_REACHED`):**
> "You've reached your plan's limit of {endpoint_cap} devices, so new
> devices can't enroll. Remove devices you no longer use, or contact us to
> raise the limit."

---

## 3. MITRE Technique Plain-Language Pattern

### 3.1 Display pattern

In the alert detail "Attack technique(s)" section, each technique renders
as:

```
{Plain-language sentence}
{Technique name} · {ID}  —  Learn more (MITRE ATT&CK) ↗
```

The plain sentence leads; the official name and ID are the de-emphasized
second line (Sam doesn't know ATT&CK; Morgan and auditors want the ID).
"Learn more" opens attack.mitre.org in a new tab.

### 3.2 One-sentence formula

> **"Attackers {do what, in everyday words}{— optionally: using what
> familiar thing} so they can {goal the reader cares about}."**

Rules: one sentence, ≤ 30 words, present tense, subject is always
"Attackers", obeys the §1.4 jargon denylist, names the built-in tool when
the technique abuses one ("the same tool IT uses for X" pattern builds
recognition). These strings ship as **static managed content keyed by
technique ID** (authored with detection-engineering's rule pack, one string
per technique in the ≥20-rule starter pack) — they are NOT LLM-generated at
runtime. Fallback for an unmapped ID: "A known attack technique. Learn more
on MITRE ATT&CK." (never blank).

### 3.3 Worked examples (canonical strings for the starter pack)

| ID | Name (2nd line) | Plain-language sentence (1st line) |
|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | "Attackers run commands through PowerShell — a tool built into every Windows machine — so they can act without installing anything that antivirus might catch." |
| T1110 | Brute Force | "Attackers guess passwords over and over, usually with automated tools, so they can break into an account without needing to steal the password first." |
| T1021.001 | Remote Services: Remote Desktop Protocol | "Attackers sign in over Remote Desktop — the same tool IT uses for remote support — so they can move from one computer to another inside your network." |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | "Attackers add their program to the list of things Windows starts automatically, so their access survives every restart." |
| T1071.001 | Application Layer Protocol: Web Protocols | "Attackers make an infected computer quietly report back to a server they control, disguising that traffic as ordinary web browsing so it isn't noticed." |

These five double as authoring exemplars: any new rule-pack technique string
must be reviewable against the formula in §3.2 by a non-security reader.

---

## Appendix: traceability

| Spec section | Satisfies |
|---|---|
| §1.1–1.9 | AC-48 (style guide + QA pattern), AC-50 (fallback copy), SEC-31/33 (plain text) |
| §2.1 | AC-49 labeling, AC-72 one-liner |
| §2.2 | AC-49 dual severity, priority-score contract §2 (raw `ai_severity` display) |
| §2.3 | AC-74 detail view, AC-49 progressive disclosure |
| §2.4 | AC-71 empty states |
| §2.5 | AC-70 onboarding checklist, AC-56 token copy |
| §2.6 | AC-53/54 quota + reset time, AC-17 locked-not-hidden |
| §2.7 | AC-9 trial banner, SEC-39 abuse freeze, AC-88 quota notice, AC-14 cap banner |
| §3 | AC-74 "MITRE technique(s) with plain-language descriptions" |
