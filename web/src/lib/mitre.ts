/**
 * Plain-language MITRE ATT&CK technique strings per
 * docs/design/ux-alert-style.md §3: one-sentence formula ("Attackers {do
 * what} so they can {goal}"), static managed content keyed by technique ID —
 * never LLM-generated at runtime. The five §3.3 worked examples are verbatim.
 * Display pattern (§3.1): plain sentence first, then "{Name} · {ID} — Learn
 * more (MITRE ATT&CK)".
 */

interface TechniqueInfo {
  name: string;
  sentence: string;
}

const TECHNIQUES: Record<string, TechniqueInfo> = {
  // ---- ux-alert-style.md §3.3 canonical strings (verbatim) ----
  "T1059.001": {
    name: "Command and Scripting Interpreter: PowerShell",
    sentence:
      "Attackers run commands through PowerShell — a tool built into every Windows machine — so they can act without installing anything that antivirus might catch.",
  },
  T1110: {
    name: "Brute Force",
    sentence:
      "Attackers guess passwords over and over, usually with automated tools, so they can break into an account without needing to steal the password first.",
  },
  "T1021.001": {
    name: "Remote Services: Remote Desktop Protocol",
    sentence:
      "Attackers sign in over Remote Desktop — the same tool IT uses for remote support — so they can move from one computer to another inside your network.",
  },
  "T1547.001": {
    name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    sentence:
      "Attackers add their program to the list of things Windows starts automatically, so their access survives every restart.",
  },
  "T1071.001": {
    name: "Application Layer Protocol: Web Protocols",
    sentence:
      "Attackers make an infected computer quietly report back to a server they control, disguising that traffic as ordinary web browsing so it isn't noticed.",
  },
  // ---- additional starter-pack techniques, authored to the §3.2 formula ----
  T1059: {
    name: "Command and Scripting Interpreter",
    sentence:
      "Attackers run commands and scripts using tools already on the computer, so they can act without installing new software that might be noticed.",
  },
  "T1059.003": {
    name: "Command and Scripting Interpreter: Windows Command Shell",
    sentence:
      "Attackers run commands through the Windows command prompt, so they can control the computer using a tool that is always available.",
  },
  T1078: {
    name: "Valid Accounts",
    sentence:
      "Attackers sign in with a real username and password they stole, so they can look like a normal user instead of breaking in.",
  },
  "T1110.001": {
    name: "Brute Force: Password Guessing",
    sentence:
      "Attackers try many passwords against one account, so they can break in without stealing the password first.",
  },
  "T1110.003": {
    name: "Brute Force: Password Spraying",
    sentence:
      "Attackers try a few common passwords across many accounts, so they can break in without triggering account lockouts.",
  },
  T1021: {
    name: "Remote Services",
    sentence:
      "Attackers use remote-access features like Remote Desktop or admin shares, so they can move from one computer to another inside your network.",
  },
  T1046: {
    name: "Network Service Discovery",
    sentence:
      "Attackers scan your network for open services, so they can learn what they can reach and attack next.",
  },
  T1053: {
    name: "Scheduled Task/Job",
    sentence:
      "Attackers create scheduled tasks, so they can keep a way to run their program even after a restart.",
  },
  "T1053.005": {
    name: "Scheduled Task/Job: Scheduled Task",
    sentence:
      "Attackers create a Windows scheduled task, so they can keep a way to run their program even after a restart.",
  },
  T1547: {
    name: "Boot or Logon Autostart Execution",
    sentence:
      "Attackers set their program to start automatically when the computer boots, so their access survives every restart.",
  },
  T1566: {
    name: "Phishing",
    sentence:
      "Attackers send a fake email or message designed to trick someone into opening a file or link, so they can get their first foothold inside your network.",
  },
  T1105: {
    name: "Ingress Tool Transfer",
    sentence:
      "Attackers download extra malicious programs onto a computer they control, so they can expand what they are able to do.",
  },
  T1071: {
    name: "Application Layer Protocol",
    sentence:
      "Attackers make an infected computer repeatedly contact a server they control over normal-looking traffic, so their communication isn't noticed.",
  },
  T1003: {
    name: "OS Credential Dumping",
    sentence:
      "Attackers read stored passwords from the computer's memory or files, so they can sign in to other accounts and computers.",
  },
  T1486: {
    name: "Data Encrypted for Impact",
    sentence:
      "Attackers encrypt your files and demand payment to unlock them, so they can extort your business (ransomware).",
  },
  T1562: {
    name: "Impair Defenses",
    sentence:
      "Attackers turn off or weaken security tools like antivirus or logging, so their activity is harder to see and stop.",
  },
  T1136: {
    name: "Create Account",
    sentence:
      "Attackers create a new user account, so they can keep access even if the account they broke into gets fixed.",
  },
  T1112: {
    name: "Modify Registry",
    sentence:
      "Attackers change Windows settings in the registry, so they can hide their activity or keep access after a restart.",
  },
  T1055: {
    name: "Process Injection",
    sentence:
      "Attackers hide malicious code inside a normal running program, so security tools see only the trusted program.",
  },
  T1033: {
    name: "System Owner/User Discovery",
    sentence:
      "Attackers check which account is signed in and what it can access, so they can plan their next step.",
  },
  T1087: {
    name: "Account Discovery",
    sentence:
      "Attackers list the accounts that exist on a computer or network, so they can find valuable ones to target.",
  },
};

/** §3.2 fallback for an unmapped ID — never blank. */
const FALLBACK_SENTENCE =
  "A known attack technique. Learn more on MITRE ATT&CK.";

export function techniqueDescription(id: string): string {
  const exact = TECHNIQUES[id];
  if (exact) return exact.sentence;
  const parent = id.split(".")[0];
  if (parent && TECHNIQUES[parent]) return TECHNIQUES[parent]!.sentence;
  return FALLBACK_SENTENCE;
}

export function techniqueName(id: string): string | null {
  return TECHNIQUES[id]?.name ?? null;
}

export function techniqueUrl(id: string): string {
  const [parent, sub] = id.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${parent}/${sub}/`
    : `https://attack.mitre.org/techniques/${parent}/`;
}
