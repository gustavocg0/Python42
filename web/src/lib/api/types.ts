/**
 * Hand-written types mirroring docs/contracts/api-contracts.md (ratified v1.1).
 * All IDs are opaque strings; all timestamps are RFC3339 UTC strings.
 */

// ---------- shared ----------

export interface Paginated<T> {
  items: T[];
  next_cursor: string | null;
  total_estimate: number;
}

export type Severity = "low" | "medium" | "high" | "critical";
export type Role = "admin" | "analyst";

// ---------- signup & provisioning (controlplane §3) ----------

export interface SignupRequest {
  org_name: string;
  email: string;
  password: string;
  challenge_response?: string;
}

export interface SignupResponse {
  account_id: string;
  state: "pending_verification";
}

export interface VerifyResponse {
  tenant_id: string;
  provisioning: "in_progress";
}

export type ProvisioningState =
  | "pending_verification"
  | "provisioning"
  | "ready"
  | "provisioning_failed";

export interface ProvisioningStatus {
  state: ProvisioningState;
  console_url?: string;
}

// ---------- auth & users (controlplane §4) ----------

export type TenantStatus = "active" | "frozen" | "purged" | (string & {});

export interface TenantInfo {
  id: string;
  name: string;
  status: TenantStatus;
  abuse_frozen: boolean;
  trial_expires_at?: string;
}

export interface UserInfo {
  id: string;
  email: string;
  role: Role;
  created_at?: string;
}

export interface LoginResponse {
  user: UserInfo;
  tenant: TenantInfo;
}

/** GET /v1/me — "user + role + tenant status" (mirrors the login payload). */
export interface Me {
  user: UserInfo;
  tenant: TenantInfo;
}

// ---------- entitlements (controlplane §5) ----------

export type ResponseMode = "recommend_only" | "playbooks_with_approval";

export interface Entitlements {
  plan: "trial" | "core" | "pro" | (string & {});
  tenant_status: TenantStatus;
  abuse_frozen: boolean;
  trial_expires_at?: string;
  entitlements: {
    endpoint_cap: number;
    retention_days: number;
    /** -1 means unlimited */
    deep_investigation_daily_quota: number;
    response_mode: ResponseMode;
    ingest_events_per_min: number;
  };
  as_of: string;
}

// ---------- ingest keys & usage (dataplane §6) ----------

export interface IngestKeyCreated {
  id: string;
  name: string;
  /** shown once — never persisted client-side */
  key: string;
  created_at: string;
}

export interface IngestKey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export interface IngestUsage {
  events_per_min_current: number;
  events_per_min_limit: number;
  throttled_batches_24h: number;
  rejected_events_24h: number;
  warning_active: boolean;
}

// ---------- assets (dataplane §7) ----------

export type AgentStatus = "enrolled" | "healthy" | "offline" | "revoked" | "none";
export type AssetSource = "agent" | "log_ingest";

export interface AssetIdentity {
  /** Needed for POST /v1/assets/{id}/split identity_ids — see contract note in web/README.md */
  id: string;
  source: AssetSource;
  identifier_type: string;
  value: string;
}

export interface MergeAuditEntry {
  at: string;
  rule: string;
  merged_identity: Record<string, unknown>;
  actor: string;
}

export interface Asset {
  id: string;
  hostname: string;
  os_family: string;
  os_name: string;
  os_version: string;
  sources: AssetSource[];
  agent_status: AgentStatus;
  agent?: {
    device_id: string;
    version: string;
    last_heartbeat_at: string;
  };
  identities: AssetIdentity[];
  merge_audit: MergeAuditEntry[];
  billable: boolean;
  first_seen: string;
  last_seen: string;
  created_via: string;
}

export interface BillableCount {
  billable_count: number;
  endpoint_cap: number;
  window_days: number;
  computed_at: string;
}

export interface AssetListParams {
  source?: AssetSource;
  agent_status?: AgentStatus;
  billable?: boolean;
  q?: string;
  limit?: number;
  cursor?: string;
}

// ---------- alerts (dataplane §8) ----------

export type AlertState = "new" | "acknowledged" | "closed";
export type TriageStatus = "pending" | "completed" | "unavailable";
export type CloseReason =
  | "resolved"
  | "false_positive"
  | "expected_behavior"
  | "duplicate";

export const CLOSE_REASONS: CloseReason[] = [
  "resolved",
  "false_positive",
  "expected_behavior",
  "duplicate",
];

export interface AlertRule {
  id: string;
  version: string;
  title: string;
  severity: Severity;
  mitre_technique_ids: string[];
}

export interface PriorityInputs {
  rule_severity: Severity;
  ai_severity: Severity | null;
  ai_severity_effective: Severity | null;
  occurrence_count: number;
  agent_status: AgentStatus;
  priority_formula_version: number;
}

export interface Triage {
  status: TriageStatus;
  /** SEC-31/33: ALWAYS render as plain text — never markdown/HTML. */
  summary: string | null;
  /** RAW model output per AC-49 (clamp affects scoring only). */
  ai_severity: Severity | null;
  model_id: string | null;
  completed_at: string | null;
  attempts: number;
}

export interface EventRef {
  event_id: string;
  es_index: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  state: AlertState;
  rule: AlertRule;
  entity: {
    hostname: string | null;
    user: string | null;
    asset_id: string | null;
  };
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  correlation_group_id: string | null;
  priority_score: number;
  priority_inputs: PriorityInputs;
  triage: Triage;
  event_refs: EventRef[];
  close_reason: CloseReason | null;
  closed_by: string | null;
  closed_at: string | null;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  created_at: string;
}

export interface AlertDetail extends Alert {
  siblings: Alert[];
  history: AuditRecord[];
}

export type AlertSort = "priority" | "-priority" | "last_seen" | "-last_seen";

export interface AlertListParams {
  state?: AlertState[];
  severity?: Severity[];
  ai_severity?: Severity[];
  rule_id?: string;
  host?: string;
  correlation_group_id?: string;
  from?: string;
  to?: string;
  sort?: AlertSort;
  limit?: number;
  cursor?: string;
}

export interface BulkAlertResult {
  succeeded: string[];
  failed: { id: string; code: string }[];
}

// ---------- deep investigation (dataplane §9) ----------

export interface InvestigationFinding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  technique_ids: string[];
  evidence_refs: string[];
}

export interface InvestigationTimelineEntry {
  at: string;
  description: string;
  event_id?: string;
}

export interface EvidenceGraphNode {
  id: string;
  type: "host" | "user" | "process" | "ip" | "file";
  label: string;
}

export interface EvidenceGraphEdge {
  from: string;
  to: string;
  relation: string;
}

export interface RecommendedAction {
  id: string;
  title: string;
  description: string;
  requires_response_mode: ResponseMode;
}

export interface DeepInvestigationQuota {
  /** -1 = unlimited */
  limit: number;
  remaining: number;
  resets_at: string;
}

export interface Investigation {
  investigation_id: string;
  alert_id: string;
  status: "completed" | "queued" | (string & {});
  is_stub: boolean;
  engine_version: string;
  requested_at: string;
  completed_at: string | null;
  requested_by: string;
  summary: string;
  confidence: number | null;
  findings: InvestigationFinding[];
  timeline: InvestigationTimelineEntry[];
  evidence_graph: { nodes: EvidenceGraphNode[]; edges: EvidenceGraphEdge[] };
  recommended_actions: RecommendedAction[];
  quota: DeepInvestigationQuota;
}

// ---------- enrollment tokens (dataplane §10) ----------

export interface EnrollmentTokenCreated {
  id: string;
  /** shown once */
  token: string;
  expires_at: string;
  install_command: string;
}

export interface EnrollmentToken {
  id: string;
  name: string;
  created_at: string;
  expires_at: string;
  enrollment_count: number;
  revoked?: boolean;
}

// ---------- rules (dataplane §11) ----------

export interface Rule {
  id: string;
  version: string;
  title: string;
  severity: Severity;
  mitre_technique_ids: string[];
  event_classes: string[];
  /** tenant-effective */
  enabled: boolean;
  description: string;
}

// ---------- audit & onboarding (dataplane §12) ----------

export interface AuditRecord {
  id: string;
  at: string;
  tenant_id: string;
  actor: { type: "user" | "system" | "device"; id: string };
  action_type: string;
  target: { type: string; id: string };
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  reason_code?: string;
}

export interface AuditListParams {
  actor?: string;
  action_type?: string;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

export type OnboardingStepId =
  | "install_agent"
  | "create_ingest_key"
  | "first_event"
  | "view_queue";

export interface OnboardingStep {
  id: OnboardingStepId;
  state: "todo" | "done";
  completed_at?: string;
}

export interface OnboardingStatus {
  steps: OnboardingStep[];
}
