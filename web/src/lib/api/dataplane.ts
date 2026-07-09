/** dataplane-api endpoints (contract §6–12; console side only). */
import { http } from "./client";
import type {
  Alert,
  AlertDetail,
  AlertListParams,
  Asset,
  AssetListParams,
  AuditListParams,
  AuditRecord,
  BillableCount,
  BulkAlertResult,
  CloseReason,
  DeepInvestigationQuota,
  EnrollmentToken,
  EnrollmentTokenCreated,
  IngestKey,
  IngestKeyCreated,
  IngestUsage,
  Investigation,
  OnboardingStatus,
  Paginated,
  Rule,
} from "./types";

const DP = "dataplane" as const;

// ----- alerts (§8) -----

export function listAlerts(params: AlertListParams): Promise<Paginated<Alert>> {
  return http.get<Paginated<Alert>>(DP, "/v1/alerts", {
    state: params.state,
    severity: params.severity,
    ai_severity: params.ai_severity,
    rule_id: params.rule_id,
    host: params.host,
    correlation_group_id: params.correlation_group_id,
    from: params.from,
    to: params.to,
    sort: params.sort,
    limit: params.limit,
    cursor: params.cursor,
  });
}

export function getAlert(id: string): Promise<AlertDetail> {
  return http.get<AlertDetail>(DP, `/v1/alerts/${encodeURIComponent(id)}`);
}

export function acknowledgeAlert(id: string): Promise<Alert> {
  return http.post<Alert>(DP, `/v1/alerts/${encodeURIComponent(id)}/acknowledge`);
}

export function closeAlert(
  id: string,
  reason: CloseReason,
  comment?: string,
): Promise<Alert> {
  return http.post<Alert>(DP, `/v1/alerts/${encodeURIComponent(id)}/close`, {
    reason,
    ...(comment ? { comment } : {}),
  });
}

export function reopenAlert(id: string): Promise<Alert> {
  return http.post<Alert>(DP, `/v1/alerts/${encodeURIComponent(id)}/reopen`);
}

export function bulkAlertAction(args: {
  action: "acknowledge" | "close";
  alert_ids: string[];
  reason?: CloseReason;
}): Promise<BulkAlertResult> {
  return http.post<BulkAlertResult>(DP, "/v1/alerts/bulk", {
    action: args.action,
    alert_ids: args.alert_ids,
    ...(args.action === "close" ? { reason: args.reason } : {}),
  });
}

// ----- deep investigation (§9) -----

export function runDeepInvestigation(alertId: string): Promise<Investigation> {
  return http.post<Investigation>(
    DP,
    `/v1/alerts/${encodeURIComponent(alertId)}/deep-investigation`,
  );
}

export function listDeepInvestigations(
  alertId: string,
): Promise<Paginated<Investigation>> {
  return http.get<Paginated<Investigation>>(
    DP,
    `/v1/alerts/${encodeURIComponent(alertId)}/deep-investigations`,
  );
}

export function deepInvestigationQuota(): Promise<DeepInvestigationQuota> {
  return http.get<DeepInvestigationQuota>(DP, "/v1/tenant/quotas/deep-investigation");
}

// ----- assets (§7) -----

export function listAssets(params: AssetListParams): Promise<Paginated<Asset>> {
  return http.get<Paginated<Asset>>(DP, "/v1/assets", {
    source: params.source,
    agent_status: params.agent_status,
    billable: params.billable,
    q: params.q,
    limit: params.limit,
    cursor: params.cursor,
  });
}

export function getAsset(id: string): Promise<Asset> {
  return http.get<Asset>(DP, `/v1/assets/${encodeURIComponent(id)}`);
}

export function billableCount(): Promise<BillableCount> {
  return http.get<BillableCount>(DP, "/v1/assets/billable-count");
}

export function mergeAssets(assetIds: string[], reason: string): Promise<Asset> {
  return http.post<Asset>(DP, "/v1/assets/merge", {
    asset_ids: assetIds,
    reason,
  });
}

export function splitAsset(
  assetId: string,
  identityIds: string[],
  reason: string,
): Promise<{ assets: Asset[] }> {
  return http.post<{ assets: Asset[] }>(
    DP,
    `/v1/assets/${encodeURIComponent(assetId)}/split`,
    { identity_ids: identityIds, reason },
  );
}

export function revokeDevice(deviceId: string): Promise<void> {
  return http.post<void>(DP, `/v1/devices/${encodeURIComponent(deviceId)}/revoke`);
}

// ----- ingest keys & usage (§6) -----

export function createIngestKey(name: string): Promise<IngestKeyCreated> {
  return http.post<IngestKeyCreated>(DP, "/v1/ingest-keys", { name });
}

export function listIngestKeys(): Promise<Paginated<IngestKey>> {
  return http.get<Paginated<IngestKey>>(DP, "/v1/ingest-keys");
}

export function revokeIngestKey(id: string): Promise<void> {
  return http.delete(DP, `/v1/ingest-keys/${encodeURIComponent(id)}`);
}

export function ingestUsage(): Promise<IngestUsage> {
  return http.get<IngestUsage>(DP, "/v1/tenant/usage/ingest");
}

// ----- enrollment tokens (§10 console side) -----

export function createEnrollmentToken(
  name: string,
  expiresInHours?: number,
): Promise<EnrollmentTokenCreated> {
  return http.post<EnrollmentTokenCreated>(DP, "/v1/enrollment-tokens", {
    name,
    ...(expiresInHours ? { expires_in_hours: expiresInHours } : {}),
  });
}

export function listEnrollmentTokens(): Promise<Paginated<EnrollmentToken>> {
  return http.get<Paginated<EnrollmentToken>>(DP, "/v1/enrollment-tokens");
}

export function revokeEnrollmentToken(id: string): Promise<void> {
  return http.delete(DP, `/v1/enrollment-tokens/${encodeURIComponent(id)}`);
}

// ----- rules (§11) -----

export function listRules(cursor?: string): Promise<Paginated<Rule>> {
  return http.get<Paginated<Rule>>(DP, "/v1/rules", { cursor, limit: 200 });
}

export function setRuleEnabled(ruleId: string, enabled: boolean): Promise<Rule> {
  return http.put<Rule>(
    DP,
    `/v1/rules/${encodeURIComponent(ruleId)}/enabled`,
    { enabled },
  );
}

// ----- audit & onboarding (§12) -----

export function listAuditLogs(
  params: AuditListParams,
): Promise<Paginated<AuditRecord>> {
  return http.get<Paginated<AuditRecord>>(DP, "/v1/audit-logs", {
    actor: params.actor,
    action_type: params.action_type,
    from: params.from,
    to: params.to,
    limit: params.limit,
    cursor: params.cursor,
  });
}

export function onboardingStatus(): Promise<OnboardingStatus> {
  return http.get<OnboardingStatus>(DP, "/v1/onboarding/status");
}
