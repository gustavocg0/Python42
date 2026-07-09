/** controlplane-api endpoints (contract §3–5). */
import { http } from "./client";
import type {
  Entitlements,
  LoginResponse,
  Me,
  ProvisioningStatus,
  Role,
  SignupRequest,
  SignupResponse,
  UserInfo,
  VerifyResponse,
} from "./types";

const CP = "controlplane" as const;

// ----- signup & provisioning (§3) -----

export function signup(body: SignupRequest): Promise<SignupResponse> {
  return http.post<SignupResponse>(CP, "/v1/signup", body);
}

export function verifySignup(token: string): Promise<VerifyResponse> {
  return http.post<VerifyResponse>(CP, "/v1/signup/verify", { token });
}

export function resendVerification(email: string): Promise<void> {
  return http.post<void>(CP, "/v1/signup/resend-verification", { email });
}

export function provisioningStatus(accountId: string): Promise<ProvisioningStatus> {
  return http.get<ProvisioningStatus>(CP, "/v1/signup/provisioning-status", {
    account_id: accountId,
  });
}

// ----- auth & users (§4) -----

export function login(email: string, password: string): Promise<LoginResponse> {
  return http.post<LoginResponse>(CP, "/v1/auth/login", { email, password });
}

export function logout(): Promise<void> {
  return http.post<void>(CP, "/v1/auth/logout");
}

export function me(): Promise<Me> {
  return http.get<Me>(CP, "/v1/me");
}

export function listUsers(): Promise<UserInfo[]> {
  return http.get<UserInfo[]>(CP, "/v1/users");
}

export function createUser(email: string, role: Role): Promise<UserInfo> {
  return http.post<UserInfo>(CP, "/v1/users", { email, role });
}

export function updateUserRole(userId: string, role: Role): Promise<UserInfo> {
  return http.patch<UserInfo>(CP, `/v1/users/${encodeURIComponent(userId)}`, { role });
}

export function deleteUser(userId: string): Promise<void> {
  return http.delete(CP, `/v1/users/${encodeURIComponent(userId)}`);
}

export function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  return http.post<void>(CP, "/v1/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
}

// ----- entitlements (§5) -----

export function entitlements(): Promise<Entitlements> {
  return http.get<Entitlements>(CP, "/v1/tenant/entitlements");
}
