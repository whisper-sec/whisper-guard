// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The keyed governor layer: per-device DNS policy (op:policy with the
// device selector) and revocation (op:revoke). Guard is
// not only a watcher: the same verbs the console's device controls speak
// are spoken here, so the enrolled browser and every fleet device can be
// governed from the dashboard. Reads and writes both return the engine's
// own read-back, so the UI always renders what is actually in force,
// never what it hoped it wrote.

import { CONTROL_PROVISION_TIMEOUT_MS } from "../shared/config";
import {
  policyFromRows,
  policyWriteArgs,
  type DevicePolicy,
  type RevokeResult,
} from "../shared/policy";
import { controlCall, ControlError } from "./control";

/** The device's policy currently in force (no body args = read-back). */
export async function readDevicePolicy(agent: string): Promise<DevicePolicy> {
  const res = await controlCall("policy", { agent });
  return policyFromRows(res.rows);
}

/**
 * Replace the device's policy (whole-value, per the engine contract) and
 * return the engine's read-back of what is now in force.
 */
export async function writeDevicePolicy(agent: string, policy: DevicePolicy): Promise<DevicePolicy> {
  const res = await controlCall("policy", { agent, ...policyWriteArgs(policy) });
  return policyFromRows(res.rows);
}

/**
 * Revoke an endpoint: its /128 is retired everywhere (AAAA, reverse-DNS
 * and RDAP withdrawn; egress tokens dropped). Idempotent on the engine
 * side; a selector the account does not own comes back as a clean
 * not_found status row, never an opaque failure.
 */
export async function revokeEndpoint(agent: string): Promise<RevokeResult> {
  const res = await controlCall("revoke", { agent }, CONTROL_PROVISION_TIMEOUT_MS);
  const row = res.rows[0];
  if (!row) throw new ControlError(0, "revoke returned no status");
  const status = typeof row["status"] === "string" ? row["status"] : "unknown";
  const id = typeof row["agent"] === "string" && row["agent"] !== "" ? row["agent"] : agent;
  return { agent: id, status };
}
