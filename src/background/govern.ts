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
import { controlCall, ControlError, type ControlResult } from "./control";

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
 * and RDAP withdrawn; egress tokens dropped).
 *
 * A selector that matches nothing of this account resolves to status
 * "not_found" (nothing was revoked), never to a failure and never to a
 * success. The plane has said that two ways: current servers answer an
 * in-row error with code NOT_FOUND (HTTP 200, status 404 inside the row),
 * older ones an ok row whose status is "not_found". Both are read here,
 * keyed on the code, so a 404 without NOT_FOUND stays an error.
 */
export async function revokeEndpoint(agent: string): Promise<RevokeResult> {
  let res: ControlResult;
  try {
    res = await controlCall("revoke", { agent }, CONTROL_PROVISION_TIMEOUT_MS);
  } catch (e) {
    if (e instanceof ControlError && (e.code ?? "").toUpperCase() === "NOT_FOUND") {
      return { agent, status: "not_found", message: e.message };
    }
    throw e;
  }
  const first = res.rows[0];
  if (!first) throw new ControlError(0, "revoke returned no status");
  const item = first["item"];
  const row =
    typeof item === "object" && item !== null && !Array.isArray(item) ? (item as Record<string, unknown>) : first;
  const raw = typeof row["status"] === "string" ? row["status"] : "unknown";
  const id = typeof row["agent"] === "string" && row["agent"] !== "" ? row["agent"] : agent;
  if (raw.toLowerCase() === "not_found") {
    const said = [row["message"], row["detail"]].find((v): v is string => typeof v === "string" && v.trim() !== "");
    return said ? { agent: id, status: "not_found", message: said } : { agent: id, status: "not_found" };
  }
  return { agent: id, status: raw };
}
