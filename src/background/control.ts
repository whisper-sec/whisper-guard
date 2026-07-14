// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The typed caller for the Whisper control plane: ONE Cypher verb,
// CALL whisper.agents({op:'...', args:{...}}), keyed only. Args are
// rendered as Cypher literals with airtight escaping (ported from the
// platform's reference serializer); the single envelope row
// {op, ok, status, result, error, retry_after} is unwrapped into either a
// column-keyed result set or a typed ControlError. Callers fail open.

import { CONTROL_TIMEOUT_MS } from "../shared/config";
import { GraphError, graphQuery, hasKey } from "./graph-client";

export class ControlError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly retryAfter: number | null = null,
  ) {
    super(message);
    this.name = "ControlError";
  }
}

// ---------------------------------------------------- literal serialization

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function escapeCypherString(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

function lit(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`non-finite number: ${value}`);
    return String(value);
  }
  if (typeof value === "string") return `'${escapeCypherString(value)}'`;
  if (Array.isArray(value)) return `[${value.map(lit).join(",")}]`;
  if (typeof value === "object") return cypherMap(value as Record<string, unknown>);
  throw new Error(`cannot serialize ${typeof value}`);
}

function cypherMap(obj: Record<string, unknown>): string {
  const entries: string[] = [];
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined) continue;
    if (!IDENTIFIER.test(key)) throw new Error(`invalid map key: ${JSON.stringify(key)}`);
    entries.push(`${key}:${lit(value)}`);
  }
  return `{${entries.join(",")}}`;
}

export function buildAgentsCall(op: string, args: Record<string, unknown> = {}): string {
  if (!IDENTIFIER.test(op)) throw new Error(`invalid op: ${JSON.stringify(op)}`);
  return `CALL whisper.agents({op:${lit(op)}, args:${cypherMap(args)}})`;
}

// ------------------------------------------------------- envelope unwrapping

export interface ControlResult {
  columns: string[];
  /** Column-keyed rows (array-form rows are re-keyed by column). */
  rows: Record<string, unknown>[];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function coerceResult(raw: unknown): ControlResult {
  if (!isObject(raw)) return { columns: [], rows: [] };
  const columns = Array.isArray(raw["columns"])
    ? (raw["columns"] as unknown[]).filter((c): c is string => typeof c === "string")
    : [];
  const rawRows = Array.isArray(raw["rows"]) ? (raw["rows"] as unknown[]) : [];
  const rows: Record<string, unknown>[] = [];
  for (const row of rawRows) {
    if (isObject(row)) {
      rows.push(row);
    } else if (Array.isArray(row)) {
      const obj: Record<string, unknown> = {};
      columns.forEach((c, i) => {
        obj[c] = row[i];
      });
      rows.push(obj);
    }
  }
  return { columns, rows };
}

/**
 * Run one control-plane op. Throws GraphError("nokey") when signed out and
 * ControlError when the op itself failed; both are meant to be caught and
 * rendered as an honest state, never an opaque failure.
 */
export async function controlCall(
  op: string,
  args: Record<string, unknown> = {},
): Promise<ControlResult> {
  if (!(await hasKey())) throw new GraphError("nokey", "sign in to use your fleet");
  const rows = await graphQuery(buildAgentsCall(op, args), {}, CONTROL_TIMEOUT_MS);
  const envelope = rows[0];
  if (!envelope) throw new ControlError(0, "the control plane returned no envelope");
  if (envelope["ok"] !== true) {
    const status = typeof envelope["status"] === "number" ? (envelope["status"] as number) : 0;
    const retry =
      typeof envelope["retry_after"] === "number" ? (envelope["retry_after"] as number) : null;
    const err = envelope["error"];
    const message =
      typeof err === "string"
        ? err
        : isObject(err) && typeof err["message"] === "string"
          ? (err["message"] as string)
          : `control op ${op} failed (status ${status})`;
    throw new ControlError(status, message, retry);
  }
  return coerceResult(envelope["result"]);
}
