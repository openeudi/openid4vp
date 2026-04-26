import type { SuiteLogEntry, SuiteLogResult } from "./suite-client";

export interface AllowlistEntry {
  id: string;
  category: "spec-drift" | "library-known-divergence";
  justification: string;
  reference: string;
}

export interface Allowlist {
  version: 1;
  checks: AllowlistEntry[];
}

export interface CategorisedFailure {
  src: string;
  msg: string;
  raw: SuiteLogEntry;
  allowlistEntry?: AllowlistEntry;
}

export interface CategorisedResult {
  tally: { success: number; failure: number; warning: number; review: number; info: number };
  blocking: CategorisedFailure[];
  allowlisted: CategorisedFailure[];
  pass: boolean;
}

export class MalformedSuiteLogError extends Error {
  override readonly name = "MalformedSuiteLogError";
}

const KNOWN_RESULTS: Set<SuiteLogResult> = new Set(["SUCCESS", "FAILURE", "WARNING", "REVIEW", "INFO"]);

export function categorise(log: SuiteLogEntry[], allowlist: Allowlist): CategorisedResult {
  validateAllowlist(allowlist);
  const allowlistById = new Map(allowlist.checks.map((c) => [c.id, c] as const));

  const tally = { success: 0, failure: 0, warning: 0, review: 0, info: 0 };
  const blocking: CategorisedFailure[] = [];
  const allowlisted: CategorisedFailure[] = [];

  for (const entry of log) {
    if (!entry || typeof entry.result !== "string" || !KNOWN_RESULTS.has(entry.result)) {
      throw new MalformedSuiteLogError(`Suite log entry missing or invalid 'result' field: ${JSON.stringify(entry)}`);
    }

    switch (entry.result) {
      case "SUCCESS":
        tally.success++;
        break;
      case "WARNING":
        tally.warning++;
        break;
      case "REVIEW":
        tally.review++;
        break;
      case "INFO":
        tally.info++;
        break;
      case "FAILURE": {
        tally.failure++;
        const found = allowlistById.get(entry.src);
        const failure: CategorisedFailure = {
          src: entry.src,
          msg: entry.msg ?? "",
          raw: entry,
          ...(found ? { allowlistEntry: found } : {}),
        };
        if (found) allowlisted.push(failure);
        else blocking.push(failure);
        break;
      }
    }
  }

  return { tally, blocking, allowlisted, pass: blocking.length === 0 };
}

function validateAllowlist(allowlist: Allowlist): void {
  const seen = new Set<string>();
  for (const c of allowlist.checks) {
    if (seen.has(c.id)) throw new Error(`Allow-list contains duplicate id: ${c.id}`);
    seen.add(c.id);
  }
}
