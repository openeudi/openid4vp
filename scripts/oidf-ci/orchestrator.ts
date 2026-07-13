import "reflect-metadata";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { generateFixtures } from "./fixtures";
import { startVerifierServer } from "./verifier-server";
import { createSuiteClient, SuiteApiError, type SuiteClient } from "./suite-client";
import { resolveProfile } from "./profiles/registry";
import type { ProfileBuildOutput } from "./profiles/happy-flow";
import { categorise, MalformedSuiteLogError, type Allowlist } from "./categorise";
import { renderResult } from "./reporter";

/** Any registered profile name (see `profiles/registry.ts`); validated at resolution time. */
export type Profile = string;

export interface RunInput {
  profile: Profile;
  suiteBaseUrl: string;
  outputDir: string;
  hostname?: string;
  allowlistPath?: string;
  pollIntervalMs?: number;
  waitingTimeoutMs?: number;
  finishedTimeoutMs?: number;
}

export class OrchestrationTimeoutError extends Error {
  override readonly name = "OrchestrationTimeoutError";
  constructor(
    readonly phase: string,
    readonly elapsedMs: number
  ) {
    super(`Orchestration timeout in phase "${phase}" after ${elapsedMs}ms`);
  }
}

const DEFAULTS = {
  hostname: "host.docker.internal",
  pollIntervalMs: 1000,
  waitingTimeoutMs: 30_000,
  finishedTimeoutMsHappy: 60_000,
  finishedTimeoutMsFull: 600_000,
  allowlistPath: "scripts/oidf-ci/allowlist.json",
};

/**
 * The single blocking suite check a documented `knownDivergence` profile is
 * expected to trip: the suite demands a 4xx HTTP response, but our verifier
 * ACCEPTED (200) instead. A known-divergence run must absorb ONLY this exact
 * blocking failure — if `result.blocking` contains anything else (TLS
 * misconfig, malformed response, an unrelated regression), that is NOT the
 * documented gap and must still fail the gate.
 */
const EXPECTED_DIVERGENCE_CHECK = "EnsureHttpStatusCodeIs4xx";

export async function runProfile(input: RunInput): Promise<{ exitCode: 0 | 1 | 2 }> {
  mkdirSync(input.outputDir, { recursive: true });

  const hostname = input.hostname ?? DEFAULTS.hostname;
  const allowlistPath = input.allowlistPath ?? DEFAULTS.allowlistPath;
  const allowlist = JSON.parse(readFileSync(allowlistPath, "utf8")) as Allowlist;

  const finishedTimeoutMs =
    input.finishedTimeoutMs ??
    (input.profile === "happy-flow" ? DEFAULTS.finishedTimeoutMsHappy : DEFAULTS.finishedTimeoutMsFull);
  const waitingTimeoutMs = input.waitingTimeoutMs ?? DEFAULTS.waitingTimeoutMs;
  const pollIntervalMs = input.pollIntervalMs ?? DEFAULTS.pollIntervalMs;

  const suiteClient = createSuiteClient({ baseUrl: input.suiteBaseUrl });
  // Resolve the registry descriptor before generating fixtures: fixtures need to know
  // the credential format up-front (DCQL query / vp_formats shape, and for mso_mdoc
  // the mdoc credential itself), but `build(fx)` — which produces the full
  // ProfileBuildOutput — requires fixtures as input. The descriptor's top-level
  // `credentialFormat` breaks that cycle by carrying the format statically.
  const descriptor = resolveProfile(input.profile);
  const fixtures = await generateFixtures({ hostname, credentialFormat: descriptor.credentialFormat });
  const verifier = await startVerifierServer({
    fixtures,
    port: 8080,
    // The verifier-server itself binds plain HTTP on host:8080 for ease of
    // debugging, but the URLs it publishes (request_uri, response_uri) are the
    // HTTPS-fronted side from the verifier-nginx sidecar at :8444. The suite
    // container reaches us via host.docker.internal; verifier-nginx terminates
    // TLS and reverse-proxies back to host:8080 over the host gateway. This is
    // what clears the two harness-category allow-list entries (HTTPS
    // request_uri / response_uri) that the spec requires.
    externalBaseUrl: `https://${hostname}:8444`,
  });

  let planId = "";
  let testId = "";

  try {
    const profile = descriptor.build(fixtures);

    const created = await suiteClient.createPlan(profile.planName, profile.variant, profile.config);
    planId = created.planId;

    const started = await suiteClient.startTest(planId, profile.moduleName);
    testId = started.testId;

    const authorizationEndpoint = await pollUntilWaiting(suiteClient, testId, waitingTimeoutMs, pollIntervalMs);
    await fetch(
      `${authorizationEndpoint}?client_id=${encodeURIComponent(profileClientId(profile))}&request_uri=${encodeURIComponent(`${verifier.url}/request.jwt`)}`
    ).catch((err) => {
      console.error("[orchestrator] wallet trigger fetch threw:", err);
    });

    await pollUntilFinished(suiteClient, testId, finishedTimeoutMs, pollIntervalMs);

    const log = await suiteClient.getTestLog(testId);
    const result = categorise(log, allowlist);

    // End-to-end gate: a green run must produce verifier-side evidence consistent
    // with what the profile expects, on top of the suite's own PASSED/FAILED verdict
    // (`result.pass`, from `categorise`). Without this, an allow-listed interruption
    // (e.g. EncryptVPResponse) would let the run pass before /response was ever
    // exercised, weakening the gate.
    //
    // - `expect: "accept"` (happy-flow profiles): the verifier must have accepted at
    //   least one response and never rejected one — a REJECT here means the library
    //   wrongly refused a valid presentation.
    // - `expect: "reject"` (GHSA-h548 negative profiles): the verifier must have
    //   rejected at least one response and never accepted one — this is the
    //   rejection proof. An ACCEPT here means the library failed to catch the
    //   malicious/malformed presentation the profile is designed to probe.
    const verifierResponses = verifier.drainResponses();
    const verifierAccepts = verifierResponses.filter((r) => r.ok);
    const verifierRejects = verifierResponses.filter((r) => !r.ok);

    // A `reject`-profile flagged with `knownDivergence` (see `profiles/registry.ts`) is
    // an EXPECTED, DOCUMENTED gap between our verifier and the suite's expectation —
    // not a bug. It's handled as a distinct, non-blocking outcome below rather than via
    // the global allowlist, which would also mask a genuine regression on the real
    // negative profiles (session-transcript, kb-jwt-nonce/aud/signature, sd-hash,
    // credential-signature) since they share the same `EnsureHttpStatusCodeIs4xx` check.
    const isKnownDivergenceProfile = descriptor.expect === "reject" && descriptor.knownDivergence !== undefined;
    // Only treat this as the documented divergence if the verifier-side evidence is
    // clean (accepted, never rejected) AND the suite's blocking failures are EXACTLY
    // the one expected check (`EnsureHttpStatusCodeIs4xx`) — nothing else. Any other
    // blocking failure alongside it means an unrelated regression is present and must
    // not be swallowed as "known divergence".
    const isExpectedDivergence =
      isKnownDivergenceProfile &&
      verifierAccepts.length >= 1 &&
      verifierRejects.length === 0 &&
      result.blocking.length > 0 &&
      result.blocking.every((b) => b.src === EXPECTED_DIVERGENCE_CHECK);

    if (descriptor.expect === "accept") {
      // A `{ok:false}` here means the library rejected a presentation this profile
      // expects to succeed — that's a blocking regression, so surface it loudly.
      if (verifierRejects.length) {
        console.error("[orchestrator] verifier-side exceptions captured (BLOCKING):");
        for (const r of verifierRejects) console.error(" ", r.error?.name, r.error?.message);
      }
      if (verifierAccepts.length === 0) {
        console.error("[orchestrator] verifier never accepted a response — suite did not reach /response");
      }
    } else if (isExpectedDivergence) {
      // This IS the documented divergence reproducing — non-blocking by design.
      console.warn(
        `[orchestrator] KNOWN DIVERGENCE on profile "${input.profile}": verifier ACCEPTED where the suite ` +
          `expects a rejection. Reason: ${descriptor.knownDivergence!.reason}`
      );
    } else {
      // A `{ok:false}` here is the DESIRED outcome (the rejection proof), not an
      // error — don't dump it as a scary exception list. Only warn when the
      // verifier failed to reject, or (worse) accepted the malicious presentation.
      if (verifierAccepts.length) {
        console.error(
          "[orchestrator] verifier unexpectedly ACCEPTED a response on a reject-mode profile (BLOCKING):",
        );
        for (const r of verifierAccepts) console.error(" ", r.result);
      }
      if (verifierRejects.length === 0) {
        console.error("[orchestrator] verifier never rejected a response — suite did not reach /response");
      }
    }

    let finalPass: boolean;
    // `jsonPass` is what's reported as the `pass` field in oidf-result.json / rendered
    // in summary.md's "Pass" line. It's deliberately decoupled from `finalPass` (which
    // only drives the process exit code): a known-divergence run exits 0 but must NOT
    // render identically to a genuine clean pass, so its reported `pass` is `false`
    // while `outcome: "known-divergence"` explains why exit code is still 0.
    let jsonPass: boolean;
    let outcome: "pass" | "fail" | "known-divergence" | "divergence-closed";
    let divergenceReason: string | undefined;

    if (isExpectedDivergence) {
      // Non-blocking by design: exit 0, but label distinctly — this must never be
      // conflated with a normal "pass" in the rendered result.
      outcome = "known-divergence";
      divergenceReason = descriptor.knownDivergence!.reason;
      finalPass = true;
      jsonPass = false;
    } else {
      // Strict gate — UNCHANGED for every profile that isn't the exact expected
      // divergence above, including a `knownDivergence` profile that happens to
      // reject as normal this run (handled as "divergence-closed" below).
      const verifierEvidenceOk =
        descriptor.expect === "accept"
          ? verifierAccepts.length >= 1 && verifierRejects.length === 0
          : verifierRejects.length >= 1 && verifierAccepts.length === 0;
      finalPass = result.pass && verifierEvidenceOk;
      jsonPass = finalPass;

      if (isKnownDivergenceProfile && finalPass) {
        // The verifier rejected as the suite expects — the documented divergence did
        // NOT reproduce this run. Informational only (still a passing, non-blocking
        // run): flag it so the registry entry can be revisited/removed if consistent.
        outcome = "divergence-closed";
        divergenceReason = descriptor.knownDivergence!.reason;
        console.warn(
          `[orchestrator] Known divergence on profile "${input.profile}" did NOT reproduce this run — ` +
            "verifier rejected as expected. If this is consistent, consider removing its knownDivergence entry."
        );
      } else {
        outcome = finalPass ? "pass" : "fail";
      }
    }

    const rendered = renderResult(
      { ...result, pass: jsonPass },
      {
        profile: input.profile,
        planId,
        testId,
        expect: descriptor.expect,
        verifierAccepts: verifierAccepts.length,
        verifierRejects: verifierRejects.length,
        verifierExceptions: verifierRejects.map((r) => ({
          name: r.error?.name ?? "Rejection",
          message: r.error?.message ?? r.reason ?? "",
        })),
        outcome,
        divergence: divergenceReason ? { reason: divergenceReason } : undefined,
      },
    );

    writeFileSync(join(input.outputDir, "oidf-result.json"), rendered.json);
    writeFileSync(join(input.outputDir, "summary.md"), rendered.summary);

    return { exitCode: finalPass ? 0 : 1 };
  } catch (err) {
    const errorRecord =
      err instanceof SuiteApiError
        ? { phase: "suite-api", status: err.status, url: err.url, body: err.body, message: err.message }
        : err instanceof OrchestrationTimeoutError
          ? { phase: err.phase, elapsedMs: err.elapsedMs, message: err.message }
          : err instanceof MalformedSuiteLogError
            ? { phase: "log-parse", message: err.message }
            : {
                phase: "unknown",
                name: (err as Error).name,
                message: (err as Error).message,
                stack: (err as Error).stack,
              };

    writeFileSync(
      join(input.outputDir, "oidf-result.json"),
      JSON.stringify({ profile: input.profile, planId, testId, pass: false, error: errorRecord }, null, 2)
    );
    console.error("[orchestrator] fatal error:", errorRecord);
    return { exitCode: 2 };
  } finally {
    await verifier.close().catch(() => undefined);
  }
}

function profileClientId(p: ProfileBuildOutput): string {
  // Wallet-trigger URL needs the FULL prefixed client_id that matches the auth request.
  // Profile stores the bare hostname under config.client.client_id; suite prepends the
  // x509_san_dns: scheme at runtime. We mirror that prefix here for the trigger URL.
  const cfg = p.config as Record<string, unknown>;
  const nested = cfg.client as { client_id?: string } | undefined;
  if (nested?.client_id) return `x509_san_dns:${nested.client_id}`;
  if (typeof cfg.client_id === "string") return cfg.client_id;
  throw new Error("profile config has no resolvable client_id");
}

async function pollUntilWaiting(
  client: SuiteClient,
  testId: string,
  timeoutMs: number,
  intervalMs: number
): Promise<string> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await client.getTestStatus(testId);
    if (status.status === "WAITING" && status.exposed.authorization_endpoint) {
      return status.exposed.authorization_endpoint;
    }
    if (status.status === "INTERRUPTED" || status.status === "FINISHED") {
      throw new OrchestrationTimeoutError(`waiting (terminal status ${status.status})`, Date.now() - start);
    }
    await sleep(intervalMs);
  }
  throw new OrchestrationTimeoutError("waiting", Date.now() - start);
}

async function pollUntilFinished(
  client: SuiteClient,
  testId: string,
  timeoutMs: number,
  intervalMs: number
): Promise<void> {
  // FINISHED = ran to completion; INTERRUPTED = stopped at a callAndStopOnFailure
  // failure but the log is complete enough to categorise (allow-list applies).
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await client.getTestStatus(testId);
    if (status.status === "FINISHED" || status.status === "INTERRUPTED") return;
    await sleep(intervalMs);
  }
  throw new OrchestrationTimeoutError("finished", Date.now() - start);
}

function sleep(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}
