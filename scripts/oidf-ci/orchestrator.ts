import "reflect-metadata";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { generateFixtures } from "./fixtures";
import { startVerifierServer } from "./verifier-server";
import { createSuiteClient, SuiteApiError, type SuiteClient } from "./suite-client";
import { buildHappyFlowProfile } from "./profiles/happy-flow";
import { buildFullPlanProfile } from "./profiles/full-plan";
import { categorise, MalformedSuiteLogError, type Allowlist } from "./categorise";
import { renderResult } from "./reporter";

export type Profile = "happy-flow" | "full";

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
  const fixtures = await generateFixtures({ hostname });
  const verifier = await startVerifierServer({
    fixtures,
    port: 8080,
    externalBaseUrl: `http://${hostname}:8080`,
  });

  let planId = "";
  let testId = "";

  try {
    const profile = input.profile === "happy-flow" ? buildHappyFlowProfile(fixtures) : buildFullPlanProfile(fixtures);

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
    const rendered = renderResult(result, { profile: input.profile, planId, testId });

    writeFileSync(join(input.outputDir, "oidf-result.json"), rendered.json);
    writeFileSync(join(input.outputDir, "summary.md"), rendered.summary);

    const verifierExceptions = verifier.drainResponses().filter((r) => !r.ok);
    if (verifierExceptions.length) {
      console.error("[orchestrator] verifier-side exceptions captured (informational):");
      for (const e of verifierExceptions) console.error(" ", e.error?.name, e.error?.message);
    }

    return { exitCode: result.pass ? 0 : 1 };
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

function profileClientId(p: ReturnType<typeof buildHappyFlowProfile>): string {
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
