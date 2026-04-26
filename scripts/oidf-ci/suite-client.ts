export interface SuiteClientOptions {
  baseUrl: string;
}

export type SuiteTestStatus = "CREATED" | "WAITING" | "RUNNING" | "FINISHED" | "INTERRUPTED" | "UNKNOWN";

export interface SuiteTestStatusResponse {
  status: SuiteTestStatus;
  exposed: Record<string, string>;
}

export type SuiteLogResult = "SUCCESS" | "FAILURE" | "WARNING" | "REVIEW" | "INFO" | "INTERRUPTED";

export interface SuiteLogEntry {
  result: SuiteLogResult;
  src: string;
  msg?: string;
  testOwner?: string;
  time?: string;
  [k: string]: unknown;
}

export class SuiteApiError extends Error {
  override readonly name = "SuiteApiError";
  constructor(
    readonly status: number,
    readonly url: string,
    readonly body: string
  ) {
    super(`OIDF suite API ${status} on ${url}: ${body.slice(0, 200)}`);
  }
}

export interface SuiteClient {
  createPlan(planName: string, variant: object, config: object): Promise<{ planId: string }>;
  startTest(planId: string, moduleName: string): Promise<{ testId: string }>;
  getTestStatus(testId: string): Promise<SuiteTestStatusResponse>;
  getTestLog(testId: string): Promise<SuiteLogEntry[]>;
}

export function createSuiteClient(opts: SuiteClientOptions): SuiteClient {
  const base = opts.baseUrl.replace(/\/$/, "");

  async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
    const res = await fetch(url, init);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new SuiteApiError(res.status, url, body);
    }
    return (await res.json()) as T;
  }

  return {
    async createPlan(planName, variant, config) {
      const params = new URLSearchParams({ planName, variant: JSON.stringify(variant) });
      const url = `${base}/api/plan?${params.toString()}`;
      const data = await jsonFetch<{ id: string }>(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(config),
      });
      return { planId: data.id };
    },

    async startTest(planId, moduleName) {
      const params = new URLSearchParams({ test: moduleName, plan: planId });
      const url = `${base}/api/runner?${params.toString()}`;
      const data = await jsonFetch<{ id: string }>(url, { method: "POST" });
      return { testId: data.id };
    },

    async getTestStatus(testId) {
      // Suite splits the data we need across two endpoints:
      //   /api/info/<id>   has `status`        (no `exposed`)
      //   /api/runner/<id> has `exposed`       (no `status`)
      // Fetch both in parallel and merge.
      const enc = encodeURIComponent(testId);
      const [info, runner] = await Promise.all([
        jsonFetch<{ status: SuiteTestStatus }>(`${base}/api/info/${enc}`),
        jsonFetch<{ exposed?: Record<string, string> }>(`${base}/api/runner/${enc}`),
      ]);
      return { status: info.status, exposed: runner.exposed ?? {} };
    },

    async getTestLog(testId) {
      return await jsonFetch<SuiteLogEntry[]>(`${base}/api/log/${encodeURIComponent(testId)}`);
    },
  };
}
