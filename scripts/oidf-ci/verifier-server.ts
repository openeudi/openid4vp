import "reflect-metadata";
import http from "node:http";
import { URL } from "node:url";
import {
  createSignedAuthorizationRequest,
  decryptAuthorizationResponse,
  verifyAuthorizationResponse,
} from "../../dist/index.js";
import type { Fixtures } from "./fixtures";

export interface StartVerifierServerInput {
  fixtures: Fixtures;
  port?: number;
  nonce?: string;
  /**
   * URL the suite (or any external client) will use to reach this server.
   * When set, the server binds to 0.0.0.0 (so dockerized clients can reach
   * it via host.docker.internal) and publishes this URL in the auth-request's
   * request_uri / response_uri. When unset, the server binds to 127.0.0.1
   * and publishes http://127.0.0.1:<port>.
   */
  externalBaseUrl?: string;
}

export interface VerifierResponseRecord {
  receivedAtMs: number;
  ok: boolean;
  error?: { name: string; message: string; stack?: string };
  result?: unknown;
}

export interface VerifierServerHandle {
  url: string;
  nonce: string;
  drainResponses(): VerifierResponseRecord[];
  close(): Promise<void>;
}

export async function startVerifierServer(input: StartVerifierServerInput): Promise<VerifierServerHandle> {
  const fx = input.fixtures;
  const nonce = input.nonce ?? `nonce-${Date.now()}`;
  const responses: VerifierResponseRecord[] = [];

  const server = http.createServer(async (req, res) => {
    try {
      const parsedUrl = new URL(req.url ?? "/", "http://localhost");

      if (parsedUrl.pathname === "/request.jwt" && req.method === "GET") {
        const authzReq = await createSignedAuthorizationRequest(
          {
            hostname: fx.hostname,
            requestUri: `${url}/request.jwt`,
            responseUri: `${url}/response`,
            nonce,
            signer: fx.leafKeypair,
            // x5c carries the leaf only. Trust anchors (root CA) must NOT be in
            // the chain — RP supplies them out-of-band; OIDF rejects self-signed
            // roots embedded in x5c (ValidateRequestObjectSignatureAgainstX5cHeader).
            certificateChain: [fx.leafCertDer],
            encryptionKey: { publicJwk: fx.encryptionPublicJwk },
            vpFormatsSupported: { "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] } },
          },
          fx.dcqlQuery
        );
        res.writeHead(200, { "content-type": "application/oauth-authz-req+jwt" });
        res.end(authzReq.requestObject);
        return;
      }

      if (parsedUrl.pathname === "/response" && req.method === "POST") {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const body = Buffer.concat(chunks).toString("utf8");
        const params = new URLSearchParams(body);
        const jwe = params.get("response");
        try {
          if (!jwe) throw new Error("Expected form-encoded `response=<JWE>`");
          const decrypted = await decryptAuthorizationResponse(jwe, fx.encryptionKeypair.privateKey);
          if (decrypted.state !== undefined) throw new Error("state mismatch (none expected)");
          const result = await verifyAuthorizationResponse({ response: jwe }, fx.dcqlQuery, {
            trustedCertificates: [fx.issuerCertDer],
            nonce,
            decryptionKey: fx.encryptionKeypair.privateKey,
          });
          responses.push({ receivedAtMs: Date.now(), ok: true, result });
          res.writeHead(200, { "content-type": "application/json" });
          res.end("{}");
        } catch (err) {
          responses.push({
            receivedAtMs: Date.now(),
            ok: false,
            error: {
              name: (err as Error).name,
              message: (err as Error).message,
              stack: (err as Error).stack,
            },
          });
          res.writeHead(500);
          res.end();
        }
        return;
      }

      res.writeHead(404);
      res.end();
    } catch (err) {
      console.error("Verifier server unexpected error:", err);
      try {
        res.writeHead(500);
        res.end();
      } catch {
        /* socket already closed */
      }
    }
  });

  const bindHost = input.externalBaseUrl ? "0.0.0.0" : "127.0.0.1";
  await new Promise<void>((resolve) => server.listen(input.port ?? 0, bindHost, resolve));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("Server failed to bind");
  const url = input.externalBaseUrl ?? `http://127.0.0.1:${addr.port}`;

  return {
    url,
    nonce,
    drainResponses() {
      return responses.splice(0, responses.length);
    },
    async close() {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}
