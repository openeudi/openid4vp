import "reflect-metadata";
import http from "node:http";
import { URL } from "node:url";
import {
  createSignedAuthorizationRequest,
  decryptAuthorizationResponse,
  verifyAuthorizationResponse,
  buildOpenID4VPHandoverSessionTranscript,
} from "../../src/index.js";
import type { Fixtures } from "./fixtures";

export interface StartVerifierServerInput {
  fixtures: Fixtures;
  port?: number;
  nonce?: string;
  state?: string;
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
  /** Human-readable rejection reason. Set whenever `ok === false`. */
  reason?: string;
  error?: { name: string; message: string; stack?: string };
  result?: unknown;
}

export interface VerifierServerHandle {
  url: string;
  nonce: string;
  state: string;
  drainResponses(): VerifierResponseRecord[];
  close(): Promise<void>;
}

export async function startVerifierServer(input: StartVerifierServerInput): Promise<VerifierServerHandle> {
  const fx = input.fixtures;
  const nonce = input.nonce ?? `nonce-${Date.now()}`;
  const state = input.state ?? `state-${Date.now()}`;
  const responses: VerifierResponseRecord[] = [];

  const server = http.createServer(async (req, res) => {
    try {
      const parsedUrl = new URL(req.url ?? "/", "http://localhost");

      if (parsedUrl.pathname === "/request.jwt" && req.method === "GET") {
        // Exact client_metadata key shape for mso_mdoc is unconfirmed against the
        // OIDF suite — Task 6 (live conformance run) verifies/adjusts this empirically.
        const vpFormatsSupported =
          fx.credentialFormat === "mso_mdoc"
            ? { mso_mdoc: { alg: ["ES256"] } }
            : { "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] } };
        const authzReq = await createSignedAuthorizationRequest(
          {
            hostname: fx.hostname,
            requestUri: `${url}/request.jwt`,
            responseUri: `${url}/response`,
            nonce,
            state,
            signer: fx.leafKeypair,
            // x5c carries the leaf only. Trust anchors (root CA) must NOT be in
            // the chain — RP supplies them out-of-band; OIDF rejects self-signed
            // roots embedded in x5c (ValidateRequestObjectSignatureAgainstX5cHeader).
            certificateChain: [fx.leafCertDer],
            encryptionKey: { publicJwk: fx.encryptionPublicJwk },
            vpFormatsSupported,
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

        // Phase 1: decrypt + basic state check. Failures here are genuine
        // harness/protocol errors (malformed POST, wrong key, replayed/foreign
        // state) rather than a credential-validation rejection, so 500 stays
        // appropriate — the OIDF negative modules never intentionally target
        // this phase.
        let decrypted: Awaited<ReturnType<typeof decryptAuthorizationResponse>>;
        try {
          if (!jwe) throw new Error("Expected form-encoded `response=<JWE>`");
          decrypted = await decryptAuthorizationResponse(jwe, fx.encryptionKeypair.privateKey);
          if (decrypted.state !== state) {
            throw new Error(`state mismatch: expected ${state}, got ${decrypted.state ?? "<absent>"}`);
          }
        } catch (err) {
          responses.push({
            receivedAtMs: Date.now(),
            ok: false,
            reason: (err as Error).message,
            error: {
              name: (err as Error).name,
              message: (err as Error).message,
              stack: (err as Error).stack,
            },
          });
          res.writeHead(500);
          res.end();
          return;
        }

        // OIDF ID3 emits vp_token entries as bare strings; OpenID4VP 1.0 §8.1
        // mandates an array of presentations. Wrap singletons.
        const reshapedVpToken = Object.fromEntries(
          Object.entries(decrypted.vp_token ?? {}).map(([k, v]) => [k, Array.isArray(v) ? v : [v]]),
        );
        const reshaped = { ...decrypted, vp_token: reshapedVpToken };

        // Phase 2: full verify pipeline (disclosures/CBOR, hash integrity,
        // KB-JWT/DeviceAuth, DCQL matching). Both success (result.valid) and
        // rejection (result.valid === false, or a thrown validation error)
        // are recorded in `responses[]`; only a genuine accept gets 200 —
        // everything else is a 4xx so the OIDF suite's negative modules
        // (which assert on the verifier's HTTP status) pass instead of
        // seeing an internal-error 500.
        // clientId/responseUri MUST byte-match what GET /request.jwt advertised
        // (`x509_san_dns:${hostname}` per createSignedAuthorizationRequest, and
        // the same `${url}/response` string) — the mdoc SessionTranscript
        // handover is built from these and a mismatch fails device auth.
        const clientId = `x509_san_dns:${fx.hostname}`;
        const responseUri = `${url}/response`;

        // This harness DECRYPTS the JWE itself (Phase 1, for the state check +
        // vp_token reshaping), so it hands verifyAuthorizationResponse a plaintext
        // envelope — which means the library's encrypted-branch auto-build of the
        // mdoc SessionTranscript never runs. For mso_mdoc we therefore build the
        // OID4VP 1.0-Final OpenID4VPHandover transcript here and pass it explicitly.
        // (The 1final flow uses OpenID4VPHandover, derived from the verifier's
        // response-encryption JWK thumbprint — no JWE `apu` needed.)
        const mdocSessionTranscript =
          fx.credentialFormat === "mso_mdoc"
            ? await buildOpenID4VPHandoverSessionTranscript({
                clientId,
                nonce,
                responseUri,
                verifierEncryptionJwk: fx.encryptionPublicJwk,
              })
            : undefined;

        try {
          const result =
            fx.credentialFormat === "mso_mdoc"
              ? await verifyAuthorizationResponse(reshaped, fx.dcqlQuery, {
                  nonce,
                  trustedCertificates: [],
                  skipTrustCheck: true,
                  clientId,
                  responseUri,
                  mdocSessionTranscript,
                })
              : // dc+sd-jwt path unchanged: the OIDF mock wallet signs SD-JWT VCs
                // using the signing_jwk from the test plan without x5c headers; we
                // supply it via `trustedIssuerJwks` so the library can use it as the
                // trust anchor instead of a certificate chain.
                await verifyAuthorizationResponse(reshaped, fx.dcqlQuery, {
                  nonce,
                  // OID4VP: the KB-JWT `aud` MUST equal the Verifier's client_id.
                  // The library only enforces it when `audience` is supplied, so a
                  // conformant verifier must pass it — without this the OIDF
                  // invalid-kb-jwt-aud negative is (wrongly) accepted.
                  audience: clientId,
                  trustedCertificates: [],
                  trustedIssuerJwks: [fx.issuerSigningJwkPublic],
                });

          // Library failures (signature, disclosure/hash, KB-JWT/DeviceAuth, DCQL
          // mismatch) are surfaced as result.valid === false rather than thrown
          // exceptions. Treat a falsy result.valid as a rejection, not an accept.
          if (!result.valid) {
            const parts: string[] = [];
            if (result.parsed && result.parsed.valid === false && result.parsed.error) {
              parts.push(`parse: ${result.parsed.error}`);
            }
            if (result.match && result.match.satisfied === false) {
              parts.push(`dcql: not satisfied (${JSON.stringify(result.match).slice(0, 200)})`);
            }
            const reason = `library rejected presentation (result.valid=false): ${parts.join(" | ") || "no detail"}`;
            responses.push({ receivedAtMs: Date.now(), ok: false, reason });
            res.writeHead(400, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: reason }));
            return;
          }

          responses.push({ receivedAtMs: Date.now(), ok: true, result });
          res.writeHead(200, { "content-type": "application/json" });
          res.end("{}");
        } catch (err) {
          // verifyAuthorizationResponse threw (malformed/invalid credential) —
          // this is a rejection, not a harness failure, so respond 4xx.
          const reason = (err as Error).message;
          responses.push({
            receivedAtMs: Date.now(),
            ok: false,
            reason,
            error: {
              name: (err as Error).name,
              message: reason,
              stack: (err as Error).stack,
            },
          });
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: reason }));
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
    state,
    drainResponses() {
      return responses.splice(0, responses.length);
    },
    async close() {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}
