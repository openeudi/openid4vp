# OIDF Conformance Suite (local + CI)

This compose file runs the OpenID Foundation conformance suite for OpenID4VP verifier interop testing.

## Image source

The image is built from `https://gitlab.com/openid/conformance-suite` at a pinned git ref via `.github/workflows/oidf-suite-image.yml` (workflow_dispatch). The pinned ref is referenced in `docker-compose.yml` as the `image:` tag on the `server` service.

## First-time bootstrap

Before any CI workflow that pulls this image can run, the image must exist on GHCR. After the scaffolding PR merges:

```bash
# Option A — via GitHub Actions (preferred)
gh workflow run oidf-suite-image.yml -f ref=release-v5.1.42

# Option B — local build + push (requires GHCR write token)
git clone https://gitlab.com/openid/conformance-suite.git /tmp/oidf-suite
cd /tmp/oidf-suite && git checkout release-v5.1.42
mvn -B clean package -DskipTests
docker build -t ghcr.io/openeudi/oidf-conformance-suite:release-v5.1.42 .
echo $GHCR_TOKEN | docker login ghcr.io -u <github-user> --password-stdin
docker push ghcr.io/openeudi/oidf-conformance-suite:release-v5.1.42
```

## Local run

```bash
cd docker/oidf-conformance-suite
docker compose up
# wait for all three containers to be healthy (~60-120s on first cold start)
curl -fsSk https://localhost:8443/api/runner/available # via nginx TLS proxy (-k skips self-signed cert check)
```

The suite UI is at `https://localhost:8443/` (self-signed TLS). Stop with `docker compose down`.

## CI usage

`oidf-pr.yml` and `oidf-release.yml` run `docker compose -f docker/oidf-conformance-suite/docker-compose.yml up -d` then drive the suite via the REST API at `https://localhost:8443/api/...`.

## Bumping the suite version

1. Pick a new upstream git ref.
2. Update the `image:` tag in `docker-compose.yml` (on the `server` service).
3. Run `gh workflow run oidf-suite-image.yml -f ref=<new-ref>` to build + push the new image.
4. Open a PR with the compose change. The PR's own `oidf-pr.yml` run validates against the new image. If new check IDs surface, classify them (library bug → fix; spec-drift → add to `scripts/oidf-ci/allowlist.json` with justification + reference).

## HTTPS verifier (verifier-nginx) and the JKS truststore

The OIDF profile requires `request_uri` and `response_uri` in the auth request to be HTTPS (`EnsureRequestUriIsHttps`, `EnsureValidResponseUriForAuthorizationEndpointRequest`). The orchestrator's in-process Node verifier-server binds plain HTTP on `host:8080` for ease of debugging, so we front it with a TLS-terminating nginx sidecar:

| Service | Role |
|---------|------|
| `verifier-nginx` | listens on `host.docker.internal:8444` (TLS, self-signed), reverse-proxies to `host.docker.internal:8080` via the host gateway |
| `truststore-init` | one-shot service that builds a JKS containing the suite-image JDK's system CAs PLUS the verifier-nginx self-signed leaf |

The orchestrator's `externalBaseUrl` (in `scripts/oidf-ci/orchestrator.ts`) publishes `https://host.docker.internal:8444` in the auth request, and the suite's Java HTTP client trusts that URL via `-Djavax.net.ssl.trustStore=/truststore/openeudi-truststore.jks` — passed into the `server` container through `JAVA_EXTRA_ARGS`.

### Lifecycle

```
verifier-nginx (entrypoint) ─► writes /etc/ssl/certs/verifier-selfsigned.crt to verifier-nginx-certs volume
                              │
                              ▼ healthcheck: cert present
truststore-init ─► reads cert from verifier-nginx-certs (mounted ro), seeds truststore from $JAVA_HOME/lib/security/cacerts, imports cert via keytool, writes /truststore/openeudi-truststore.jks
                              │
                              ▼ depends_on: service_completed_successfully
server  ──────────► JAVA_EXTRA_ARGS picks up the truststore on boot
```

Both `verifier-nginx-certs` and `truststore` are named docker volumes; on subsequent `up` invocations the cert and truststore already exist and are reused. **If you blow away `verifier-nginx-certs` you must also blow away `truststore`** — otherwise the truststore still pins the OLD cert and outbound HTTPS from the suite to the verifier will fail with a trust-anchor error. Use `docker compose down -v` to wipe both together when iterating on the cert.

### Why not Let's Encrypt?

ACME requires a publicly-resolvable hostname plus reachability on port 80 (HTTP-01) or 443 (TLS-ALPN-01) for the challenge handler. None of that fits this harness:

- **`host.docker.internal` is not a public DNS name.** ACME clients can only issue certs for hostnames the CA can resolve and reach. Even if we exposed the verifier publicly under some real DNS, the Java HTTP client inside the `server` container would still resolve `host.docker.internal` to the docker host gateway — not the public name.
- **CI runners are ephemeral.** GitHub Actions runners come up, run `docker compose up`, and tear down within minutes. Persisting an ACME account + certificate cache across runs is fragile, and rate-limit pressure (5 certs / week / hostname) makes this a liability for a high-volume PR gate.
- **Self-signed CA + JVM truststore is the right fit.** Ephemeral self-signed leaf + an explicit allow-list of trust anchors mirrors how production verifier deployments handle their own internal-PKI signers, with no external dependency on Let's Encrypt's availability.

The library itself emits whatever `request_uri` / `response_uri` it is told to publish, and the orchestrator publishes the HTTPS-fronted URL. Nothing here is an OpenID4VP-spec quirk — it's a CI-harness packaging choice.

## Upstream layout notes

The upstream conformance-suite repository uses a **three-service** architecture that differs from the two-service layout in the original task plan:

| Service | Image | Role |
|---------|-------|------|
| `mongodb` | `mongo:8.2.7` | Database |
| `server` | `ghcr.io/openeudi/oidf-conformance-suite:release-v5.1.42` | Java Spring Boot app (port 8080 internal) |
| `nginx` | `nginx:1.27.3` | TLS terminator + reverse proxy (port 8443 → server:8080) |

**Specific deviations from the plan's example compose:**

1. **Three services, not two** — nginx is required. The GHCR image (built from upstream `Dockerfile`) is the Java server only; it binds on **port 8080**, not 8443. The upstream `nginx/nginx.conf` proxies `https://localhost:8443 → http://server:8080`.

2. **`MONGODB_HOST` not `MONGO_HOST`** — the upstream `Dockerfile` declares `ENV MONGODB_HOST mongodb` and uses `spring.data.mongodb.uri=mongodb://${MONGODB_HOST}:27017/test_suite`. The plan's example used `MONGO_HOST` which would be silently ignored.

3. **`JAVA_EXTRA_ARGS` not `JAVA_OPTS`** — the upstream `Dockerfile` declares `ENV JAVA_EXTRA_ARGS=` and expands it in the `ENTRYPOINT`. `JAVA_OPTS` has no effect.

4. **Healthcheck port is 8080** — the Java server healthcheck targets `http://localhost:8080/api/runner/available` (direct to the Spring Boot app). The plan suggested port 8443 which only nginx listens on, and nginx is a separate container.

5. **`nginx.conf`** — supplied as a bind-mounted file (`./nginx.conf`). It is an adapted copy of the upstream `nginx/nginx.conf`, trimmed to the single `server` block needed for local/CI use.

The external contract is unchanged: `localhost:8443/api/...` is accessible once all three services are healthy. The nginx self-signed cert is generated on first start via an `entrypoint` override and cached in a named Docker volume (`nginx-certs`).
