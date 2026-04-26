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
curl -fsS http://localhost:8080/api/runner/available   # direct to Java server
curl -fsSk https://localhost:8443/api/runner/available # via nginx TLS proxy
```

The suite UI is at `https://localhost:8443/` (self-signed TLS). Stop with `docker compose down`.

## CI usage

`oidf-pr.yml` and `oidf-release.yml` run `docker compose -f docker/oidf-conformance-suite/docker-compose.yml up -d` then drive the suite via the REST API at `https://localhost:8443/api/...` (or `http://localhost:8080/api/...` when skipping TLS inside CI).

## Bumping the suite version

1. Pick a new upstream git ref.
2. Update the `image:` tag in `docker-compose.yml` (on the `server` service).
3. Run `gh workflow run oidf-suite-image.yml -f ref=<new-ref>` to build + push the new image.
4. Open a PR with the compose change. The PR's own `oidf-pr.yml` run validates against the new image. If new check IDs surface, classify them (library bug → fix; spec-drift → add to `scripts/oidf-ci/allowlist.json` with justification + reference).

## Upstream layout notes

The upstream conformance-suite repository uses a **three-service** architecture that differs from the two-service layout in the original task plan:

| Service | Image | Role |
|---------|-------|------|
| `mongodb` | `mongo:8` | Database |
| `server` | `ghcr.io/openeudi/oidf-conformance-suite:release-v5.1.42` | Java Spring Boot app (port 8080 internal) |
| `nginx` | `nginx:1.27.3` | TLS terminator + reverse proxy (port 8443 → server:8080) |

**Specific deviations from the plan's example compose:**

1. **Three services, not two** — nginx is required. The GHCR image (built from upstream `Dockerfile`) is the Java server only; it binds on **port 8080**, not 8443. The upstream `nginx/nginx.conf` proxies `https://localhost:8443 → http://server:8080`.

2. **`MONGODB_HOST` not `MONGO_HOST`** — the upstream `Dockerfile` declares `ENV MONGODB_HOST mongodb` and uses `spring.data.mongodb.uri=mongodb://${MONGODB_HOST}:27017/test_suite`. The plan's example used `MONGO_HOST` which would be silently ignored.

3. **`JAVA_EXTRA_ARGS` not `JAVA_OPTS`** — the upstream `Dockerfile` declares `ENV JAVA_EXTRA_ARGS=` and expands it in the `ENTRYPOINT`. `JAVA_OPTS` has no effect.

4. **Healthcheck port is 8080** — the Java server healthcheck targets `http://localhost:8080/api/runner/available` (direct to the Spring Boot app). The plan suggested port 8443 which only nginx listens on, and nginx is a separate container.

5. **`nginx.conf`** — supplied as a bind-mounted file (`./nginx.conf`). It is an adapted copy of the upstream `nginx/nginx.conf`, trimmed to the single `server` block needed for local/CI use.

The external contract is unchanged: `localhost:8443/api/...` is accessible once all three services are healthy. The nginx self-signed cert is generated on first start via an `entrypoint` override and cached in a named Docker volume (`nginx-certs`).
