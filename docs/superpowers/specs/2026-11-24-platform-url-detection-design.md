# openverdict — Part 1 design: platform + URL detection

Date: 2026-11-24 · Status: approved

## Intent

**openverdict** (Apache-2.0) is a self-hosted, open-source **threat verdict engine**. Client applications (for example an
integration inside a SaaS/CRM platform) send things to check; the engine answers with a verdict
and the evidence behind it; the client enforces its own policy. The long-term scope is phishing
and malicious URLs, malware files, and identity attacks. Part 1 builds the platform every detector
plugs into, with URL detection as the first detector family.

Success for Part 1: `docker compose up` brings up the whole stack; a client posts a list of URLs and
gets an explained verdict per URL in well under a second; big lists run as jobs; analysts can
correct verdicts; a Grafana dashboard shows latency, availability, feed freshness and a
detection-quality signal.

## Goals (Part 1)

1. **Synchronous URL check**: up to 100 URLs per request → one result per URL, in input order.
2. **Async jobs**: up to 10,000 URLs → `202` + job ID → poll for progress and paginated results.
3. **Pluggable URL detectors**: URLhaus feed, Phishing.Database feed, top-sites allowlist,
   heuristics, Google Safe Browsing (optional, off by default).
4. **Analyst overrides** for a URL or a domain, with an audit log; overrides beat detectors.
5. **Metrics + Grafana dashboard** provisioned from the repo.
6. **Runs locally** via `docker compose`; container is ready for Kubernetes later.
7. **Tests** (unit + integration) and **GitHub Actions CI** (lint, type-check, test).
8. **README** with quickstart, API examples, architecture diagram, and an **"On AWS"** section
   mapping each component to AWS services with trade-offs (documentation only).
9. **Demo profile**: `docker compose --profile demo up` gives repeatable, offline verdicts from
   synthetic feeds (see below).

## Non-goals (Part 1)

- File/malware and identity detection (Parts 2 and 3).
- Multi-tenancy: one organization per install.
- Visiting, fetching, rendering URLs, following redirects or resolving DNS.
- Analyst UI (API only), per-key rate limiting, job-completion webhooks, ML classifier.
- Kubernetes manifests, homelab deploy, AWS deploy.

## Anti-goals (failure even if it "works")

- The engine makes requests to customer-supplied URLs (SSRF, malware exposure).
- Customer URLs leave the system by default (only the opt-in Safe Browsing detector sends them out).
- Full URLs in logs (they can carry reset tokens and PII) — log host + SHA-256 of the URL only.
- Third-party feed data or API keys committed to the repo.
- A `safe` verdict without positive evidence.
- Tests that touch the live internet.

## Constraints

- Python + FastAPI, **MVC layout** (below).
- **Approach B** (chosen): `api` + `worker` (same image) + Valkey + Postgres + Prometheus + Grafana.
- One org per install; API keys carry a role: `client` or `analyst`.
- Self-hosters supply their own feed keys via env (abuse.ch Auth-Key; Safe Browsing key, whose
  terms are non-commercial — README must say so). Every feed's source URL is also set via env
  (defaults = the real feeds), which is what lets the demo profile point at local files.
- Kubernetes-ready: config only from env, `/healthz` (liveness) and `/readyz` (Postgres + Valkey
  reachable), non-root user, read-only root filesystem, one image for api and worker.

## Approaches considered

| | Approach | Trade-off | Outcome |
|---|---|---|---|
| A | Modular monolith on Postgres (Postgres as store, queue via `SKIP LOCKED`, feed mirror) | Fewest moving parts; queue throughput ceiling | Not chosen |
| **B** | **API + Valkey/Redis + worker; Postgres for durable state** | Fast cache and set lookups; one more stateful service | **Chosen** |
| C | Event-driven microservices on Kafka/Redpanda | Independent scaling; far too heavy for one-org install | Rejected |

Within B: **Redis Streams + consumer groups instead of arq** (arq is maintenance-only on PyPI; one
job type does not need a framework; Streams give ack + reclaim = at-least-once). **Valkey** instead
of Redis (BSD licence; Redis 8 is AGPL/SSPL/RSAL). Both are the designer's calls.

## Verdict model

- `verdict ∈ {safe, suspicious, malicious, unknown}`.
- Combine rule (no override): any `malicious` → malicious; else any `suspicious` → suspicious;
  else any `safe` → safe; else `unknown`.
- Heuristics can only produce `suspicious`. Only the allowlist and analyst overrides produce `safe`.
- Result per URL:
  ```json
  {"url": "<as submitted>", "normalized_url": "...", "verdict": "malicious",
   "reasons": [{"detector": "urlhaus", "verdict": "malicious", "detail": "listed: malware_download, 2026-11-20"}],
   "degraded": ["safe_browsing"], "checked_at": "2026-11-24T10:00:00Z", "error": null}
  ```
  `degraded` lists detectors that timed out or errored for this URL. Invalid items get
  `verdict: null` and `error: "invalid_url" | "unsupported_scheme" | "too_long"`; the batch still
  succeeds. `422` only for a malformed body or too many URLs.

## URL normalization

Accept `http`/`https` only; max 2,048 chars. Lowercase scheme and host, IDNA → punycode (keep the
Unicode form for heuristics), strip default port, trailing dot and fragment; keep path and query.
Pure function, no network.

## Pipeline (per batch)

1. Normalize all URLs.
2. **Overrides**: one Postgres query for exact-URL and domain matches (a domain override covers its
   subdomains; exact URL beats domain; the most specific domain wins). Overridden URLs skip detectors.
3. **Cache**: Valkey key `verdict:{cache_version}:{sha256(normalized_url)}`, TTL 15 min.
   `cache_version` = hash of the active feed versions + an overrides counter, so a feed refresh or an
   override change invalidates the cache without deletes.
4. **Detectors** run concurrently on cache misses, each with a timeout (default 2 s). Detector
   interface is batch-shaped:
   ```python
   class UrlDetector(Protocol):
       name: str
       async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]
   ```
   Detectors without required config (e.g. no Auth-Key) are disabled at startup with a warning log.
5. Combine, cache, return.

## URL detectors

| Detector | Source | Verdict it can give | Notes |
|---|---|---|---|
| `urlhaus` | abuse.ch URLhaus "recent" export (last 30 days; needs free Auth-Key) | malicious (exact URL) / suspicious (host only) | see matching rule below |
| `phishing_db` | Phishing.Database (MIT, GitHub) active links + active domains | malicious (exact URL) / suspicious (host only) | see matching rule below |
| `allowlist` | Tranco top-N domains (N=10,000 default) | safe | ships a built-in exclusion list of user-content hosts (docs/drive/sites.google.com, `*.github.io`, `*.pages.dev`, `*.workers.dev`, `*.blob.core.windows.net`, `*.s3.amazonaws.com`, `*.firebaseapp.com`, …) |
| `heuristics` | URL text only | suspicious | weighted signals ≥ threshold: IP-literal host, punycode/mixed-script host, brand lookalike (edit distance ≤ 2 to a configurable brand list), `@` in authority, subdomain depth > 4, URL > 200 chars, configurable risky TLDs. Each fired signal becomes a reason |
| `safe_browsing` | Google Safe Browsing Lookup API | malicious | **off by default**; sends URLs to Google; non-commercial terms |

**Feed matching rule (designer's call):** an exact normalized-URL match gives `malicious`. A
host-only match (the host appears in the feed but this URL does not) gives `suspicious`, never
`malicious`, because feeds often list single URLs on shared or compromised hosts. Host-only matches
on allowlisted or user-content hosts are ignored entirely (github.com, drive.google.com, Discord
CDN, … would otherwise flood false positives).

## Feed sync (worker)

Per feed on a schedule (configurable interval): download → parse → normalize → write a new
versioned Valkey set (`feed:{name}:{version}:urls`, `:hosts`) → atomically switch
`feed:{name}:active` → delete the old version. Failure keeps the old version and increments an
error counter. A Valkey lock (`SET NX EX`) ensures only one worker replica syncs a feed. On first
start, the api reports ready even if feeds are empty (detectors just find nothing); the
`feed_age_seconds` metric shows the gap.

## Demo profile

`docker compose --profile demo up` adds a tiny static file server (`demo-feeds`) serving synthetic
feed files from `deploy/compose/demo-feeds/`, in the same formats as the real feeds, and an env
overlay pointing every feed URL at it (no abuse.ch key needed). Synthetic entries use only reserved
names (RFC 2606/6761: `*.test`, `*.example`, `example.com`), e.g. a listed malware URL, a listed
phishing URL, a host-only match, a lookalike of a brand on the brand list, and an allowlisted
domain — so each verdict type and each reason appears on demand, offline, identically every run.
No real feed data is committed. A demo request file (e.g. `demo/requests.http` or a script) with
the showcase calls is committed alongside.

## Jobs (Postgres is the source of truth; Valkey only dispatches)

- `POST /v1/jobs`: insert `jobs` row (`queued`) + `job_items` (idx, url) in one transaction, then
  `XADD jobs {job_id}`.
- Worker: `XREADGROUP` → mark `running` → process unfinished items in chunks of 100 through the same
  pipeline → write results + progress per chunk → `done` → `XACK`.
- Crash recovery: `XAUTOCLAIM` reclaims messages idle > 5 min; processing resumes from items without
  a result (idempotent). A sweeper re-enqueues jobs stuck in `queued` > 5 min (covers a failed XADD
  or Valkey data loss).
- Job status: `queued | running | done | failed`; progress `{done, total}`; results paginated
  (`offset`, `limit` ≤ 1,000). Jobs and results deleted after 7 days.

## HTTP API

Auth: header `X-API-Key`. Keys are 32 random bytes, stored as SHA-256 (high-entropy keys do not need
a slow password hash). Keys are created/revoked with a CLI (`create-key --name --role`,
`revoke-key`); no key-management HTTP API.

| Method + path | Role | Purpose |
|---|---|---|
| `POST /v1/url-checks` | client, analyst | ≤100 URLs, synchronous |
| `POST /v1/jobs` | client, analyst | ≤10,000 URLs → 202 `{job_id}` |
| `GET /v1/jobs/{id}` | owner key or analyst | status, progress, paginated results |
| `POST /v1/overrides` | analyst | `{target_type: url\|domain, target, verdict: safe\|malicious, note}` |
| `GET /v1/overrides` | analyst | list active overrides |
| `DELETE /v1/overrides/{id}` | analyst | deactivate |
| `GET /v1/audit-log` | analyst | override changes: who, what, before/after, when |
| `GET /healthz`, `/readyz`, `/metrics` | none | probes and Prometheus |

On override creation the engine also computes the verdict it *would* have given without the
override and stores it as `engine_verdict`. For a URL override that is the normal pipeline result;
for a domain override it is the pipeline result for `https://<domain>/` (host-level signals:
allowlist, host-only feed matches, heuristics). Classification (designer's call):

- engine `malicious`/`suspicious`, analyst `safe` → **false positive**
- engine `safe`, analyst `malicious` → **false negative**
- engine `unknown`, analyst anything → **coverage gap** (the engine had no evidence; not an error)
- same verdict → agreement

Counter: `override_outcomes_total{outcome="false_positive|false_negative|coverage_gap|agreement"}`.
The dashboard shows FP and FN as the quality signal and coverage gaps separately.

## Data stores

- **Postgres**: `api_keys`, `overrides`, `audit_log`, `jobs`, `job_items`. Alembic migrations.
- **Valkey**: verdict cache, feed sets + active pointers, `jobs` stream (group `workers`), sync locks,
  overrides counter.

## Observability

- Prometheus metrics from api (`/metrics`) and worker (own metrics port): request latency histogram
  per route, URL verdicts by type, cache hit ratio, detector duration/errors/timeouts, feed age +
  sync errors, job queue depth (stream pending) + job durations, override disagreements.
- JSON structured logs with request ID; URLs logged as host + SHA-256 only.
- Grafana dashboard JSON + Prometheus scrape config committed under `deploy/compose/` and
  provisioned on `docker compose up`.

## MVC layout

```
src/openverdict/
  main.py              # FastAPI app factory
  config.py            # pydantic-settings, env only
  controllers/         # FastAPI routers: url_checks, jobs, overrides, audit, health   (C)
  views/               # Pydantic request/response schemas                            (V)
  models/              # domain types (verdict, normalized url), SQLAlchemy tables,    (M)
                       # repositories
  services/            # pipeline/combine, cache, jobs, overrides (part of the Model layer)
  detectors/url/       # base protocol + urlhaus, phishing_db, allowlist, heuristics, safe_browsing
  feeds/               # downloaders + parsers + sync
  worker/              # stream consumer, scheduler (feed sync, sweeper, cleanup)
  cli.py               # create-key, revoke-key
migrations/            # Alembic
deploy/compose/        # prometheus.yml, grafana provisioning + dashboard, demo-feeds/, demo env overlay
tests/unit, tests/integration
Dockerfile, docker-compose.yml, .env.example, README.md, LICENSE
```
Detectors live under `detectors/url/` so Parts 2/3 add `detectors/file/` and `detectors/identity/`
with their own subject types — no premature generic "subject" abstraction now.

## Tooling (designer's calls)

Python 3.14, uv, ruff, mypy, pytest + pytest-asyncio, FastAPI, Pydantic v2 + pydantic-settings,
SQLAlchemy 2 (async) + asyncpg, Alembic, redis-py (asyncio) against Valkey, httpx, respx (mock feed
downloads), testcontainers (Postgres, Valkey), prometheus-client. Multi-stage Dockerfile on a slim
base.

## Testing

- Unit: normalization, each heuristic signal, combine rule, override precedence, cache-key
  versioning, feed parsers on fixture files.
- Integration (testcontainers): each endpoint via httpx ASGI client, auth/roles, job end-to-end
  through a real worker loop, worker crash reclaim, sweeper, overrides + audit + override-outcome
  classification, feed sync swap, demo feed files parse with the real parsers.
- No live network: feed downloads mocked with fixture files.
- Process: TDD per task (failing test first).

## Left to the builder

URL parsing library, exact metric names, heuristic weights/threshold, brand and risky-TLD lists,
Grafana panel layout, sync intervals, chunk sizes, log library.
