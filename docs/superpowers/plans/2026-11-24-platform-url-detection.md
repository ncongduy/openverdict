# openverdict Part 1 (platform + URL detection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A self-hosted FastAPI service that returns an explained verdict per URL (sync ≤100, async jobs ≤10,000), backed by threat feeds, heuristics, analyst overrides, metrics and a Docker Compose stack with an offline demo profile.

**Architecture:** One Python package (`openverdict`, MVC: `controllers/` = FastAPI routers, `views/` = Pydantic schemas, `models/` + `services/` + `detectors/` = model layer) run as two processes from one image: `api` and `worker`. Postgres holds durable state (keys, overrides, audit, jobs). Valkey holds feed sets, the verdict cache and the job stream (Redis Streams consumer group). Prometheus + Grafana are provisioned from the repo.

**Tech Stack:** Python 3.14, uv, FastAPI, uvicorn, Pydantic v2 + pydantic-settings, SQLAlchemy 2 async + asyncpg, Alembic, redis-py asyncio (against Valkey 9), httpx, prometheus-client; pytest, pytest-asyncio, respx, testcontainers, ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-11-24-platform-url-detection-design.md`

## Global Constraints

- `requires-python = ">=3.14"`; package `openverdict` in `src/` layout; licence Apache-2.0.
- All config from env vars with prefix `OPENVERDICT_` (no `.env` loading in code).
- The engine never makes requests to submitted URLs. Outbound HTTP only to configured feed URLs and the opt-in Safe Browsing endpoint.
- Never log a full submitted URL: log `url_fingerprint()` (host + SHA-256). Never log feed download URLs (the URLhaus one contains the Auth-Key) or `str(exc)` of httpx errors: log feed name, exception type, status code.
- Verdict strings exactly: `safe`, `suspicious`, `malicious`, `unknown`. Per-item error codes exactly: `invalid_url`, `unsupported_scheme`, `too_long`.
- Limits: sync request 1–100 URLs; job 1–10,000 URLs; URL ≤ 2,048 chars; job results page `limit` default 100, max 1,000; request body ≤ 25 MiB (413 above).
- Defaults: detector timeout 2.0 s; cache TTL 900 s; job reclaim idle 300 s; sweeper threshold 300 s; job retention 7 days; allowlist top 10,000 Tranco domains.
- Metric names exactly as in "Shared names" below; Valkey key names exactly as below.
- Tests never touch the live internet (respx for HTTP). `tests/unit` needs no Docker; `tests/integration` uses testcontainers (`postgres:18-alpine`, `valkey/valkey:9-alpine`).
- Committed files contain no personal or employer context.
- Every commit message ends with the trailer line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Work only on branch `ai/platform-url-detection`.
- After each task: `uv run ruff check . && uv run ruff format --check . && uv run mypy src` clean, plus that task's tests green.

## Shared names

**Feed names** (`openverdict.feeds.store`): `URLHAUS = "urlhaus"`, `PHISHING_DB = "phishing_db"`, `ALLOWLIST = "allowlist"`, `ALL_FEEDS = (URLHAUS, PHISHING_DB, ALLOWLIST)`.

**Valkey keys:**

| Key | Type | Purpose |
|---|---|---|
| `feed:{feed}:active` | string | active version id |
| `feed:{feed}:{version}:urls` | hash | `sha256(normalized_url)[:32]` → meta string (may be `""`) |
| `feed:{feed}:{version}:hosts` | set | hosts/domains (ASCII) |
| `feed:{feed}:synced_at` | string | unix seconds of last successful sync |
| `lock:feed:{feed}` | string | sync lock, `SET NX EX 600` |
| `overrides:version` | string | `INCR` on every override change |
| `verdict:{cache_version}:{sha256}` | string | cached verdict JSON, `EX` = cache TTL |
| `openverdict:jobs` | stream | field `job_id`; consumer group `workers` |

**Metrics** (`openverdict.metrics`, default registry):

| Name | Type | Labels | Added in |
|---|---|---|---|
| `openverdict_feed_last_success_timestamp_seconds` | Gauge | feed | Task 7 |
| `openverdict_feed_entries` | Gauge | feed, kind=`urls`\|`hosts` | Task 7 |
| `openverdict_feed_sync_failures_total` | Counter | feed | Task 7 |
| `openverdict_url_verdicts_total` | Counter | verdict=`safe`\|`suspicious`\|`malicious`\|`unknown`\|`invalid` | Task 11 |
| `openverdict_cache_requests_total` | Counter | result=`hit`\|`miss`\|`error` | Task 11 |
| `openverdict_detector_duration_seconds` | Histogram | detector | Task 11 |
| `openverdict_detector_failures_total` | Counter | detector, reason=`timeout`\|`error` | Task 11 |
| `openverdict_http_request_duration_seconds` | Histogram | method, route (template), status | Task 12 |
| `openverdict_override_outcomes_total` | Counter | outcome=`false_positive`\|`false_negative`\|`coverage_gap`\|`agreement` | Task 13 |
| `openverdict_job_queue_depth` | Gauge | — | Task 15 |
| `openverdict_job_duration_seconds` | Histogram | — | Task 15 |
| `openverdict_jobs_total` | Counter | status=`done`\|`failed` | Task 15 |

Feed age is computed in PromQL as `time() - openverdict_feed_last_success_timestamp_seconds` (ruling: a timestamp gauge is correct across restarts; an age gauge would need constant updating).

**Settings** (`openverdict.config.Settings`, env prefix `OPENVERDICT_`):

| Field | Type | Default |
|---|---|---|
| `database_url` | str | `postgresql+asyncpg://openverdict:openverdict@localhost:5432/openverdict` |
| `valkey_url` | str | `redis://localhost:6379/0` |
| `urlhaus_auth_key` | SecretStr \| None | None |
| `urlhaus_url` | str | `https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv` |
| `urlhaus_interval_seconds` | int | 900 |
| `phishing_db_links_url` | str | `https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt` |
| `phishing_db_domains_url` | str | `https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt` |
| `phishing_db_interval_seconds` | int | 21600 |
| `tranco_url` | str | `https://tranco-list.eu/top-1m.csv.zip` |
| `tranco_interval_seconds` | int | 86400 |
| `allowlist_size` | int | 10000 |
| `safe_browsing_enabled` | bool | False |
| `safe_browsing_api_key` | SecretStr \| None | None |
| `detector_timeout_seconds` | float | 2.0 |
| `cache_ttl_seconds` | int | 900 |
| `job_reclaim_idle_seconds` | int | 300 |
| `job_sweep_after_seconds` | int | 300 |
| `job_retention_days` | int | 7 |
| `api_host` / `api_port` | str / int | `0.0.0.0` / 8000 |
| `worker_metrics_port` | int | 9100 |
| `log_level` | str | `INFO` |

Method `urlhaus_download_url() -> str | None`: if `{auth_key}` is in `urlhaus_url`, return it formatted with the key, or `None` when no key is set; otherwise return `urlhaus_url` unchanged (demo/self-hosted mirrors).

## Review Focus

1. **Duplicate URLs in one batch** (same URL twice, or two spellings that normalize the same) → every input position gets a result; detectors see each unique normalized URL once. Test in Task 11.
2. **Feed download returns 200 with an empty or garbage body** (HTML error page) → must not publish an empty set and wipe protection; keep the old version, count a failure. Test in Task 7.
3. **Auth-Key leaking into logs** via httpx error messages that embed the URL → sync failure logs contain neither the key nor the host `urlhaus-api.abuse.ch`. Test in Task 7.
4. **Override target spelled differently from the checked URL** (Unicode vs punycode domain, uppercase scheme/host) → still matches. Test in Task 13.
5. **Valkey unreachable during a URL check** → request still answers: cache treated as a miss, Valkey-backed detectors reported in `degraded`, verdict from the rest (no 500). Test in Task 11.

---

## File map

```
pyproject.toml, uv.lock, .python-version, .env.example, Dockerfile, docker-compose.yml, README.md
src/openverdict/
  __init__.py  config.py  metrics.py  logs.py  resources.py  main.py  cli.py
  controllers/  __init__.py deps.py health.py url_checks.py overrides.py audit.py jobs.py
  views/        __init__.py url_checks.py overrides.py audit.py jobs.py
  models/       __init__.py url.py verdict.py db.py tables.py api_keys.py overrides.py jobs.py
  services/     __init__.py cache.py pipeline.py overrides.py jobs.py
  detectors/url/ __init__.py base.py heuristics.py user_content.py feeds.py allowlist.py safe_browsing.py
  feeds/        __init__.py parsers.py store.py sync.py
  worker/       __init__.py consumer.py maintenance.py scheduler.py main.py
  migrations/   env.py script.py.mako versions/0001_initial.py
deploy/compose/ prometheus.yml demo.env demo-feeds/... grafana/provisioning/... grafana/dashboards/openverdict.json
demo/requests.sh
.github/workflows/ci.yml
tests/helpers.py  tests/unit/...  tests/integration/conftest.py  tests/integration/...  tests/fixtures/feeds/...
```

Ruling: migrations live inside the package (`openverdict:migrations`) instead of a root `migrations/` so they ship in the image.

---

### Task 1: Project scaffold, settings, URL normalization

**Files:**
- Create: `pyproject.toml`, `.python-version`, `src/openverdict/__init__.py`, `src/openverdict/config.py`, `src/openverdict/models/__init__.py`, `src/openverdict/models/url.py`
- Test: `tests/unit/test_config.py`, `tests/unit/test_url.py`

**Interfaces:**
- Produces: `Settings` (table above); `UrlError(code)`; `NormalizedUrl(url, scheme, host, host_unicode, port, has_userinfo, sha256)` frozen dataclass; `normalize_url(raw: str) -> NormalizedUrl`; `normalize_domain(raw: str) -> str`; `host_suffixes(host: str) -> list[str]`; `MAX_URL_LENGTH = 2048`.

- [ ] **Step 1: Prerequisite.** Run `uv --version`. If missing, ask Duy to run `! curl -LsSf https://astral.sh/uv/install.sh | sh` and wait.
- [ ] **Step 2: Scaffold.** In `/home/ncd/workspace/openverdict`: write `pyproject.toml` (name `openverdict`, version `0.1.0`, `requires-python = ">=3.14"`, `license = "Apache-2.0"`, `[project.scripts] openverdict = "openverdict.cli:main"`, hatchling build backend, src layout); `.python-version` = `3.14`. Then:
  `uv add fastapi "uvicorn[standard]" pydantic-settings "sqlalchemy[asyncio]" asyncpg alembic redis httpx prometheus-client`
  `uv add --dev pytest pytest-asyncio respx "testcontainers[postgres,redis]" ruff mypy`
  Tool config in `pyproject.toml`: ruff `line-length = 100`, `target-version = "py314"`, `select = ["E","F","I","B","UP","ASYNC","S"]`, `per-file-ignores = {"tests/**" = ["S101","S105","S106"]}`; mypy `strict = true`, `plugins = ["pydantic.mypy"]`, `ignore_missing_imports` for `asyncpg.*`, `testcontainers.*`; pytest `asyncio_mode = "auto"`, `asyncio_default_fixture_loop_scope = "session"`, `asyncio_default_test_loop_scope = "session"`, `testpaths = ["tests"]`.
- [ ] **Step 3: Write the failing tests**

```python
# tests/unit/test_config.py
from openverdict.config import Settings

def test_defaults():
    s = Settings()
    assert s.detector_timeout_seconds == 2.0
    assert s.cache_ttl_seconds == 900
    assert s.allowlist_size == 10_000
    assert s.safe_browsing_enabled is False

def test_env_override(monkeypatch):
    monkeypatch.setenv("OPENVERDICT_CACHE_TTL_SECONDS", "60")
    assert Settings().cache_ttl_seconds == 60

def test_urlhaus_download_url():
    assert Settings().urlhaus_download_url() is None
    assert Settings(urlhaus_auth_key="k1").urlhaus_download_url() == (
        "https://urlhaus-api.abuse.ch/v2/files/exports/k1/recent.csv")
    demo = "http://demo-feeds/urlhaus/recent.csv"
    assert Settings(urlhaus_url=demo).urlhaus_download_url() == demo
```

```python
# tests/unit/test_url.py
import hashlib
import pytest
from openverdict.models.url import UrlError, host_suffixes, normalize_domain, normalize_url

@pytest.mark.parametrize("raw, expected", [
    ("HTTP://Example.COM:80/a?b=1#frag", "http://example.com/a?b=1"),
    ("https://example.com:443/", "https://example.com/"),
    ("https://example.com:8443/x", "https://example.com:8443/x"),
    ("http://example.com", "http://example.com/"),
    ("http://example.com./p", "http://example.com/p"),
    ("  http://a.test/x  ", "http://a.test/x"),
    ("http://user:pw@a.test/", "http://user:pw@a.test/"),
    ("http://[::1]:8080/", "http://[::1]:8080/"),
])
def test_normalize(raw, expected):
    assert normalize_url(raw).url == expected

def test_idn_host():
    n = normalize_url("http://Bücher.example/")
    assert (n.host, n.host_unicode, n.url) == (
        "xn--bcher-kva.example", "bücher.example", "http://xn--bcher-kva.example/")
    assert normalize_url("http://xn--bcher-kva.example/").host_unicode == "bücher.example"

def test_userinfo_and_hash():
    n = normalize_url("http://paypal.com@Evil.test/")
    assert n.has_userinfo and n.host == "evil.test"
    assert normalize_url("HTTP://A.test").sha256 == hashlib.sha256(b"http://a.test/").hexdigest()

@pytest.mark.parametrize("raw, code", [
    ("ftp://files.test/x", "unsupported_scheme"),
    ("javascript:alert(1)", "unsupported_scheme"),
    ("example.com/path", "invalid_url"),
    ("http://", "invalid_url"),
    ("not a url", "invalid_url"),
    ("http://exa mple.test/", "invalid_url"),
    ("http://a.test:99999/", "invalid_url"),
    ("http://a.test/" + "x" * 2048, "too_long"),
])
def test_rejects(raw, code):
    with pytest.raises(UrlError) as exc:
        normalize_url(raw)
    assert exc.value.code == code

def test_normalize_domain():
    assert normalize_domain("Bücher.Example.") == "xn--bcher-kva.example"
    for bad in ("http://x.test/", "a b.test", "", "x.test/path"):
        with pytest.raises(UrlError):
            normalize_domain(bad)

def test_host_suffixes():
    assert host_suffixes("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert host_suffixes("example.com") == ["example.com"]
    assert host_suffixes("192.0.2.1") == ["192.0.2.1"]
```

- [ ] **Step 4: Run** `uv run pytest tests/unit -v` → FAIL (ImportError).
- [ ] **Step 5: Implement** `config.py` (pydantic-settings `BaseSettings`, `env_prefix="OPENVERDICT_"`, no env_file) and `models/url.py`. Normalization rules: strip whitespace; length check on stripped raw (> 2048 → `too_long`); `urllib.parse.urlsplit`; empty scheme or no host → `invalid_url`; scheme not http/https → `unsupported_scheme`; port parse errors → `invalid_url`; host lowercased, trailing dot stripped, IDNA-encoded with Python's `idna` codec, each ASCII label must match `[a-z0-9_-]{1,63}` (IP literals via `ipaddress` exempt; IPv6 re-bracketed); `host_unicode` via IDNA decode; drop default port (80/443); drop fragment; empty path → `/`; keep userinfo, path and query verbatim (ruling: no percent-encoding normalization; missing scheme is `invalid_url`, not auto-`http://`). `host_suffixes` returns host plus parents with ≥ 2 labels; IP literals return `[host]`. `normalize_domain` rejects anything containing `/`, `:` or whitespace, then applies the same host rules.
- [ ] **Step 6: Run** `uv run pytest tests/unit -v` → PASS; ruff + mypy clean.
- [ ] **Step 7: Commit** `git add -A && git commit -m "feat: project scaffold, settings and URL normalization"`

---

### Task 2: Verdict model, combine rule, override outcome

**Files:**
- Create: `src/openverdict/models/verdict.py`
- Test: `tests/unit/test_verdict.py`

**Interfaces:**
- Produces: `Verdict(StrEnum)` SAFE/SUSPICIOUS/MALICIOUS/UNKNOWN; `DetectorFinding(detector: str, verdict: Verdict, detail: str)` frozen; `UrlResult(url: str, normalized_url: str | None, verdict: Verdict | None, reasons: list[DetectorFinding], degraded: list[str], checked_at: datetime, error: str | None)`; `combine(findings: Iterable[DetectorFinding]) -> Verdict`; `OverrideOutcome(StrEnum)` FALSE_POSITIVE/FALSE_NEGATIVE/COVERAGE_GAP/AGREEMENT (values snake_case); `classify_override(engine: Verdict, analyst: Verdict) -> OverrideOutcome`.

- [ ] **Step 1: Write the failing test**

```python
from openverdict.models.verdict import DetectorFinding as F, OverrideOutcome as O, Verdict as V, classify_override, combine

def test_combine():
    assert combine([]) is V.UNKNOWN
    assert combine([F("allowlist", V.SAFE, "")]) is V.SAFE
    assert combine([F("allowlist", V.SAFE, ""), F("heuristics", V.SUSPICIOUS, "")]) is V.SUSPICIOUS
    assert combine([F("heuristics", V.SUSPICIOUS, ""), F("urlhaus", V.MALICIOUS, "")]) is V.MALICIOUS

def test_classify_override():
    assert classify_override(V.MALICIOUS, V.SAFE) is O.FALSE_POSITIVE
    assert classify_override(V.SUSPICIOUS, V.SAFE) is O.FALSE_POSITIVE
    assert classify_override(V.SAFE, V.MALICIOUS) is O.FALSE_NEGATIVE
    assert classify_override(V.UNKNOWN, V.MALICIOUS) is O.COVERAGE_GAP
    assert classify_override(V.UNKNOWN, V.SAFE) is O.COVERAGE_GAP
    assert classify_override(V.SUSPICIOUS, V.MALICIOUS) is O.AGREEMENT
    assert classify_override(V.SAFE, V.SAFE) is O.AGREEMENT
    assert O.FALSE_POSITIVE.value == "false_positive"
```

- [ ] **Step 2: Run** `uv run pytest tests/unit/test_verdict.py -v` → FAIL.
- [ ] **Step 3: Implement** `models/verdict.py` (severity order malicious > suspicious > safe > unknown).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git commit -am "feat: verdict model and combine rule"` (add the new files first).

---

### Task 3: Detector protocol, heuristics, user-content hosts

**Files:**
- Create: `src/openverdict/detectors/__init__.py`, `detectors/url/__init__.py`, `detectors/url/base.py`, `detectors/url/heuristics.py`, `detectors/url/user_content.py`
- Test: `tests/unit/test_heuristics.py`, `tests/unit/test_user_content.py`

**Interfaces:**
- Consumes: `NormalizedUrl`, `normalize_url`, `host_suffixes` (Task 1); `DetectorFinding`, `Verdict` (Task 2).
- Produces: `UrlDetector` Protocol (`name: str`; `async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]`, result aligned with input); `Signal(name: str, weight: int)`; `score_url(url, brands: Sequence[str], risky_tlds: frozenset[str]) -> list[Signal]`; `HeuristicsDetector(brands=DEFAULT_BRANDS, risky_tlds=DEFAULT_RISKY_TLDS)` with `name = "heuristics"`; `THRESHOLD = 3`; `USER_CONTENT_HOSTS: frozenset[str]`; `is_user_content(host: str) -> bool`.

Signals and weights, evaluated and reported in this order:

| Signal | Weight | Fires when |
|---|---|---|
| `ip_literal_host` | 3 | host is an IP literal or all digits |
| `mixed_script_host` | 3 | a Unicode label mixes scripts (first word of `unicodedata.name`, ignoring digits/`-`) |
| `punycode_host` | 2 | any ASCII label starts with `xn--` |
| `at_in_authority` | 3 | `has_userinfo` |
| `brand_lookalike` | 3 | a token (Unicode labels except TLD, split on `-`) has len ≥ 5 and edit distance 1–2 to a brand |
| `brand_combo` | 2 | a token equals a brand but the second-level label is not that brand |
| `deep_subdomains` | 1 | label count − 2 > 4 |
| `long_url` | 1 | `len(url) > 200` |
| `risky_tld` | 1 | last label in risky TLDs |

`DEFAULT_BRANDS` (all ≥ 6 chars to limit false positives): paypal, microsoft, office365, outlook, icloud, google, amazon, netflix, facebook, instagram, linkedin, dropbox, docusign, salesforce, onedrive, sharepoint, wellsfargo, coinbase, binance, metamask. `DEFAULT_RISKY_TLDS`: zip, mov, xyz, top, tk, ml, ga, cf, gq, click, country, kim, work, rest, fit, support, cam. A finding is produced only when total ≥ 3; detail = `", ".join(f"{name}+{weight}")` + `f" (score {total})"`.

`USER_CONTENT_HOSTS` (match host or any suffix): docs.google.com, drive.google.com, sites.google.com, forms.gle, googleusercontent.com, storage.googleapis.com, firebaseapp.com, web.app, appspot.com, github.io, githubusercontent.com, gitlab.io, pages.dev, workers.dev, r2.dev, netlify.app, vercel.app, herokuapp.com, glitch.me, replit.app, blob.core.windows.net, azurewebsites.net, web.core.windows.net, sharepoint.com, onedrive.live.com, 1drv.ms, s3.amazonaws.com, amazonaws.com, cloudfront.net, dropboxusercontent.com, blogspot.com, wordpress.com, weebly.com, weeblysite.com, wixsite.com, 000webhostapp.com, notion.site, cdn.discordapp.com, ngrok-free.app, ngrok.io, trycloudflare.com, ipfs.io.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_heuristics.py
import pytest
from openverdict.detectors.url.heuristics import DEFAULT_BRANDS, DEFAULT_RISKY_TLDS, HeuristicsDetector, score_url
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding, Verdict

def names(raw):
    return {s.name for s in score_url(normalize_url(raw), DEFAULT_BRANDS, DEFAULT_RISKY_TLDS)}

@pytest.mark.parametrize("raw, expected", [
    ("http://192.0.2.10/login", {"ip_literal_host"}),
    ("http://3232235777/", {"ip_literal_host"}),
    ("http://paypa1.test/", {"brand_lookalike"}),
    ("http://paypal-login.test/", {"brand_combo"}),
    ("http://paypal.com/", set()),
    ("http://a.b.c.d.e.evil.test/", {"deep_subdomains"}),
    ("http://a.test/" + "x" * 200, {"long_url"}),
    ("http://shop.zip/", {"risky_tld"}),
    ("https://www.example.com/", set()),
])
def test_signals(raw, expected):
    assert names(raw) == expected

def test_homoglyph_and_userinfo():
    assert {"punycode_host", "mixed_script_host", "brand_lookalike"} <= names("http://pаypal.test/")
    assert "at_in_authority" in names("http://paypal.com@evil.test/")

async def test_detector():
    d = HeuristicsDetector()
    hit, low, clean = await d.check([normalize_url(u) for u in
        ("http://192.0.2.10/", "http://shop.zip/", "http://example.com/")])
    assert hit == DetectorFinding("heuristics", Verdict.SUSPICIOUS, "ip_literal_host+3 (score 3)")
    assert low is None and clean is None
```

```python
# tests/unit/test_user_content.py
from openverdict.detectors.url.user_content import is_user_content

def test_user_content():
    assert is_user_content("evil.github.io") and is_user_content("github.io")
    assert is_user_content("docs.google.com")
    assert not is_user_content("www.google.com") and not is_user_content("github.com")
```

- [ ] **Step 2: Run** `uv run pytest tests/unit/test_heuristics.py tests/unit/test_user_content.py -v` → FAIL.
- [ ] **Step 3: Implement** the three modules (edit distance: small iterative Levenshtein in `heuristics.py`; no new dependency).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: URL detector protocol, heuristics and user-content hosts"`

---

### Task 4: Feed parsers

**Files:**
- Create: `src/openverdict/feeds/__init__.py`, `src/openverdict/feeds/parsers.py`, `tests/fixtures/feeds/urlhaus_recent.csv`, `tests/fixtures/feeds/phishing_links.txt`, `tests/fixtures/feeds/phishing_domains.txt`
- Test: `tests/unit/test_parsers.py`

**Interfaces:**
- Consumes: `normalize_url`, `normalize_domain`, `UrlError` (Task 1).
- Produces: `ParsedFeed(urls: dict[str, str], hosts: set[str], skipped: int)` dataclass (urls: normalized URL → meta); `parse_urlhaus_csv(text: str) -> ParsedFeed`; `parse_url_lines(text: str) -> ParsedFeed`; `parse_domain_lines(text: str) -> set[str]`; `parse_tranco(content: bytes, limit: int) -> list[str]`.

Format rules: URLhaus CSV — skip lines starting with `#` and a header row whose first cell is `id`; columns by position `id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter`; meta = `f"{threat}, {dateadded[:10]}"`; rows with < 6 columns or URLs failing normalization count as `skipped`; hosts = hosts of all accepted URLs. URL lines / domain lines — one per line, skip blanks and `#`. Tranco — if `content` starts with `b"PK"` read the first zip member, else treat as text; rows `rank,domain`; first `limit` valid domains via `normalize_domain`. Ruling: the new export's exact format is assumed equal to the documented legacy CSV; verify once against a real download when a key exists (PR "Deferred minors").

`urlhaus_recent.csv` fixture:

```
################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs)           #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3301001","2026-11-20 10:01:02","http://malware-drop.test/payload.exe","online","2026-11-20 10:01:02","malware_download","exe","https://urlhaus.abuse.ch/url/3301001/","anonymous"
"3301002","2026-11-19 08:00:00","http://bad-host.test/a.exe","offline","","malware_download","elf","https://urlhaus.abuse.ch/url/3301002/","anonymous"
"3301003","2026-11-18 08:00:00","ftp://ftp-only.test/x","online","","malware_download","","https://urlhaus.abuse.ch/url/3301003/","anonymous"
"broken-row"
```

`phishing_links.txt`: `http://secure-login.test/verify`, `# comment`, blank line, `ftp://x.test/y`. `phishing_domains.txt`: `phish-domain.test`, `Bücher-Phish.test`, `not a domain!`.

- [ ] **Step 1: Write the failing test**

```python
import io, zipfile
from pathlib import Path
from openverdict.feeds.parsers import parse_domain_lines, parse_tranco, parse_url_lines, parse_urlhaus_csv

FIX = Path(__file__).parents[1] / "fixtures" / "feeds"

def test_urlhaus():
    feed = parse_urlhaus_csv((FIX / "urlhaus_recent.csv").read_text())
    assert feed.urls == {
        "http://malware-drop.test/payload.exe": "malware_download, 2026-11-20",
        "http://bad-host.test/a.exe": "malware_download, 2026-11-19"}
    assert feed.hosts == {"malware-drop.test", "bad-host.test"}
    assert feed.skipped == 2

def test_urlhaus_plain_header_row():
    text = "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n" \
           '"1","2026-11-01 00:00:00","http://x.test/a","online","","malware_download","","l","r"\n'
    assert parse_urlhaus_csv(text).urls == {"http://x.test/a": "malware_download, 2026-11-01"}

def test_url_lines():
    feed = parse_url_lines((FIX / "phishing_links.txt").read_text())
    assert feed.urls == {"http://secure-login.test/verify": ""}
    assert feed.hosts == {"secure-login.test"} and feed.skipped == 1

def test_domain_lines():
    assert parse_domain_lines((FIX / "phishing_domains.txt").read_text()) == {
        "phish-domain.test", "xn--bcher-phish-thb.test"}

def test_tranco_plain_and_zip():
    csv = b"1,example.com\n2,example.org\n3,example.net\n"
    assert parse_tranco(csv, 2) == ["example.com", "example.org"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", csv)
    assert parse_tranco(buf.getvalue(), 3) == ["example.com", "example.org", "example.net"]
```


- [ ] **Step 2: Run** `uv run pytest tests/unit/test_parsers.py -v` → FAIL.
- [ ] **Step 3: Implement** `feeds/parsers.py` (stdlib `csv`, `zipfile`, `io`).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: feed parsers for URLhaus, Phishing.Database and Tranco"`

---

### Task 5: Integration test harness + FeedStore

**Files:**
- Create: `tests/integration/__init__.py`, `tests/integration/conftest.py`, `src/openverdict/feeds/store.py`
- Test: `tests/integration/test_feed_store.py`

**Interfaces:**
- Produces: fixtures `valkey_url` (session, sync; starts `RedisContainer("valkey/valkey:9-alpine")`), `valkey` (async; `redis.asyncio.from_url(valkey_url, decode_responses=True)`, `FLUSHDB` before each test), `feed_store`. `FeedStore(valkey: Redis)` with:
  - `async def publish(self, feed: str, urls: Mapping[str, str], hosts: Iterable[str]) -> str` — writes `feed:{feed}:{version}:urls|hosts` in pipelined chunks of 5,000, then `SET feed:{feed}:active {version} GET`, then `UNLINK`s the previous version's keys; returns the version (`uuid4().hex[:12]`).
  - `async def active_versions(self, feeds: Sequence[str]) -> dict[str, str | None]`
  - `async def match_urls(self, feed: str, urls: Sequence[str]) -> list[str | None]` — `HMGET` by `sha256(url)[:32]`; meta (possibly `""`) or None; all None without an active version.
  - `async def match_hosts(self, feed: str, hosts: Sequence[str]) -> list[bool]` — `SMISMEMBER`.
  - `async def mark_synced(self, feed: str, at: float) -> None`; `async def synced_at(self, feed: str) -> float | None`
  - Constants `URLHAUS`, `PHISHING_DB`, `ALLOWLIST`, `ALL_FEEDS`.

- [ ] **Step 1: Write the failing test**

```python
from openverdict.feeds.store import URLHAUS

async def test_publish_and_match(feed_store):
    await feed_store.publish(URLHAUS, {"http://a.test/x": "malware_download, 2026-11-20",
                                       "http://b.test/y": ""}, {"a.test", "b.test"})
    assert await feed_store.match_urls(URLHAUS, ["http://a.test/x", "http://b.test/y", "http://c.test/"]) == [
        "malware_download, 2026-11-20", "", None]
    assert await feed_store.match_hosts(URLHAUS, ["a.test", "c.test"]) == [True, False]

async def test_republish_replaces_and_cleans(feed_store, valkey):
    v1 = await feed_store.publish(URLHAUS, {"http://old.test/": ""}, {"old.test"})
    v2 = await feed_store.publish(URLHAUS, {"http://new.test/": ""}, {"new.test"})
    assert v1 != v2
    assert await feed_store.match_urls(URLHAUS, ["http://old.test/"]) == [None]
    assert await feed_store.active_versions([URLHAUS]) == {URLHAUS: v2}
    assert await valkey.keys(f"feed:{URLHAUS}:{v1}:*") == []

async def test_no_active_version(feed_store):
    assert await feed_store.match_urls(URLHAUS, ["http://a.test/"]) == [None]
    assert await feed_store.match_hosts(URLHAUS, ["a.test"]) == [False]
    assert await feed_store.active_versions([URLHAUS]) == {URLHAUS: None}

async def test_large_publish_and_synced_at(feed_store):
    urls = {f"http://h{i}.test/": "" for i in range(12_000)}
    await feed_store.publish(URLHAUS, urls, set())
    assert await feed_store.match_urls(URLHAUS, ["http://h11999.test/"]) == [""]
    assert await feed_store.synced_at(URLHAUS) is None
    await feed_store.mark_synced(URLHAUS, 1700000000.5)
    assert await feed_store.synced_at(URLHAUS) == 1700000000.5
```

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_feed_store.py -v` → FAIL (ImportError).
- [ ] **Step 3: Implement** `conftest.py` fixtures and `feeds/store.py`.
- [ ] **Step 4: Run** → PASS (Docker must be running).
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: versioned feed store on Valkey with integration harness"`

---

### Task 6: Feed and allowlist detectors

**Files:**
- Create: `src/openverdict/detectors/url/feeds.py`, `src/openverdict/detectors/url/allowlist.py`
- Test: `tests/integration/test_feed_detectors.py`

**Interfaces:**
- Consumes: `FeedStore`, feed constants (Task 5); `is_user_content`, `UrlDetector` (Task 3); `host_suffixes` (Task 1).
- Produces: `FeedDetector(name: str, store: FeedStore)` (name is the feed name: `"urlhaus"` or `"phishing_db"`); `AllowlistDetector(store: FeedStore)` with `name = "allowlist"`.

Rules (spec "Feed matching rule"): exact `match_urls` hit → MALICIOUS, detail `f"listed in {name}: {meta}"` or `f"listed in {name}"` if meta is `""`. Otherwise, if the URL host is neither user-content nor allowlisted (any suffix in the `allowlist` feed) and any `host_suffixes(host)` is in the feed's hosts → SUSPICIOUS, detail `f"host listed in {name}: {matched_suffix}"`. Allowlist: host not user-content and a suffix in the allowlist set → SAFE, detail `f"top-sites list: {matched_suffix}"`. Each `check` uses one batched call per store method (no per-URL round trips).

- [ ] **Step 1: Write the failing test**

```python
import pytest
from openverdict.detectors.url.allowlist import AllowlistDetector
from openverdict.detectors.url.feeds import FeedDetector
from openverdict.feeds.store import ALLOWLIST, PHISHING_DB, URLHAUS
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding as F, Verdict as V

@pytest.fixture
async def seeded(feed_store):
    await feed_store.publish(URLHAUS, {
        "http://malware-drop.test/payload.exe": "malware_download, 2026-11-20",
        "http://evil.github.io/a": "malware_download, 2026-11-20",
        "http://example.com/bad": "malware_download, 2026-11-20"},
        {"malware-drop.test", "bad-host.test", "evil.github.io", "example.com"})
    await feed_store.publish(PHISHING_DB, {"http://secure-login.test/verify": ""}, {"phish-domain.test"})
    await feed_store.publish(ALLOWLIST, {}, {"example.com", "google.com"})
    return feed_store

async def check(det, *raw):
    return await det.check([normalize_url(u) for u in raw])

async def test_feed_detector(seeded):
    d = FeedDetector(URLHAUS, seeded)
    assert await check(d, "http://malware-drop.test/payload.exe", "http://bad-host.test/other",
                       "http://x.bad-host.test/", "http://evil.github.io/b", "http://evil.github.io/a",
                       "http://example.com/other", "http://unlisted.test/") == [
        F("urlhaus", V.MALICIOUS, "listed in urlhaus: malware_download, 2026-11-20"),
        F("urlhaus", V.SUSPICIOUS, "host listed in urlhaus: bad-host.test"),
        F("urlhaus", V.SUSPICIOUS, "host listed in urlhaus: bad-host.test"),
        None,
        F("urlhaus", V.MALICIOUS, "listed in urlhaus: malware_download, 2026-11-20"),
        None,
        None]

async def test_phishing_db_empty_meta_and_domain(seeded):
    d = FeedDetector(PHISHING_DB, seeded)
    assert await check(d, "http://secure-login.test/verify", "http://login.phish-domain.test/") == [
        F("phishing_db", V.MALICIOUS, "listed in phishing_db"),
        F("phishing_db", V.SUSPICIOUS, "host listed in phishing_db: phish-domain.test")]

async def test_allowlist(seeded):
    d = AllowlistDetector(seeded)
    assert await check(d, "https://www.example.com/", "https://docs.google.com/x", "http://unlisted.test/") == [
        F("allowlist", V.SAFE, "top-sites list: example.com"), None, None]
```

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_feed_detectors.py -v` → FAIL.
- [ ] **Step 3: Implement** both detectors.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: feed and allowlist URL detectors"`

---

### Task 7: Feed sync + feed metrics

**Files:**
- Create: `src/openverdict/feeds/sync.py`, `src/openverdict/metrics.py`, `tests/helpers.py`
- Test: `tests/integration/test_feed_sync.py`

**Interfaces:**
- Consumes: `Settings` (Task 1); parsers (Task 4); `FeedStore` (Task 5).
- Produces: `metrics.py` with the three Task 7 metrics; `tests/helpers.py::sample(name: str, **labels: str) -> float` (`REGISTRY.get_sample_value(name, labels) or 0.0`); `FeedSource(name: str, interval_seconds: int, fetch: Callable[[httpx.AsyncClient], Awaitable[ParsedFeed]])`; `build_sources(settings: Settings) -> list[FeedSource]`; `FeedSyncer(store: FeedStore, valkey: Redis, http: httpx.AsyncClient, sources: Sequence[FeedSource])` with `async def sync(self, source: FeedSource) -> bool` and `async def sync_due(self, now: float) -> None`.

Rules: `build_sources` omits `urlhaus` with a warning log when `urlhaus_download_url()` is None; `phishing_db` fetch downloads links + domains and merges domains into `hosts`; `allowlist` fetch → `ParsedFeed(urls={}, hosts=set(parse_tranco(bytes, allowlist_size)), skipped=0)`; HTTP via `http.get(url, follow_redirects=True)` + `raise_for_status()`. `sync`: acquire `lock:feed:{name}` (`SET NX EX 600`) or return False without HTTP; fetch; a feed with zero URLs **and** zero hosts is a failure; on any failure keep the old version, increment `openverdict_feed_sync_failures_total{feed}`, log `"feed sync failed"` with extras `feed`, `error` (exception class name) and `status` (HTTP status or None) — never the URL or `str(exc)`; on success publish, `mark_synced(now)`, set the last-success gauge and the entries gauges (`urls`, `hosts`); always release the lock. `sync_due(now)`: sync each source whose `synced_at` is None or older than its interval. Ruling: feed *sync* is what gets disabled without an Auth-Key; the URLhaus *detector* stays on and simply finds nothing until data exists.

- [ ] **Step 1: Write the failing test**

```python
import logging
import httpx, pytest, respx
from openverdict.config import Settings
from openverdict.feeds.store import ALLOWLIST, PHISHING_DB, URLHAUS
from openverdict.feeds.sync import FeedSyncer, build_sources
from tests.helpers import sample

KEY = "sekret-key-123"
URLHAUS_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
CSV = '"1","2026-11-20 10:00:00","http://malware-drop.test/payload.exe","online","","malware_download","","l","r"\n'

@pytest.fixture
def sync_settings():
    return Settings(urlhaus_auth_key=KEY, phishing_db_links_url="http://feeds.test/links.txt",
                    phishing_db_domains_url="http://feeds.test/domains.txt",
                    tranco_url="http://feeds.test/tranco.csv", allowlist_size=2)

def by_name(settings):
    return {s.name: s for s in build_sources(settings)}

@pytest.fixture
async def syncer(feed_store, valkey, sync_settings):
    async with httpx.AsyncClient() as http:
        yield FeedSyncer(feed_store, valkey, http, build_sources(sync_settings))

@respx.mock
async def test_urlhaus_sync(syncer, feed_store, sync_settings):
    respx.get(URLHAUS_URL).respond(text=CSV)
    assert await syncer.sync(by_name(sync_settings)[URLHAUS]) is True
    assert await feed_store.match_urls(URLHAUS, ["http://malware-drop.test/payload.exe"]) == [
        "malware_download, 2026-11-20"]
    assert await feed_store.synced_at(URLHAUS) is not None
    assert sample("openverdict_feed_entries", feed=URLHAUS, kind="urls") == 1

@respx.mock
@pytest.mark.parametrize("response", [httpx.Response(500), httpx.Response(200, text="<html>oops</html>")])
async def test_failure_keeps_old_and_hides_key(syncer, feed_store, sync_settings, caplog, response):
    await feed_store.publish(URLHAUS, {"http://old.test/": ""}, {"old.test"})
    respx.get(URLHAUS_URL).mock(return_value=response)
    before = sample("openverdict_feed_sync_failures_total", feed=URLHAUS)
    with caplog.at_level(logging.DEBUG):
        assert await syncer.sync(by_name(sync_settings)[URLHAUS]) is False
    assert await feed_store.match_urls(URLHAUS, ["http://old.test/"]) == [""]
    assert sample("openverdict_feed_sync_failures_total", feed=URLHAUS) == before + 1
    assert KEY not in caplog.text and "urlhaus-api.abuse.ch" not in caplog.text

@respx.mock
async def test_lock_held_skips(syncer, valkey, sync_settings):
    route = respx.get(URLHAUS_URL).respond(text=CSV)
    await valkey.set(f"lock:feed:{URLHAUS}", "other", ex=600)
    assert await syncer.sync(by_name(sync_settings)[URLHAUS]) is False
    assert not route.called

def test_build_sources_without_key():
    assert URLHAUS not in by_name(Settings())
    assert URLHAUS in by_name(Settings(urlhaus_url="http://demo-feeds/urlhaus/recent.csv"))

@respx.mock
async def test_phishing_db_and_tranco(syncer, feed_store, sync_settings):
    respx.get("http://feeds.test/links.txt").respond(text="http://secure-login.test/verify\n")
    respx.get("http://feeds.test/domains.txt").respond(text="phish-domain.test\n")
    respx.get("http://feeds.test/tranco.csv").respond(content=b"1,example.com\n2,example.org\n3,example.net\n")
    assert await syncer.sync(by_name(sync_settings)[PHISHING_DB])
    assert await syncer.sync(by_name(sync_settings)[ALLOWLIST])
    assert await feed_store.match_hosts(PHISHING_DB, ["phish-domain.test", "secure-login.test"]) == [True, True]
    assert await feed_store.match_hosts(ALLOWLIST, ["example.org", "example.net"]) == [True, False]

@respx.mock
async def test_sync_due(syncer, feed_store):
    respx.get(URLHAUS_URL).respond(text=CSV)
    respx.get("http://feeds.test/links.txt").respond(text="http://secure-login.test/verify\n")
    respx.get("http://feeds.test/domains.txt").respond(text="")
    tranco = respx.get("http://feeds.test/tranco.csv").respond(content=b"1,example.com\n")
    await feed_store.mark_synced(ALLOWLIST, 1_000_000.0)
    await syncer.sync_due(now=1_000_010.0)
    assert await feed_store.synced_at(URLHAUS) is not None
    assert not tranco.called
```

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_feed_sync.py -v` → FAIL.
- [ ] **Step 3: Implement** `metrics.py`, `tests/helpers.py`, `feeds/sync.py`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: scheduled feed sync with lock, safe failure handling and metrics"`

---

### Task 8: Google Safe Browsing detector (opt-in)

**Files:**
- Create: `src/openverdict/detectors/url/safe_browsing.py`
- Test: `tests/unit/test_safe_browsing.py`

**Interfaces:**
- Produces: `SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"`; `SafeBrowsingDetector(http: httpx.AsyncClient, api_key: str, endpoint: str = SAFE_BROWSING_URL)`, `name = "safe_browsing"`.

Request: `POST {endpoint}?key={api_key}`, JSON `{"client": {"clientId": "openverdict", "clientVersion": "0.1.0"}, "threatInfo": {"threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": u}, ...]}}`, at most 500 entries per request. Response `matches[].threat.url` + `threatType` → MALICIOUS detail `f"safe browsing: {threatType}"`. HTTP errors raise (the pipeline marks it degraded).

- [ ] **Step 1: Write the failing test**

```python
import json
import httpx, pytest, respx
from openverdict.detectors.url.safe_browsing import SAFE_BROWSING_URL, SafeBrowsingDetector
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding, Verdict

@respx.mock
async def test_matches_and_batching():
    def reply(request):
        urls = [e["url"] for e in json.loads(request.content)["threatInfo"]["threatEntries"]]
        assert len(urls) <= 500
        hit = [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}} for u in urls if "phish" in u]
        return httpx.Response(200, json={"matches": hit} if hit else {})
    route = respx.post(SAFE_BROWSING_URL).mock(side_effect=reply)
    urls = [normalize_url(f"http://h{i}.test/") for i in range(600)] + [normalize_url("http://phish.test/")]
    async with httpx.AsyncClient() as http:
        out = await SafeBrowsingDetector(http, "k").check(urls)
    assert route.call_count == 2
    assert out[-1] == DetectorFinding("safe_browsing", Verdict.MALICIOUS, "safe browsing: SOCIAL_ENGINEERING")
    assert out[:600] == [None] * 600

@respx.mock
async def test_http_error_raises():
    respx.post(SAFE_BROWSING_URL).respond(403)
    async with httpx.AsyncClient() as http:
        with pytest.raises(httpx.HTTPStatusError):
            await SafeBrowsingDetector(http, "k").check([normalize_url("http://a.test/")])
```

- [ ] **Step 2: Run** `uv run pytest tests/unit/test_safe_browsing.py -v` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: opt-in Google Safe Browsing detector"`

---

### Task 9: Database schema, migrations, API keys, CLI

**Files:**
- Create: `src/openverdict/models/db.py`, `models/tables.py`, `models/api_keys.py`, `src/openverdict/migrations/env.py`, `migrations/script.py.mako`, `migrations/versions/0001_initial.py`, `src/openverdict/cli.py`
- Modify: `tests/integration/conftest.py` (add `pg_url`, `db`)
- Test: `tests/integration/test_api_keys.py`, `tests/integration/test_cli.py`

**Interfaces:**
- Produces: `create_engine(url: str) -> AsyncEngine`; `create_sessionmaker(engine) -> async_sessionmaker[AsyncSession]`; `run_migrations(database_url: str) -> None` (sync; Alembic `Config` with `script_location = "openverdict:migrations"`); ORM rows in `tables.py`: `ApiKeyRow`, `OverrideRow`, `AuditRow`, `JobRow`, `JobItemRow`; `Role(StrEnum)` CLIENT/ANALYST; `Principal(key_id: int, name: str, role: Role)`; `generate_key() -> str` (`"ov_" + secrets.token_urlsafe(32)`); `hash_key(key: str) -> str` (SHA-256 hex); `KeyNameTaken(Exception)`; `ApiKeyRepo(db)` with `create(name: str, role: Role) -> tuple[Principal, str]`, `authenticate(key: str) -> Principal | None`, `revoke(name: str) -> bool`; `cli.main(argv: list[str] | None = None) -> int` with subcommands `migrate`, `create-key --name --role`, `revoke-key --name` (later tasks add `api`, `worker`). Fixtures: `pg_url` (session, sync; `PostgresContainer("postgres:18-alpine", driver="asyncpg")`, then `run_migrations`), `db` (async; sessionmaker; `TRUNCATE api_keys, overrides, audit_log, jobs, job_items RESTART IDENTITY CASCADE` before each test).

Schema (`0001_initial`, hand-written, matches ORM):
- `api_keys`: id identity PK, name text unique, role text check in (client, analyst), key_hash text unique, created_at timestamptz default now(), revoked_at timestamptz null.
- `overrides`: id identity PK, target_type text check in (url, domain), target text, verdict text check in (safe, malicious), note text default '', engine_verdict text, outcome text, created_by int FK api_keys, created_at timestamptz default now(), deleted_at timestamptz null; partial unique index (target_type, target) where deleted_at is null.
- `audit_log`: id identity PK, actor_key_id int FK api_keys, action text, override_id int FK overrides, before jsonb null, after jsonb null, at timestamptz default now(); index on at.
- `jobs`: id uuid PK, status text, total int, done int default 0, attempts int default 0, created_by int FK api_keys, created_at / started_at / updated_at / finished_at timestamptz (created_at, updated_at default now()), error text null; index (status, updated_at).
- `job_items`: job_id uuid FK jobs on delete cascade, idx int, url text, result jsonb null, PK (job_id, idx).

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_api_keys.py
import pytest
from openverdict.models.api_keys import ApiKeyRepo, KeyNameTaken, Role, hash_key

async def test_create_authenticate_revoke(db):
    repo = ApiKeyRepo(db)
    principal, key = await repo.create("app", Role.CLIENT)
    assert key.startswith("ov_") and len(key) > 40 and hash_key(key) != key
    assert await repo.authenticate(key) == principal
    assert principal.role is Role.CLIENT and principal.name == "app"
    assert await repo.authenticate("ov_wrong") is None
    assert await repo.revoke("app") is True
    assert await repo.authenticate(key) is None
    assert await repo.revoke("missing") is False

async def test_duplicate_name(db):
    repo = ApiKeyRepo(db)
    await repo.create("dup", Role.ANALYST)
    with pytest.raises(KeyNameTaken):
        await repo.create("dup", Role.CLIENT)
```

```python
# tests/integration/test_cli.py  (sync tests: the CLI calls asyncio.run itself)
from openverdict.cli import main

def test_create_and_revoke_key(pg_url, monkeypatch, capsys):
    monkeypatch.setenv("OPENVERDICT_DATABASE_URL", pg_url)
    assert main(["migrate"]) == 0
    assert main(["create-key", "--name", "cli-app", "--role", "client"]) == 0
    assert capsys.readouterr().out.strip().startswith("ov_")
    assert main(["revoke-key", "--name", "cli-app"]) == 0
    assert main(["revoke-key", "--name", "cli-app-missing"]) == 1
    assert main(["create-key", "--name", "x", "--role", "admin"]) == 2
```

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_api_keys.py tests/integration/test_cli.py -v` → FAIL.
- [ ] **Step 3: Implement** db helpers, ORM, migration, `ApiKeyRepo` (lookup by `hash_key(key)` where `revoked_at is null`; map unique violation to `KeyNameTaken`), CLI (argparse; `main` catches the `SystemExit` raised by argparse and returns its code, so a bad `--role` returns 2; `create-key` prints only the key on stdout; `revoke-key` returns 1 when the name is unknown).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: Postgres schema, migrations, API keys and CLI"`

---

### Task 10: Override repository (data layer + audit)

**Files:**
- Create: `src/openverdict/models/overrides.py`
- Test: `tests/integration/test_override_repo.py`

**Interfaces:**
- Consumes: `OverrideRow`, `AuditRow` (Task 9); `Principal` (Task 9); `Verdict`, `OverrideOutcome` (Task 2); `NormalizedUrl`, `host_suffixes` (Task 1).
- Produces: `TargetType(StrEnum)` URL/DOMAIN; `OverrideMatch(id: int, verdict: Verdict, note: str)`; `OverrideRecord(id, target_type, target, verdict, note, engine_verdict, outcome, created_by: str, created_at)`; `AuditRecord(id, actor: str, action: str, override_id: int, before: dict | None, after: dict | None, at)`; `OverrideRepo(db)` with:
  - `create(actor: Principal, target_type: TargetType, target: str, verdict: Verdict, note: str, engine_verdict: Verdict, outcome: OverrideOutcome) -> OverrideRecord` — one transaction: soft-delete an active override on the same target, insert the new one, audit `action="override.create"` with `before` = replaced record dict or None, `after` = new record dict.
  - `deactivate(actor: Principal, override_id: int) -> bool` — sets `deleted_at`; audit `"override.delete"` (before = record, after None); False if missing/already deleted.
  - `list_active() -> list[OverrideRecord]` (newest first); `audit_log(limit: int, offset: int) -> list[AuditRecord]` (newest first).
  - `match(urls: Sequence[NormalizedUrl]) -> dict[str, OverrideMatch]` — one query for active rows where (url, target ∈ urls) or (domain, target ∈ all suffixes); per URL: exact beats domain; longest matching domain wins.
  Record dicts in audit JSON: `{"id","target_type","target","verdict","note"}`.

- [ ] **Step 1: Write the failing test**

```python
from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.overrides import OverrideRepo, TargetType as T
from openverdict.models.url import normalize_url
from openverdict.models.verdict import OverrideOutcome as O, Verdict as V

async def setup(db):
    analyst, _ = await ApiKeyRepo(db).create("ana", Role.ANALYST)
    return OverrideRepo(db), analyst

async def test_match_precedence(db):
    repo, a = await setup(db)
    await repo.create(a, T.DOMAIN, "evil.test", V.MALICIOUS, "", V.UNKNOWN, O.COVERAGE_GAP)
    sub = await repo.create(a, T.DOMAIN, "ok.evil.test", V.SAFE, "vetted", V.UNKNOWN, O.COVERAGE_GAP)
    exact = await repo.create(a, T.URL, "http://ok.evil.test/bad", V.MALICIOUS, "", V.UNKNOWN, O.COVERAGE_GAP)
    urls = [normalize_url(u) for u in ("http://x.evil.test/", "http://a.ok.evil.test/", "http://ok.evil.test/bad", "http://other.test/")]
    m = await repo.match(urls)
    assert m["http://x.evil.test/"].verdict is V.MALICIOUS
    assert m["http://a.ok.evil.test/"].id == sub.id and m["http://a.ok.evil.test/"].note == "vetted"
    assert m["http://ok.evil.test/bad"].id == exact.id
    assert "http://other.test/" not in m

async def test_replace_and_delete_with_audit(db):
    repo, a = await setup(db)
    first = await repo.create(a, T.DOMAIN, "evil.test", V.MALICIOUS, "", V.UNKNOWN, O.COVERAGE_GAP)
    second = await repo.create(a, T.DOMAIN, "evil.test", V.SAFE, "fp", V.UNKNOWN, O.COVERAGE_GAP)
    assert [r.id for r in await repo.list_active()] == [second.id]
    assert await repo.deactivate(a, second.id) is True
    assert await repo.deactivate(a, second.id) is False
    assert await repo.match([normalize_url("http://evil.test/")]) == {}
    log = await repo.audit_log(limit=10, offset=0)
    assert [e.action for e in log] == ["override.delete", "override.create", "override.create"]
    assert log[1].before["id"] == first.id and log[1].after["verdict"] == "safe"
    assert log[0].actor == "ana" and log[0].after is None
```

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_override_repo.py -v` → FAIL.
- [ ] **Step 3: Implement** `models/overrides.py`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: override repository with precedence matching and audit log"`

---

### Task 11: Verdict cache + URL pipeline

**Files:**
- Create: `src/openverdict/services/__init__.py`, `services/cache.py`, `services/pipeline.py`
- Modify: `src/openverdict/metrics.py` (Task 11 metrics)
- Test: `tests/integration/test_pipeline.py`

**Interfaces:**
- Consumes: `normalize_url`, `UrlError` (T1); `combine`, `UrlResult`, `DetectorFinding` (T2); `UrlDetector` (T3); `FeedStore.active_versions`, `ALL_FEEDS` (T5); `OverrideMatch` (T10).
- Produces:
  - `CachedVerdict(verdict: Verdict, reasons: list[DetectorFinding], checked_at: datetime)`; `VerdictCache(valkey: Redis, ttl_seconds: int, feeds: Sequence[str] = ALL_FEEDS)` with `version() -> str` (one `MGET` of `feed:{f}:active` + `overrides:version`, hashed to 16 hex chars), `get_many(version, urls: Sequence[NormalizedUrl]) -> list[CachedVerdict | None]`, `set_many(version, items: Sequence[tuple[NormalizedUrl, CachedVerdict]]) -> None`, `bump_overrides() -> None`.
  - `OverrideLookup` Protocol: `async def match(self, urls: Sequence[NormalizedUrl]) -> dict[str, OverrideMatch]` (implemented by `OverrideRepo`).
  - `UrlPipeline(detectors: Sequence[UrlDetector], cache: VerdictCache, overrides: OverrideLookup, timeout_seconds: float, clock: Callable[[], datetime] = utc_now)` with `check(raw_urls: Sequence[str]) -> list[UrlResult]` and `engine_verdict(url: NormalizedUrl) -> Verdict` (detectors only; no cache, no overrides).

`check` algorithm:
1. Normalize each position; `UrlError` → `UrlResult(verdict=None, error=code, normalized_url=None)`.
2. Deduplicate by normalized `url` (keep first-seen order).
3. `overrides.match(unique)`; overridden URLs get reason `DetectorFinding("override", v, f"analyst override #{id}")` + `f": {note}"` when note non-empty; they skip cache and detectors.
4. Cache: `version()` then `get_many`; any Valkey error → count `cache_requests_total{result="error"}`, treat all as misses, skip `set_many`. Count hits/misses.
5. Misses: run every detector concurrently, each under `asyncio.wait_for(timeout_seconds)`; record duration histogram; `TimeoutError` → `detector_failures_total{reason="timeout"}`, other exceptions (or misaligned result length) → `{reason="error"}`; failed detector names go into `degraded` (sorted) for every miss in the batch; log detector name + exception class only.
6. Verdict = `combine(findings)` with findings in detector order; `checked_at = clock()`; cache only misses with empty `degraded`.
7. Expand back to input positions; increment `url_verdicts_total{verdict}` per position (`invalid` for errors).

- [ ] **Step 1: Write the failing test**

```python
import asyncio
import pytest
from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.overrides import OverrideRepo, TargetType
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding as F, OverrideOutcome, Verdict as V
from openverdict.services.cache import VerdictCache
from openverdict.services.pipeline import UrlPipeline
from tests.helpers import sample

class Fake:
    def __init__(self, name, hits=None, delay=0.0, boom=False):
        self.name, self.hits, self.delay, self.boom, self.calls = name, hits or {}, delay, boom, []
    async def check(self, urls):
        self.calls.append([u.url for u in urls])
        await asyncio.sleep(self.delay)
        if self.boom:
            raise RuntimeError("boom")
        return [self.hits.get(u.url) for u in urls]

BAD = F("feed", V.MALICIOUS, "listed")
SUS = F("heur", V.SUSPICIOUS, "score 3")

@pytest.fixture
async def make(valkey, db):
    def _make(*dets, timeout=1.0, cache_valkey=None):
        return UrlPipeline(list(dets), VerdictCache(cache_valkey or valkey, 900), OverrideRepo(db), timeout)
    return _make

async def test_order_errors_combine(make):
    p = make(Fake("feed", {"http://a.test/": BAD}), Fake("heur", {"http://a.test/": SUS}))
    r = await p.check(["http://a.test/", "ftp://x.test/", "http://b.test/"])
    assert [x.verdict for x in r] == [V.MALICIOUS, None, V.UNKNOWN]
    assert r[0].reasons == [BAD, SUS] and r[1].error == "unsupported_scheme" and r[2].reasons == []

async def test_duplicates_checked_once(make):
    det = Fake("feed")
    r = await make(det).check(["http://a.test/x", "HTTP://A.test/x"])
    assert len(r) == 2 and det.calls == [["http://a.test/x"]]

async def test_timeout_and_error_degrade(make):
    before = sample("openverdict_detector_failures_total", detector="slow", reason="timeout")
    p = make(Fake("slow", delay=1.0), Fake("bad", boom=True), Fake("heur", {"http://a.test/": SUS}), timeout=0.05)
    [r] = await p.check(["http://a.test/"])
    assert r.verdict is V.SUSPICIOUS and r.degraded == ["bad", "slow"]
    assert sample("openverdict_detector_failures_total", detector="slow", reason="timeout") == before + 1

async def test_cache_hit_and_invalidation(make, valkey):
    det = Fake("feed", {"http://a.test/": BAD})
    p = make(det)
    await p.check(["http://a.test/"])
    hits = sample("openverdict_cache_requests_total", result="hit")
    [r] = await p.check(["http://a.test/"])
    assert r.verdict is V.MALICIOUS and len(det.calls) == 1
    assert sample("openverdict_cache_requests_total", result="hit") == hits + 1
    await VerdictCache(valkey, 900).bump_overrides()
    await p.check(["http://a.test/"])
    assert len(det.calls) == 2

async def test_degraded_not_cached(make):
    det = Fake("feed", boom=True)
    p = make(det)
    await p.check(["http://a.test/"]); await p.check(["http://a.test/"])
    assert len(det.calls) == 2

async def test_override_wins_and_skips_detectors(make, db):
    a, _ = await ApiKeyRepo(db).create("ana", Role.ANALYST)
    o = await OverrideRepo(db).create(a, TargetType.DOMAIN, "a.test", V.SAFE, "vetted", V.MALICIOUS,
                                      OverrideOutcome.FALSE_POSITIVE)
    det = Fake("feed", {"http://x.a.test/": BAD})
    p = make(det)
    [r] = await p.check(["http://x.a.test/"])
    assert r.verdict is V.SAFE and r.reasons == [F("override", V.SAFE, f"analyst override #{o.id}: vetted")]
    assert det.calls == []
    assert await p.engine_verdict(normalize_url("http://x.a.test/")) is V.MALICIOUS

async def test_valkey_down_still_answers(make):
    from redis.asyncio import from_url
    dead = from_url("redis://127.0.0.1:1/0", decode_responses=True, socket_connect_timeout=0.2)
    p = make(Fake("heur", {"http://a.test/": SUS}), cache_valkey=dead)
    [r] = await p.check(["http://a.test/"])
    assert r.verdict is V.SUSPICIOUS
```


- [ ] **Step 2: Run** `uv run pytest tests/integration/test_pipeline.py -v` → FAIL.
- [ ] **Step 3: Implement** `services/cache.py`, `services/pipeline.py`, Task 11 metrics.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: URL pipeline with overrides, versioned cache and detector timeouts"`

---

### Task 12: API core — app, wiring, auth, health, URL checks, logging

**Files:**
- Create: `src/openverdict/logs.py`, `src/openverdict/resources.py`, `src/openverdict/main.py`, `controllers/__init__.py`, `controllers/deps.py`, `controllers/health.py`, `controllers/url_checks.py`, `views/__init__.py`, `views/url_checks.py`
- Modify: `metrics.py` (HTTP histogram), `cli.py` (add `api`), `tests/integration/conftest.py` (add `settings`, `api`, `client_key`, `analyst_key`, `published_feeds`)
- Test: `tests/integration/test_api_url_checks.py`, `tests/integration/test_health.py`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `logs.py`: `configure_logging(level: str) -> None` (JSON lines: ts, level, logger, msg, request_id, plus `extra` fields); `request_id_var: ContextVar[str | None]`; `url_fingerprint(url: NormalizedUrl) -> dict[str, str]` → `{"host": ..., "url_sha256": ...}`.
  - `resources.py`: `Resources` dataclass (settings, engine, db, valkey, http, feed_store, cache, keys: ApiKeyRepo, overrides: OverrideRepo, pipeline: UrlPipeline) with `aclose()`; `build_detectors(settings, store, http) -> list[UrlDetector]` in order `urlhaus`, `phishing_db`, `allowlist`, `heuristics`, then `safe_browsing` only if `safe_browsing_enabled` and a key is set (warning log when enabled without key); `async def build_resources(settings: Settings) -> Resources`.
  - `main.py`: `create_app(settings: Settings | None = None) -> FastAPI` (lifespan builds/closes `Resources` on `app.state.resources`); `MAX_BODY_BYTES = 25 * 1024 * 1024` (Content-Length above → 413 `{"detail": "body_too_large"}`); request-ID middleware (`X-Request-ID` in/out, uuid4 hex if absent); HTTP metrics middleware labelled with the route template (`"unmatched"` if none).
  - `controllers/deps.py`: `get_resources(request) -> Resources`; `require(*roles: Role) -> Callable[..., Awaitable[Principal]]` reading `X-API-Key`; missing/invalid/revoked → 401 `{"detail": "invalid_api_key"}`; wrong role → 403 `{"detail": "forbidden"}`.
  - `views/url_checks.py`: `SYNC_MAX_URLS = 100`; `UrlCheckRequest(urls: list[str] = Field(min_length=1, max_length=100))`; `ReasonView(detector, verdict, detail)`; `UrlResultView(url, normalized_url, verdict, reasons, degraded, checked_at, error)`; `UrlCheckResponse(results: list[UrlResultView])`; `result_to_view(r: UrlResult) -> UrlResultView`.
  - Routes: `POST /v1/url-checks` (client, analyst) → 200; `GET /healthz` → `{"status": "ok"}`; `GET /readyz` → 200 `{"postgres": "ok", "valkey": "ok"}` or 503 with the failing one `"error"`; `GET /metrics` → Prometheus text.
  - `cli.py api`: `configure_logging`, then `uvicorn.run("openverdict.main:create_app", factory=True, host, port, log_config=None, access_log=False)`.
  - Fixtures: `settings` (Settings with test `pg_url`/`valkey_url`, feed URLs `http://feeds.test/...`, `urlhaus_url="http://feeds.test/urlhaus.csv"`); `app` (async: `app = create_app(settings)` inside `async with app.router.lifespan_context(app)`); `api` (async: `httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test")`); `resources` (returns `app.state.resources`); `client_key`, `analyst_key` (raw key strings via `ApiKeyRepo(db).create`); `published_feeds` (publishes the Task 6 `seeded` data via `FeedStore`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_health.py
from openverdict.main import create_app
import httpx

async def test_health_ready_metrics(api):
    assert (await api.get("/healthz")).json() == {"status": "ok"}
    assert (await api.get("/readyz")).json() == {"postgres": "ok", "valkey": "ok"}
    assert "openverdict_http_request_duration_seconds" in (await api.get("/metrics")).text

async def test_ready_fails_without_valkey(settings):
    app = create_app(settings.model_copy(update={"valkey_url": "redis://127.0.0.1:1/0"}))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://t") as c:
            r = await c.get("/readyz")
    assert r.status_code == 503 and r.json()["valkey"] == "error"
```

```python
# tests/integration/test_api_url_checks.py
import logging
from tests.helpers import sample

URL = "/v1/url-checks"

async def test_auth(api, client_key):
    assert (await api.post(URL, json={"urls": ["http://a.test/"]})).status_code == 401
    assert (await api.post(URL, json={"urls": ["http://a.test/"]}, headers={"X-API-Key": "ov_nope"})).status_code == 401
    assert (await api.post(URL, json={"urls": ["http://a.test/"]}, headers={"X-API-Key": client_key})).status_code == 200

async def test_verdicts(api, client_key, published_feeds):
    before = sample("openverdict_url_verdicts_total", verdict="malicious")
    r = await api.post(URL, headers={"X-API-Key": client_key}, json={"urls": [
        "http://malware-drop.test/payload.exe", "https://www.example.com/", "http://paypa1.test/login",
        "http://unlisted.test/", "ftp://files.test/x"]})
    body = r.json()["results"]
    assert [x["verdict"] for x in body] == ["malicious", "safe", "suspicious", "unknown", None]
    assert body[0]["reasons"][0] == {"detector": "urlhaus", "verdict": "malicious",
                                     "detail": "listed in urlhaus: malware_download, 2026-11-20"}
    assert body[4]["error"] == "unsupported_scheme" and body[0]["degraded"] == []
    assert sample("openverdict_url_verdicts_total", verdict="malicious") == before + 1

async def test_limits(api, client_key):
    h = {"X-API-Key": client_key}
    assert (await api.post(URL, headers=h, json={"urls": []})).status_code == 422
    assert (await api.post(URL, headers=h, json={"urls": ["http://a.test/"] * 101})).status_code == 422
    too_big = b"x" * (25 * 1024 * 1024 + 1)
    assert (await api.post(URL, headers={**h, "Content-Type": "application/json"}, content=too_big)).status_code == 413

async def test_no_url_in_logs_and_request_id(api, client_key, caplog):
    with caplog.at_level(logging.DEBUG):
        r = await api.post(URL, headers={"X-API-Key": client_key, "X-Request-ID": "req-1"},
                           json={"urls": ["http://a.test/reset?token=secret-reset-token-123"]})
    assert r.headers["X-Request-ID"] == "req-1"
    dumped = caplog.text + "".join(str(vars(rec)) for rec in caplog.records)
    assert "secret-reset-token-123" not in dumped
```


- [ ] **Step 2: Run** `uv run pytest tests/integration/test_health.py tests/integration/test_api_url_checks.py -v` → FAIL.
- [ ] **Step 3: Implement** listed files.
- [ ] **Step 4: Run** `uv run pytest -v` → all PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: FastAPI app with auth, health, URL checks, metrics and redacted logging"`

---

### Task 13: Overrides service + API + audit log + outcome metric

**Files:**
- Create: `src/openverdict/services/overrides.py`, `controllers/overrides.py`, `controllers/audit.py`, `views/overrides.py`, `views/audit.py`
- Modify: `metrics.py` (outcome counter), `resources.py` (add `override_service`), `main.py` (routers)
- Test: `tests/integration/test_api_overrides.py`

**Interfaces:**
- Consumes: `OverrideRepo` (T10), `UrlPipeline.engine_verdict`, `VerdictCache.bump_overrides` (T11), `classify_override` (T2), `normalize_url`/`normalize_domain` (T1), `require` (T12).
- Produces: `InvalidTarget(Exception)`; `OverrideService(repo: OverrideRepo, pipeline: UrlPipeline, cache: VerdictCache)` with `create(actor, target_type, target: str, verdict: Verdict, note: str) -> OverrideRecord` (normalize target — URL via `normalize_url(...).url`, domain via `normalize_domain`; `UrlError` → `InvalidTarget`; engine verdict from `engine_verdict(url)` or, for a domain, `engine_verdict(normalize_url(f"https://{domain}/"))`; outcome via `classify_override`; repo create; `bump_overrides`; increment `openverdict_override_outcomes_total{outcome}`), `delete(actor, override_id) -> bool` (bump on success), `list_active()`, `audit_log(limit, offset)`.
- Views: `OverrideCreateRequest(target_type: Literal["url","domain"], target: str = Field(max_length=2048), verdict: Literal["safe","malicious"], note: str = Field("", max_length=1000))`; `OverrideView(id, target_type, target, verdict, note, engine_verdict, outcome, created_by, created_at)`; `AuditEntryView(id, actor, action, override_id, before, after, at)`.
- Routes (analyst only): `POST /v1/overrides` → 201 `OverrideView` (`InvalidTarget` → 422 `{"detail": "invalid_target"}`); `GET /v1/overrides` → `list[OverrideView]`; `DELETE /v1/overrides/{override_id}` → 204 or 404; `GET /v1/audit-log?limit=100&offset=0` (limit 1–1000) → `list[AuditEntryView]`.

- [ ] **Step 1: Write the failing test**

```python
from tests.helpers import sample
CHECK, OV = "/v1/url-checks", "/v1/overrides"

async def check(api, key, url):
    return (await api.post(CHECK, headers={"X-API-Key": key}, json={"urls": [url]})).json()["results"][0]

async def test_false_positive_flow(api, client_key, analyst_key, published_feeds):
    a = {"X-API-Key": analyst_key}
    assert (await check(api, client_key, "http://malware-drop.test/payload.exe"))["verdict"] == "malicious"
    assert (await api.post(OV, headers={"X-API-Key": client_key}, json={
        "target_type": "url", "target": "http://malware-drop.test/payload.exe", "verdict": "safe"})).status_code == 403
    before = sample("openverdict_override_outcomes_total", outcome="false_positive")
    r = await api.post(OV, headers=a, json={"target_type": "url", "target": "HTTP://Malware-Drop.test/payload.exe",
                                            "verdict": "safe", "note": "vendor file"})
    assert r.status_code == 201
    body = r.json()
    assert (body["engine_verdict"], body["outcome"], body["created_by"]) == ("malicious", "false_positive", "analyst")
    assert sample("openverdict_override_outcomes_total", outcome="false_positive") == before + 1
    after = await check(api, client_key, "http://malware-drop.test/payload.exe")
    assert after["verdict"] == "safe" and after["reasons"][0]["detector"] == "override"
    assert (await api.delete(f"{OV}/{body['id']}", headers=a)).status_code == 204
    assert (await api.delete(f"{OV}/{body['id']}", headers=a)).status_code == 404
    assert (await check(api, client_key, "http://malware-drop.test/payload.exe"))["verdict"] == "malicious"
    log = (await api.get("/v1/audit-log", headers=a)).json()
    assert [e["action"] for e in log[:2]] == ["override.delete", "override.create"]

async def test_domain_outcomes_and_unicode(api, client_key, analyst_key, published_feeds):
    a = {"X-API-Key": analyst_key}
    gap = (await api.post(OV, headers=a, json={"target_type": "domain", "target": "Bücher.example", "verdict": "malicious"})).json()
    assert gap["outcome"] == "coverage_gap" and gap["target"] == "xn--bcher-kva.example"
    assert (await check(api, client_key, "http://shop.xn--bcher-kva.example/a"))["verdict"] == "malicious"
    fn = (await api.post(OV, headers=a, json={"target_type": "domain", "target": "example.com", "verdict": "malicious"})).json()
    assert fn["engine_verdict"] == "safe" and fn["outcome"] == "false_negative"

async def test_validation_and_list(api, analyst_key):
    a = {"X-API-Key": analyst_key}
    for bad in ({"target_type": "url", "target": "ftp://x.test/", "verdict": "safe"},
                {"target_type": "domain", "target": "http://x.test/", "verdict": "safe"}):
        r = await api.post(OV, headers=a, json=bad)
        assert r.status_code == 422 and r.json() == {"detail": "invalid_target"}
    assert (await api.post(OV, headers=a, json={"target_type": "url", "target": "http://x.test/",
                                                "verdict": "suspicious"})).status_code == 422
    await api.post(OV, headers=a, json={"target_type": "domain", "target": "x.test", "verdict": "malicious"})
    await api.post(OV, headers=a, json={"target_type": "domain", "target": "x.test", "verdict": "safe"})
    assert [o["verdict"] for o in (await api.get(OV, headers=a)).json()] == ["safe"]
```

(The `analyst_key` fixture creates its key with name `"analyst"`.)

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_api_overrides.py -v` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `uv run pytest -v` → all PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: analyst overrides API with audit log and detection-quality metric"`

---

### Task 14: Jobs repository, service and API

**Files:**
- Create: `src/openverdict/models/jobs.py`, `services/jobs.py`, `controllers/jobs.py`, `views/jobs.py`
- Modify: `resources.py` (add `job_repo`, `jobs`), `main.py` (router)
- Test: `tests/integration/test_api_jobs.py`

**Interfaces:**
- Consumes: `JobRow`, `JobItemRow` (T9); `Principal`, `Role` (T9); `require` (T12); `UrlResultView` (T12).
- Produces:
  - `JobStatus(StrEnum)` QUEUED/RUNNING/DONE/FAILED; `JobRecord(id: UUID, status, total, done, attempts, created_by: int, created_at, finished_at, error)`; `JobRepo(db)` with `create(owner_key_id: int, urls: Sequence[str]) -> JobRecord` (one transaction, items `idx` 0..n-1), `get(job_id) -> JobRecord | None`, `results(job_id, offset, limit) -> list[dict]`, `start(job_id) -> JobRecord | None` (status running, attempts += 1, started_at, updated_at), `pending_items(job_id, limit) -> list[tuple[int, str]]` (result null, idx order), `save_results(job_id, results: Sequence[tuple[int, dict]]) -> int` (update only rows with null result; then `done = count(result not null)`, `updated_at = now()`; returns done), `finish(job_id, status, error: str | None = None) -> None`, `stale(older_than: datetime) -> list[UUID]` (queued/running with `updated_at < older_than`), `delete_older_than(cutoff: datetime) -> int` (by `created_at`).
  - `JOB_STREAM = "openverdict:jobs"`, `JOB_GROUP = "workers"`; `JobService(repo: JobRepo, valkey: Redis)` with `submit(owner: Principal, urls) -> JobRecord` (create, then `enqueue`; enqueue errors logged and swallowed — the sweeper recovers), `enqueue(job_id) -> None` (`XADD JOB_STREAM {"job_id": str(id)}`), `visible_job(job_id, requester) -> JobRecord | None` (None unless owner or analyst).
  - Views: `JOB_MAX_URLS = 10_000`; `JobCreateRequest(urls: list[str] = Field(min_length=1, max_length=10_000))`; `JobCreatedView(job_id, status, total)`; `ProgressView(done, total)`; `JobView(job_id, status, progress, created_at, finished_at, error, offset, limit, results: list[UrlResultView])` — `results` filled only when status is `done`.
  - Routes (client, analyst): `POST /v1/jobs` → 202 + `Location: /v1/jobs/{id}`; `GET /v1/jobs/{job_id}?offset=0&limit=100` (`limit` 1–1000, `offset` ≥ 0) → 200 or 404 (also for jobs of another client).

- [ ] **Step 1: Write the failing test**

```python
import uuid
from openverdict.services.jobs import JOB_STREAM, JobService

async def test_submit_and_get(api, client_key, analyst_key, valkey, db):
    h = {"X-API-Key": client_key}
    r = await api.post("/v1/jobs", headers=h, json={"urls": ["http://a.test/", "http://b.test/", "bad"]})
    assert r.status_code == 202
    job = r.json()
    assert job["status"] == "queued" and job["total"] == 3
    assert r.headers["Location"] == f"/v1/jobs/{job['job_id']}"
    [(_, fields)] = await valkey.xrange(JOB_STREAM)
    assert fields == {"job_id": job["job_id"]}
    got = (await api.get(f"/v1/jobs/{job['job_id']}", headers=h)).json()
    assert got["progress"] == {"done": 0, "total": 3} and got["results"] == []
    assert (await api.get(f"/v1/jobs/{job['job_id']}", headers={"X-API-Key": analyst_key})).status_code == 200

async def test_visibility_and_validation(api, client_key, db):
    from openverdict.models.api_keys import ApiKeyRepo, Role
    _, other = await ApiKeyRepo(db).create("other-app", Role.CLIENT)
    h = {"X-API-Key": client_key}
    job_id = (await api.post("/v1/jobs", headers=h, json={"urls": ["http://a.test/"]})).json()["job_id"]
    assert (await api.get(f"/v1/jobs/{job_id}", headers={"X-API-Key": other})).status_code == 404
    assert (await api.get(f"/v1/jobs/{uuid.uuid4()}", headers=h)).status_code == 404
    assert (await api.get("/v1/jobs/not-a-uuid", headers=h)).status_code == 422
    assert (await api.get(f"/v1/jobs/{job_id}?limit=1001", headers=h)).status_code == 422
    assert (await api.post("/v1/jobs", headers=h, json={"urls": ["http://a.test/"] * 10_001})).status_code == 422

async def test_enqueue_failure_still_accepted(api, client_key, monkeypatch):
    async def broken(self, job_id):
        raise ConnectionError("valkey down")
    monkeypatch.setattr(JobService, "enqueue", broken)
    r = await api.post("/v1/jobs", headers={"X-API-Key": client_key}, json={"urls": ["http://a.test/"]})
    assert r.status_code == 202
```

- [ ] **Step 2: Run** `uv run pytest tests/integration/test_api_jobs.py -v` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `uv run pytest -v` → all PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: async jobs API backed by Postgres with stream dispatch"`

---

### Task 15: Worker — consumer, recovery, maintenance, scheduler

**Files:**
- Create: `src/openverdict/worker/__init__.py`, `worker/consumer.py`, `worker/maintenance.py`, `worker/scheduler.py`, `worker/main.py`
- Modify: `metrics.py` (job metrics), `cli.py` (add `worker`)
- Test: `tests/integration/test_worker.py`

**Interfaces:**
- Consumes: `JobRepo`, `JobService`, `JOB_STREAM`, `JOB_GROUP` (T14); `UrlPipeline` (T11); `result_to_view` (T12); `FeedSyncer` (T7); `FeedStore.synced_at` (T5); `build_resources` (T12).
- Produces:
  - `JobConsumer(valkey, repo: JobRepo, pipeline: UrlPipeline, name: str, reclaim_idle_ms: int, chunk_size: int = 100, max_attempts: int = 3)` with `ensure_group()` (`XGROUP CREATE ... $ MKSTREAM`, ignore `BUSYGROUP`), `run_once(block_ms: int = 5000) -> int` (first `XAUTOCLAIM` min-idle `reclaim_idle_ms` count 10, then `XREADGROUP` `>` count 1; process each; `XACK` only when `process` returns without raising; returns messages handled), `process(job_id: UUID) -> None` (missing/done/failed → return; `attempts >= max_attempts` → finish failed `"max attempts exceeded"` + `jobs_total{status="failed"}`; else `start`, loop `pending_items(chunk_size)` → `pipeline.check` → `save_results` with `result_to_view(r).model_dump(mode="json")`, until empty; finish done; observe `job_duration_seconds`; `jobs_total{status="done"}`).
  - `maintenance.py`: `sweep_stale_jobs(repo, jobs: JobService, older_than: datetime) -> int` (re-enqueue `repo.stale(...)`); `delete_old_jobs(repo, cutoff: datetime) -> int`; `update_queue_depth(valkey) -> int` (`XINFO GROUPS` → `lag + pending` for `workers`, sets `openverdict_job_queue_depth`; 0 if the stream does not exist).
  - `Scheduler(syncer, jobs, repo, valkey, feed_store, settings, clock=time.time)` with `tick() -> None`: every call `syncer.sync_due(now)`, `update_queue_depth`, and refresh `feed_last_success` gauges from `feed_store.synced_at`; sweep when ≥ 60 s since last sweep; cleanup when ≥ 3600 s since last cleanup (both run on the first tick).
  - `run_worker(settings: Settings) -> None`: configure logging, `build_resources`, `prometheus_client.start_http_server(worker_metrics_port)`, `ensure_group`, `asyncio.TaskGroup` with the consumer loop and a 15 s scheduler loop; consumer name `f"{socket.gethostname()}-{os.getpid()}"`; exits cleanly on SIGTERM/SIGINT. CLI `worker` runs it.

- [ ] **Step 1: Write the failing test**

```python
import asyncio
from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy import update
from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.jobs import JobRepo, JobStatus
from openverdict.models.tables import JobRow
from openverdict.services.jobs import JOB_GROUP, JOB_STREAM, JobService
from openverdict.worker.consumer import JobConsumer
from openverdict.worker.maintenance import delete_old_jobs, sweep_stale_jobs, update_queue_depth
from tests.helpers import sample

@pytest.fixture
async def env(resources, db, valkey, published_feeds):
    res = resources
    owner, _ = await ApiKeyRepo(db).create("owner", Role.CLIENT)
    repo, jobs = JobRepo(db), JobService(JobRepo(db), valkey)
    def consumer(name="c1", idle=300_000):
        return JobConsumer(valkey, repo, res.pipeline, name, idle)
    await consumer().ensure_group()
    return owner, repo, jobs, consumer

URLS = [f"http://bulk-{i}.test/" for i in range(250)]
URLS[7] = "http://malware-drop.test/payload.exe"

async def test_process_job(env, valkey):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS)
    assert await consumer().run_once(block_ms=100) == 1
    done = await repo.get(job.id)
    assert (done.status, done.done, done.total) == (JobStatus.DONE, 250, 250)
    page = await repo.results(job.id, offset=0, limit=1000)
    assert len(page) == 250 and page[7]["verdict"] == "malicious" and page[8]["verdict"] == "unknown"
    assert [r["url"] for r in await repo.results(job.id, offset=100, limit=50)] == URLS[100:150]
    assert (await valkey.xpending(JOB_STREAM, JOB_GROUP))["pending"] == 0

async def test_reclaim_after_crash(env, valkey):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS[:10])
    await valkey.xreadgroup(JOB_GROUP, "dead", {JOB_STREAM: ">"}, count=1)  # delivered, never acked
    assert await consumer("c2", idle=0).run_once(block_ms=100) == 1
    assert (await repo.get(job.id)).status is JobStatus.DONE

async def test_resume_and_concurrent_duplicates(env):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS)
    await repo.save_results(job.id, [(i, {"url": URLS[i], "marker": True}) for i in range(100)])
    await jobs.enqueue(job.id)  # second message for the same job
    await asyncio.gather(consumer("a").run_once(100), consumer("b").run_once(100))
    final = await repo.get(job.id)
    assert final.done == 250
    first = await repo.results(job.id, offset=0, limit=100)
    assert all(r.get("marker") for r in first)

async def test_max_attempts(env, db):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS[:1])
    async with db() as s, s.begin():
        await s.execute(update(JobRow).where(JobRow.id == job.id).values(attempts=3))
    before = sample("openverdict_jobs_total", status="failed")
    await consumer().run_once(100)
    assert (await repo.get(job.id)).status is JobStatus.FAILED
    assert sample("openverdict_jobs_total", status="failed") == before + 1

async def test_sweeper_cleanup_and_gauge(env, db, valkey):
    owner, repo, jobs, consumer = env
    stale = await repo.create(owner.key_id, URLS[:1])       # created without XADD
    fresh = await repo.create(owner.key_id, URLS[:1])
    old = await repo.create(owner.key_id, URLS[:1])
    async with db() as s, s.begin():
        await s.execute(update(JobRow).where(JobRow.id == stale.id).values(updated_at=datetime.now(UTC) - timedelta(minutes=10)))
        await s.execute(update(JobRow).where(JobRow.id == old.id).values(created_at=datetime.now(UTC) - timedelta(days=8)))
    assert await sweep_stale_jobs(repo, jobs, datetime.now(UTC) - timedelta(minutes=5)) == 1
    ids = [f["job_id"] for _, f in await valkey.xrange(JOB_STREAM)]
    assert str(stale.id) in ids and str(fresh.id) not in ids
    assert await update_queue_depth(valkey) == len(ids)
    assert await delete_old_jobs(repo, datetime.now(UTC) - timedelta(days=7)) == 1
    assert await repo.get(old.id) is None and await repo.get(fresh.id) is not None
```


- [ ] **Step 2: Run** `uv run pytest tests/integration/test_worker.py -v` → FAIL.
- [ ] **Step 3: Implement** consumer, maintenance, scheduler, `run_worker`, CLI `worker`.
- [ ] **Step 4: Run** `uv run pytest -v` → all PASS.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: job worker with stream reclaim, sweeper, cleanup and scheduler"`

---

### Task 16: Container, Compose stack, dashboard, demo profile

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `.env.example`, `deploy/compose/prometheus.yml`, `deploy/compose/grafana/provisioning/datasources/prometheus.yml`, `deploy/compose/grafana/provisioning/dashboards/dashboards.yml`, `deploy/compose/grafana/dashboards/openverdict.json`, `deploy/compose/demo.env`, `deploy/compose/demo-feeds/urlhaus/recent.csv`, `deploy/compose/demo-feeds/phishing/links.txt`, `deploy/compose/demo-feeds/phishing/domains.txt`, `deploy/compose/demo-feeds/tranco/top-1m.csv`, `demo/requests.sh`
- Test: `tests/unit/test_demo_feeds.py`

**Decisions:**
- **Dockerfile:** two stages on `python:3.14-slim`. Build stage: `pip install uv`, `uv sync --locked --no-dev --no-install-project` (deps layer), copy `src`, then `uv sync --locked --no-dev --no-editable`. Runtime stage: copy `/app/.venv`, user uid 10001 with no shell, `ENTRYPOINT ["openverdict"]`, `PYTHONUNBUFFERED=1`.
- **Compose services:**
  - `postgres:18-alpine`: volume at `/var/lib/postgresql`, `pg_isready` healthcheck.
  - `valkey/valkey:9-alpine`: `--appendonly yes`, `valkey-cli ping` healthcheck.
  - `migrate`: `command: ["migrate"]`, depends on healthy postgres.
  - `api`: `["api"]`, port 8000, depends on `migrate: service_completed_successfully` and healthy valkey; healthcheck on `/readyz` using python urllib.
  - `worker`: `["worker"]`, same dependencies.
  - `prometheus`: scrapes `api:8000` and `worker:9100` every 15 s; port 9090.
  - `grafana`: anonymous Viewer enabled, provisioned datasource and dashboard; port 3000.
  - `demo-feeds`: `nginx:alpine`, `profiles: ["demo"]`, serves `deploy/compose/demo-feeds` read-only.
  - `api` and `worker` run with `read_only: true`, `tmpfs: [/tmp]`, `user: "10001"`.
  - Feed URLs and keys are passed from compose variables with real defaults, e.g. `OPENVERDICT_URLHAUS_URL: ${OPENVERDICT_URLHAUS_URL:-https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv}`. Watch the `$$`/`{}` escaping.
  - Prometheus and Grafana are pinned to the newest stable tag at build time (check with `docker manifest inspect`).
- **Demo command (ruling):** `docker compose --env-file deploy/compose/demo.env up -d --build`. `demo.env` sets `COMPOSE_PROFILES=demo` and points the four feed URLs at `http://demo-feeds/...`. A bare `--profile demo` can't change the worker's environment, so the env file carries both.
- **Demo feed contents (reserved names only):**
  - `urlhaus/recent.csv` (legacy CSV format): `http://malware-drop.test/payload.exe` and `http://bad-host.test/a.exe`.
  - `phishing/links.txt`: `http://secure-login.test/verify`.
  - `phishing/domains.txt`: `phish-domain.test`.
  - `tranco/top-1m.csv`: `1,example.com`, `2,example.org`, `3,example.net`.
- **`demo/requests.sh`** (bash + curl + `python3 -m json.tool`, keys from `CLIENT_KEY` and `ANALYST_KEY`):
  1. Check these URLs: `http://malware-drop.test/payload.exe`, `http://secure-login.test/verify`, `http://bad-host.test/other`, `http://login.phish-domain.test/`, `http://paypa1.test/login`, `https://www.example.com/`, `http://unlisted.test/`, `ftp://files.test/x`.
  2. Send 101 URLs to show the 422.
  3. Create an analyst override marking `http://malware-drop.test/payload.exe` safe, then re-check it.
  4. Submit a 5,000-URL job and poll it until it's done.
- **Dashboard** (uid `openverdict`):
  - Request rate and p50/p95/p99 latency (`histogram_quantile` on the HTTP histogram)
  - 5xx rate
  - Verdicts by type
  - Cache hit ratio
  - Detector p95 latency and failures
  - Feed age (`time() - openverdict_feed_last_success_timestamp_seconds`)
  - Feed entries
  - Job queue depth
  - Job p95 duration
  - Override outcomes: false positives and false negatives in one panel, coverage gaps in a separate one

- [ ] **Step 1: Write the failing test**

```python
from pathlib import Path
from openverdict.feeds.parsers import parse_domain_lines, parse_tranco, parse_url_lines, parse_urlhaus_csv

DEMO = Path(__file__).parents[2] / "deploy" / "compose" / "demo-feeds"

def test_demo_feeds_parse_with_real_parsers():
    assert "http://malware-drop.test/payload.exe" in parse_urlhaus_csv((DEMO / "urlhaus/recent.csv").read_text()).urls
    assert parse_url_lines((DEMO / "phishing/links.txt").read_text()).urls == {"http://secure-login.test/verify": ""}
    assert parse_domain_lines((DEMO / "phishing/domains.txt").read_text()) == {"phish-domain.test"}
    assert parse_tranco((DEMO / "tranco/top-1m.csv").read_bytes(), 10) == ["example.com", "example.org", "example.net"]
```

- [ ] **Step 2: Run** `uv run pytest tests/unit/test_demo_feeds.py -v` → FAIL (files missing).
- [ ] **Step 3: Create** all files listed above.
- [ ] **Step 4: Run** `uv run pytest tests/unit/test_demo_feeds.py -v` → PASS.
- [ ] **Step 5: End-to-end verification**
  - `docker compose --env-file deploy/compose/demo.env up -d --build`, then `curl -fsS localhost:8000/readyz` → `{"postgres":"ok","valkey":"ok"}`.
  - `docker compose exec api openverdict create-key --name demo-client --role client` and the same for `--role analyst`. Export the keys as `CLIENT_KEY` and `ANALYST_KEY`.
  - Wait until `curl -s localhost:9100/metrics | grep openverdict_feed_last_success_timestamp_seconds` shows all three feeds.
  - `bash demo/requests.sh` should return, in order: malicious, malicious, suspicious, suspicious, suspicious, safe, unknown, `unsupported_scheme`. Then 422, override → safe, and the job reaching done with 5,000 results.
  - Re-run the job step and run `docker compose kill worker && docker compose up -d worker` mid-run. The job still finishes with 5,000 results.
  - `curl -s localhost:3000/api/dashboards/uid/openverdict` → 200.
  - `docker compose logs api worker | grep -c "/verify"` → 0.
  - Finish with `docker compose down`.
- [ ] **Step 6: Commit** `git add -A && git commit -m "feat: container image, compose stack, Grafana dashboard and offline demo profile"`

---

### Task 17: CI and README

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md` (replace the GitHub stub)

**Decisions:**
- **CI** runs on push and pull_request, on `ubuntu-latest` (Docker is available for testcontainers), using the latest major versions of `actions/checkout` and `astral-sh/setup-uv`. Three jobs:
  - `lint`: `uv sync --locked`, `ruff check`, `ruff format --check`, `mypy src`.
  - `test`: `uv run pytest -v`.
  - `image`: `docker build .` (no push).
- **README sections, in order:**
  1. What it is: one paragraph plus the verdict JSON example.
  2. Quickstart (demo): the Task 16 commands.
  3. Real feeds: getting a free abuse.ch Auth-Key, `.env`. Note that the first sync downloads about 80 MB from Phishing.Database, and that that feed is community-maintained and partly stale.
  4. API reference table.
  5. Architecture: a mermaid diagram of api, worker, Valkey and Postgres, plus Prometheus and Grafana.
  6. Detection: detectors, the matching rule, the combine rule, heuristics signals.
  7. Security model: never fetches URLs; Safe Browsing is opt-in and sends URLs to Google under non-commercial terms; log redaction; API keys stored as SHA-256 hashes; non-root, read-only containers.
  8. Metrics and the dashboard.
  9. **On AWS**, as a component → service table with trade-offs:
     - API: ECS Fargate behind an ALB vs Lambda + API Gateway (cold starts, 29 s limit).
     - Worker: Fargate scaled on queue depth.
     - Valkey: ElastiCache for Valkey, serverless or node-based.
     - Job stream: keep Valkey Streams or swap to SQS (visibility timeout ≈ `XAUTOCLAIM`, no ops).
     - Postgres: RDS/Aurora PostgreSQL, Multi-AZ.
     - Metrics: Amazon Managed Prometheus/Grafana or CloudWatch.
     - Secrets: Secrets Manager.
     - Network: private subnets, plus a NAT/egress allowlist limited to the feed hosts (defence in depth against SSRF).
     - IaC: Terraform.
  10. Development: uv commands and test layout.
  11. Licence: Apache-2.0.

- [ ] **Step 1: Write** `ci.yml` and `README.md`.
- [ ] **Step 2: Verify locally** `uv sync --locked && uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest -v && docker build -t openverdict:ci .` → all green; README commands match `demo/requests.sh` and compose file.
- [ ] **Step 3: Commit** `git add -A && git commit -m "docs: README with AWS mapping; ci: lint, test and image build"`

---

## Deferred (not in Part 1)

- Verify the URLhaus v2 export's exact CSV format against a real download, once an Auth-Key exists.
- Map Postgres outages during URL checks to 503 instead of 500.
- Stream-parse the 66 MB Phishing.Database file to lower peak memory in the worker.
- Per-key rate limiting, webhooks and the analyst UI (spec non-goals).
