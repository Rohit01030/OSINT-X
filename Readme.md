# OSINT-X — Project Structure (v2)

An OSINT (Open-Source Intelligence) investigation platform — domain, IP,
email, username, and file intelligence, threat-intel integrations, and a
local AI assistant (Ollama-based, no API key required) — built full-stack
with React, FastAPI, and PostgreSQL.

> **Build status:** Step 1 of 30 complete — backend skeleton, config,
> logging, and health check are working. See the build roadmap for what's
> next.

### Local AI integration · No API keys required · Security-first ordering

---

## 1. What changed from the original plan

| Change | Why |
|---|---|
| AI runs **100% locally via Ollama** | No API key, no cost, no third-party data exposure, works offline |
| Basic security (rate limiting, input validation) moved into **Phase 1 & 4** | Prevents burning through free-tier API quotas (Shodan/VirusTotal) before Phase 11 even exists |
| New `findings`, `iocs`, `consent_logs` tables added to schema in Phase 1 | Avoids corrective migrations later; Phase 4–7 modules just insert into `findings` |
| Explicit **consent gate** added to Phase 5 | Enforces "authorized targets only" in the product, not just the docs |
| AI kept **out** of security-critical logic (ATT&CK mapping, blacklist scoring) | Those stay deterministic/rule-based; AI only explains and summarizes — no hallucination risk on things that matter |

---

## 2. Tech Stack

**Frontend**
- React + Vite, Tailwind CSS, React Router, Axios, React Query, Chart.js, React Hook Form

**Backend**
- FastAPI, SQLAlchemy, Alembic, Pydantic, Uvicorn, Passlib
- Celery + Redis (background jobs — lookups and AI calls run async, don't block requests)
- slowapi (rate limiting)

**Database**
- PostgreSQL

**AI (local only)**
- Ollama, running a local model — Llama 3 8B / Qwen2.5 7B / Mistral 7B (user-selectable)
- No API key, no internet call at inference time
- Optional: LangChain for prompt orchestration (not required — a thin direct wrapper is enough)

**DevOps**
- Docker, Docker Compose, Nginx, GitHub Actions

---

## 3. Folder Structure

```
OSINT-X/
│
├── frontend/
│   ├── src/
│   │   ├── assets/
│   │   ├── components/
│   │   ├── layouts/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── routes/
│   │   ├── contexts/
│   │   ├── utils/
│   │   └── App.jsx
│   ├── public/
│   └── package.json
│
├── backend/
│   ├── app/
│   ├── api/
│   ├── auth/
│   ├── models/
│   ├── schemas/
│   ├── database/
│   ├── services/
│   │   ├── domain/
│   │   ├── ip/
│   │   ├── email/
│   │   ├── username/
│   │   ├── file_analysis/
│   │   └── threat_intel/
│   ├── core/
│   │   ├── rate_limit.py
│   │   ├── validation.py
│   │   └── consent.py          # enforces authorized-target confirmation
│   ├── background/              # Celery tasks (lookups, AI calls)
│   ├── middleware/
│   ├── logs/
│   ├── tests/
│   ├── main.py
│   └── requirements.txt
│
├── ai/
│   ├── engine/
│   │   ├── ollama_client.py     # thin wrapper around local Ollama REST API — no external key
│   │   ├── summarizer.py        # investigation summary via local model
│   │   ├── risk_scoring.py      # DETERMINISTIC — no AI, fixed rule weights
│   │   ├── attack_mapping.py    # DETERMINISTIC — static MITRE ATT&CK lookup table
│   │   ├── ioc_correlation.py   # rule-based cross-investigation matching
│   │   └── nl_search.py         # local model translates query -> structured filter
│   ├── prompts/
│   │   ├── summary_prompt.txt
│   │   ├── explain_findings_prompt.txt
│   │   └── nl_search_prompt.txt
│   ├── models_config.yaml       # which local model, endpoint, temperature
│   └── README.md                # documents: no API key, no external calls, fully local
│
├── database/
│   └── migrations/              # Alembic
│
├── docker/
├── nginx/
├── docs/
├── scripts/
├── reports/
├── screenshots/
├── .env
├── docker-compose.yml
├── README.md
└── .gitignore
```

---

## 4. Database Schema (updated)

**users** — id, username, email, password_hash, role, created_at

**investigations** — id, title, description, created_by, created_at, status, tags[]

**findings** *(new)* — id, investigation_id, module (`domain`/`ip`/`email`/`username`/`file`/`threat_intel`), type, data (JSONB), created_at
> Every module (Phase 4–7) writes here. One flexible table instead of a new one per module.

**iocs** *(new)* — id, value, type (`ip`/`domain`/`hash`/`email`), first_seen, last_seen, source, reputation_score
> Enables Phase 8's correlation feature — same IOC appearing across investigations gets flagged automatically.

**consent_logs** *(new)* — id, user_id, investigation_id, target, confirmed_at, ip_address
> Written every time a user confirms authorization before an active scan (Phase 5).

**reports** — id, investigation_id, report_path, created_at

**audit_logs** *(Phase 11)* — id, user_id, action, target, timestamp

---

## 5. AI Module Design — how "no API key" actually works

```
Frontend → Backend API → Celery task → ai/engine/*.py → Ollama (localhost:11434) → response
```

- `OLLAMA_BASE_URL=http://ollama:11434` runs as its own Docker Compose service — a model server on your machine, not a hosted API.
- `ollama_client.py` is the **only** file that talks to the model. Swappable later if you ever want a hosted fallback, but nothing requires it.
- **Deterministic logic stays deterministic.** Risk scores and ATT&CK mapping are rule-based Python, not model output — AI only writes the human-readable explanation around numbers that are already fixed. This means the platform is accurate even if the local model is small or occasionally imprecise in phrasing.
- Runs fully offline once the models are pulled (`ollama pull llama3:8b`).

---

## 6. Updated 12-Phase Plan

**Phase 1 — Project Setup & Core Security Foundations**
Git, React+Vite, FastAPI, PostgreSQL, Docker, env vars, folder structure, logging, **+ basic rate limiting & input validation middleware**, **+ `findings`/`iocs`/`consent_logs` tables created now**

**Phase 2 — Authentication & User Management**
Registration, login, JWT, password hashing, forgot password, email verification, profile, admin role

**Phase 3 — Dashboard & Case Management**
Dashboard, investigation CRUD, search, tags, notes, favorites, timeline

**Phase 4 — Domain Intelligence Module**
WHOIS, DNS, reverse DNS, SSL analysis, subdomain enum, HTTP headers, tech detection, security headers — rate-limited endpoints, results written to `findings`

**Phase 5 — IP Intelligence Module + Consent Gate**
GeoIP, ASN, reputation, blacklist, abuse reports, open ports (**authorized targets only — enforced via required consent checkbox → `consent_logs`**), ISP, map

> **Optional MVP checkpoint:** Phases 1–5 + Phase 10 alone form a demoable, portfolio-ready tool.

**Phase 6 — Email, Username & File Intelligence**
MX/SPF/DKIM/DMARC, breach status (via HIBP API, not scraped dumps), username search, file metadata/EXIF/hashing

**Phase 7 — Threat Intelligence Integration**
VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, Censys, urlscan.io — IOC lookup, reputation, feeds, history

**Phase 8 — Local AI Investigation Engine**
- Investigation summary (template + local model polish)
- Risk score (deterministic rules; AI explains the "why")
- IOC correlation (rule-based matching across investigations)
- MITRE ATT&CK mapping (static lookup table)
- Natural language search (local model → structured filter, with regular filter UI always available as fallback)
- No API key, no external calls — Ollama only

**Phase 9 — Visualization**
Relationship graph, timeline, interactive charts, geo map, network graph

**Phase 10 — Report Generator**
PDF/CSV/JSON export, executive summary, technical report, AI-assisted narrative section

**Phase 11 — Security & Performance**
CSRF protection, audit logs, Redis caching, Celery job tuning, pagination, API optimization

**Phase 12 — Deployment & Documentation**
Docker Compose, Nginx, HTTPS, CI/CD, README, Swagger docs, user guide, architecture diagrams, unit/integration/E2E tests

---

## 7. Docker Compose Services

```
frontend
backend
postgres
redis
celery-worker
ollama          ← local model server, no key required
nginx           ← Phase 12
```

---

## 8. Environment Variables (updated)

```
# Frontend
VITE_API_URL=http://localhost:8000

# Backend
DATABASE_URL=
SECRET_KEY=
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REDIS_URL=

# AI — no API key anywhere
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama3:8b

# Threat intel (only these need keys — all have free tiers)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
```

---

## 9. Estimated Timeline

| Phases | Duration |
|---|---|
| 1–3 | 2 weeks |
| 4–7 | 4 weeks |
| 8–10 | 3 weeks |
| 11–12 | 2 weeks |
| **Total** | **~10–12 weeks part-time** |

Note: this is roughly the same timeline as the original AI-included version — local Ollama integration doesn't remove any development time the way dropping AI entirely would, but it does remove all API cost and setup friction for anyone running the project.
