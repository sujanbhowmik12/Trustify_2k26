<div align="center">

<img src="assets/logo.png" alt="Trustify logo" width="130" />

# Trustify

### AI-Powered Web Threat Detection & Digital Trust Intelligence

**Detect phishing websites, fraudulent payment portals and Certificate Authority key vulnerabilities, with a unified 0–100 trust score in seconds.**

![Status](https://img.shields.io/badge/status-hackathon%20build-468D8B?style=for-the-badge)
![Next.js](https://img.shields.io/badge/Next.js-14-213843?style=for-the-badge&logo=nextdotjs)
![FastAPI](https://img.shields.io/badge/FastAPI-Python%203.11-468D8B?style=for-the-badge&logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-74B3A8?style=for-the-badge&logo=postgresql&logoColor=213843)
![License](https://img.shields.io/badge/license-MIT-FEAF76?style=for-the-badge)

[Demo](#-demo) · [Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [API](#-api-overview) · [Team](#-team)

<img src="[docs/screenshots/dashboard.png](https://drive.google.com/file/d/1YiF2vM-kPLvvPIMLYRiiVwgmlbznzqq5/view?usp=sharing)" alt="Trustify dashboard" width="900" />

</div>

---

## 📌 Table of Contents
1. [Problem Statement](#-problem-statement)
2. [Our Solution](#-our-solution)
3. [Features](#-features)
4. [Demo](#-demo)
5. [Architecture](#-architecture)
6. [Tech Stack](#-tech-stack)
7. [Quick Start](#-quick-start)
8. [Test URLs](#-try-these-test-urls)
9. [API Overview](#-api-overview)
10. [MCP Server](#-mcp-server)
11. [Project Structure](#-project-structure)
12. [Security & Responsible Use](#-security--responsible-use)
13. [Testing](#-testing)
14. [Roadmap](#-roadmap)
15. [Team](#-team)
16. [License](#-license)

---

## 🎯 Problem Statement

The internet powers banking, education, recruitment, e-commerce and payments, but it is also full of **phishing sites, fake payment links, fake recruitment portals, impersonated organisations, malicious redirects and credential-harvesting attacks**. A fraudulent site can look identical to a real bank or university portal.

The web's **trust infrastructure** is under pressure too. Weak Certificate Authority key generation, as highlighted by the recent **eMudhra TLS certificate incident**, can allow fraudulent certificates to be issued for website impersonation. This makes **certificate transparency, cryptographic validation and continuous monitoring** essential.

Existing tools solve these problems **separately**, and ordinary users cannot tell a safe site from a dangerous one.

## 💡 Our Solution

**Trustify** fuses four engines into one accessible platform and returns a single, **explainable trust score (0–100)** for any URL.

| Engine | What it does |
|---|---|
| 🧠 **Threat Analysis** | ML + heuristics for phishing, brand lookalikes and homoglyphs, risky redirects, malicious page content |
| 🔐 **Certificate Forensics** | TLS chain checks, key strength, SHA-1 and weak keys, shared-key detection, Certificate Transparency timeline and anomalies |
| 🧱 **Web Security Assessment** | Security headers, cookie flags, mixed content, information disclosure (passive only) |
| 🤝 **Collaborative Threat Intelligence** | Community reports and voting, live threat feeds, trending threats, IOC export |

Every verdict comes with **plain-language reasons** and a **recommended action**, so users understand *why* a site is risky.

---

## ✨ Features

- 🔍 **URL Scanner**: Safe / Suspicious / Malicious verdict with live progress (SSE)
- 📊 **Dashboard**: total scans, safe websites, threats blocked, average latency, 7-day trust-score trend, recent threat alerts
- 🔐 **Certificate Forensics**: chain visualisation, expiry, key details, CT log timeline, weak-key analysis
- 🛡️ **eMudhra CA Defense**: continuous CT log monitoring and weak RSA key generation detection
- 🧬 **Explainable AI**: top signals shown as reason codes such as `BRAND_LOOKALIKE` and `NEW_DOMAIN_LT_30D`
- 🔔 **Security Alerts**: severity-based alerts (High / Medium / Low) for malicious sites and certificate issues
- 🕘 **Scan History**: searchable, filterable history with CSV export
- 🌐 **Threat Intelligence Hub**: report URLs, vote, trending domains, IOC export (CSV / JSON / STIX-lite)
- 👀 **Watchlist**: monitor your own domains for certificate expiry and unexpected issuance
- 🔌 **Settings & API**: API keys, public check endpoint and an MCP server for AI agents
- ♿ **Accessible, responsive UI**: WCAG AA contrast, keyboard friendly, mobile ready

---

## 🎬 Demo

| Dashboard | URL Scanner |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Scanner](docs/screenshots/scan-result.png) |

| Certificate Forensics | Threat Intelligence |
|---|---|
| ![Certificate](docs/screenshots/certificate.png) | ![Intel](docs/screenshots/intel.png) |

🎥 **Demo video:** `<add link>` · 🌐 **Live app:** `<add link>`

---

## 🏗️ Architecture

```
Browser ──► Next.js Frontend ──► FastAPI Gateway ──► Redis (queue · cache · pub/sub)
                                       │                    │
                                       ▼                    ▼
                                 PostgreSQL          Celery Scan Workers
                                                     ├─ Threat Engine (ML)
                                                     ├─ Certificate Engine (+ CT logs)
                                                     ├─ Web Security Engine
                                                     └─ Intel Engine (feeds + community)
```

**Scoring:** `risk = 0.40·threat + 0.25·certificate + 0.20·web-security + 0.15·intel`, then `score = 100 − risk`
**Verdict:** ≥ 80 **Safe** · 50–79 **Suspicious** · < 50 **Malicious** (confirmed feed hits override)

Full design: [`docs/03_ARCHITECTURE.md`](docs/03_ARCHITECTURE.md)

---

## 🧰 Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | Next.js 14, TypeScript, Tailwind CSS, shadcn/ui, Recharts, TanStack Query |
| **Backend** | FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Celery |
| **Data** | PostgreSQL 16, Redis 7 |
| **ML / Security** | scikit-learn, XGBoost, cryptography, dnspython, RapidFuzz |
| **Browser sandbox** | Playwright (isolated container) |
| **DevOps** | Docker Compose, GitHub Actions |
| **Integrations** | crt.sh (Certificate Transparency), OpenPhish, URLhaus, Google Safe Browsing, VirusTotal *(all optional)* |

---

## 🚀 Quick Start

### Prerequisites
Docker and Docker Compose v2, Git. Optional for local development: Node.js 20 and Python 3.11.

### Run with Docker
```bash
git clone https://github.com/<your-username>/trustify.git
cd trustify
cp .env.example .env        # add optional API keys
docker compose up --build
```

| Service | URL |
|---|---|
| Web app | http://localhost:3000 |
| API docs (Swagger) | http://localhost:8000/docs |

```bash
make migrate   # apply database migrations
make seed      # load demo data
```

**Demo login (local development only):** `demo@trustify.app` / `Demo@12345`

### Environment variables
All variables are documented in [`docs/09_SETUP.md`](docs/09_SETUP.md). External API keys are **optional**. Set `MOCK_EXTERNAL=true` to run fully offline with fixtures.

---

## 🧪 Try These Test URLs

| URL | Expected result |
|---|---|
| `https://example.com` | ✅ Safe |
| `https://expired.badssl.com` | ⚠️ Certificate expired |
| `https://self-signed.badssl.com` | ⚠️ Self-signed certificate |
| `https://wrong.host.badssl.com` | ⚠️ Hostname mismatch |
| `http://neverssl.com` | ⚠️ No TLS |
| Local phishing fixture (`tests/fixtures/phish_site`) | ❌ Malicious: brand lookalike, off-domain login form |

---

## 🔌 API Overview

Base path: `/api/v1` · Full reference: [`docs/05_API.md`](docs/05_API.md) · Interactive docs at `/docs`

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/scans` | Start a scan |
| `GET` | `/scans/{id}` | Get verdict, score and reasons |
| `GET` | `/scans/{id}/events` | Live progress (SSE) |
| `POST` | `/certificates/check` | Analyse a host's certificate |
| `GET` | `/certificates/ct/{domain}` | Certificate Transparency timeline |
| `POST` | `/intel/reports` | Report a malicious URL |
| `GET` | `/dashboard/summary` | Dashboard metrics |
| `GET` | `/public/check?url=` | Lightweight check for extensions (API key) |

---

## 🤖 MCP Server

Trustify includes a **Model Context Protocol** server so AI agents can use it as a tool: `scan_url`, `check_certificate`, `lookup_indicator`, `report_threat`, `get_trending_threats`.

Setup details: [`docs/12_MCP_CONNECTION.md`](docs/12_MCP_CONNECTION.md)

---

## 📁 Project Structure

```
trustify/
├─ apps/
│  ├─ web/        # Next.js frontend
│  └─ api/        # FastAPI backend, engines, workers, ML
├─ mcp/           # Trustify MCP server
├─ docs/          # PRD, design, architecture, API, ...
├─ assets/        # Logo and brand assets
├─ docker-compose.yml
├─ .env.example
└─ Makefile
```

### 📚 Documentation
| Doc | Doc |
|---|---|
| [PRD](docs/01_PRD.md) | [Testing & QA](docs/14_TESTING_QA.md) |
| [Design System](docs/02_DESIGN.md) | [Auth & Security](docs/11_AUTH_SECURITY.md) |
| [Architecture](docs/03_ARCHITECTURE.md) | [MCP Connection](docs/12_MCP_CONNECTION.md) |
| [Database](docs/04_DATABASE.md) | [Integrations](docs/13_INTEGRATIONS.md) |
| [API](docs/05_API.md) | [Debugging](docs/15_DEBUGGING.md) |
| [Agents](docs/06_AGENTS.md) | [Setup](docs/09_SETUP.md) |
| [Implementation Plan](docs/08_PROJECT_IMPLEMENTATION.md) | [Feature Development](docs/10_FEATURE_DEVELOPMENT.md) |

---

## 🔒 Security & Responsible Use

- Scanning is **passive and non-intrusive**: no exploitation, brute forcing or port scanning.
- All outbound fetching goes through an **SSRF-safe client** (private, loopback and metadata IPs blocked, redirects re-validated, DNS pinned).
- Page rendering runs in an **isolated browser sandbox**.
- Passwords are hashed with **Argon2id**, with short-lived JWTs, rotating refresh tokens and rate limiting on sensitive routes.
- Use Trustify only on sites you are permitted to test.

Details: [`docs/11_AUTH_SECURITY.md`](docs/11_AUTH_SECURITY.md) · To report a vulnerability, email `<security contact>`.

---

## ✅ Testing

```bash
make lint        # ruff, mypy, eslint, tsc
make test        # backend + frontend unit/integration tests
make e2e         # Playwright end-to-end tests
make eval-model  # ML precision / recall / false-positive report
```

Strategy and checklists: [`docs/14_TESTING_QA.md`](docs/14_TESTING_QA.md)

---

## 🎨 Brand & Design

| Token | Hex | Use |
|---|---|---|
| Deep teal | `#213843` | Sidebar and background |
| Teal | `#468D8B` | Primary buttons, active items |
| Soft teal | `#74B3A8` | Charts, highlights |
| Warm cream | `#F6DAC0` | Cards |
| Peach | `#FEAF76` | Warnings, suspicious |
| Coral | `#DA6D58` | Critical, malicious |

---

## 🗺️ Roadmap

- [x] URL scan with explainable verdicts
- [x] Certificate forensics and CT monitoring
- [x] Community threat intelligence
- [ ] Browser extension (Chrome / Edge)
- [ ] PDF security reports
- [ ] Live CT-log streaming for watchlist domains
- [ ] STIX/TAXII sharing
- [ ] Organisation dashboards and team workspaces

---

## 👥 Team

| | Name | Role | GitHub |
|---|---|---|---|
| 👤 | `<Member 1>` | Team Lead · Full-stack | [@username](https://github.com/username) |
| 👤 | `Arghya Chowdhury` | Frontend & UI/UX | [@username](https://github.com/username) |
| 👤 | `Sayan Pattanaya` | Backend & Security Engines | [@username](https://github.com/username) |
| 👤 | `<Member 4>` | ML, QA & DevOps | [@username](https://github.com/username) |

**Built for:** `Hackmatrix` · `<Date>`

---

## 🤝 Contributing

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Follow the standards in [`AGENTS.md`](AGENTS.md) and run `make lint test`
3. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`)
4. Open a Pull Request with a clear description and screenshots for UI changes

## 🙏 Acknowledgements

OpenPhish · abuse.ch URLhaus · PhishTank · crt.sh · Tranco list · Google Safe Browsing · badssl.com

## 📄 License

Released under the [MIT License](LICENSE).

<div align="center">

**Trustify** · *Because trust should be verified, not assumed.* 🛡️

</div>
