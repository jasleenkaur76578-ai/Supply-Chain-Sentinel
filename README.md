# SUPPLY CHAIN SENTINEL
> **"See the Risk. Trace the Impact. Stop the Spread."**
> 
> *Enterprise-Grade AI-Powered Software Supply Chain Risk Intelligence & Attack Propagation Platform*

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened%20ASVS%20v4-blue.svg)](SECURITY.md)
[![Architecture: Decoupled](https://img.shields.io/badge/Architecture-Decoupled%20Micro--Modular-brightgreen.svg)](ARCHITECTURE.md)
[![Vulnerability Intel: OSV%20%7C%20NVD%20%7C%20KEV%20%7C%20EPSS](https://img.shields.io/badge/Intel-OSV%20%7C%20NVD%20%7C%20CISA%20KEV%20%7C%20EPSS-orange.svg)](API_DOCUMENTATION.md)
[![Python: 3.12](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![React: 18](https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-cyan.svg)](https://react.dev/)

---

## 1. Executive Overview

Modern organizations depend on thousands of open-source packages, third-party libraries, container images, and software development pipelines. Over 85% of modern enterprise software consists of dependencies, with an average application inheriting between 4 and 10 layers of transitive dependencies.

When a vulnerability or compromise strikes an open-source component (e.g. Log4Shell, Spring4Shell, XZ Utils backdoor), it rarely stays confined to a single application. It propagates through shared libraries across the organization, putting revenue-generating business services at risk.

**Supply Chain Sentinel** bridges the gap between raw vulnerability detection and enterprise business impact.

```
Software Asset → Dependency → Vulnerability → Attack Scenario → Affected Application → Business Service → Risk Priority → Remediation
```

### The Sentinel Philosophy
1. **Move from Reactive Detection to Proactive Intelligence**: Connect low-level CVE telemetry directly with business service disruption potential.
2. **Strict Distinction Between Exposure and Incident**: Explicitly distinguish:
   - A *vulnerable component* (code present)
   - A *dependency relationship* (direct vs. transitive linkage)
   - A *potentially exploitable attack path* (reachability and exposure)
   - A *confirmed security incident* (runtime compromise)
   Theoretical exposure is never presented as a confirmed compromise.

---

## 2. Core Functional Modules

1. **Security Operations Overview**: Executive dashboard with live KPI metrics, vulnerability severity distribution, risk trends, urgent attention items, and intelligence sync status.
2. **Software Asset Discovery**: Centralized repository and application inventory with business criticality ratings, environment classifications, and owner mappings.
3. **Hardened SBOM Analyser**: Dual CycloneDX (JSON/XML) and SPDX (JSON) parser with XML entity protection (`defusedxml`), PURL normalization, license compliance, and direct vs. transitive mapping.
4. **Vulnerability Intelligence Engine**: Live integration with OSV.dev, NIST NVD, CISA Known Exploited Vulnerabilities (KEV), and FIRST EPSS probability scores.
5. **Interactive Dependency Graph**: Rich visual graph topology displaying applications, direct/transitive packages, suppliers, and vulnerabilities with depth filters, search, and detail drawers.
6. **Attack Propagation & Blast Radius**: Downstream graph traversal engine (BFS/DFS) mapping how a single vulnerable package cascades into affected applications and critical business services.
7. **Enterprise Risk Scoring Engine**: Transparent, explainable multi-factor risk formula factoring CVSS severity, EPSS weaponization likelihood, KEV status, asset criticality, and internet exposure.
8. **AI Security Intelligence Assistant**: Grounded Retrieval-Augmented Generation (RAG) providing explainable vulnerability summaries, blast-radius briefings, and remediation advice without prompt injection risk.
9. **Remediation Management Centre**: Complete remediation lifecycle (SLA tracking, team assignment, compensating controls, risk acceptance) with automated dual-SBOM rescan verification.
10. **Third-Party Supplier Risk**: Supplier concentration analysis, trust tier classification, and risk exposure assessment.
11. **Continuous Monitoring & Alerts**: Automated intelligence polling, in-app notification center, and alert acknowledgement workflows.
12. **Executive Reporting**: Management-ready PDF, HTML, and CSV exports detailing enterprise risk posture, affected services, and remediation progress.

---

## 3. Technology Stack

- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, React Flow, Recharts, Lucide Icons, TanStack Query.
- **Backend**: Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, DefusedXML.
- **Data Tier**: PostgreSQL 16+ (or SQLite for instant standalone evaluation), Redis (caching & background queues).
- **Security Intelligence**: OSV.dev REST API, NIST NVD 2.0 API, CISA KEV JSON feed, FIRST EPSS API.
- **Deployment**: Docker, Docker Compose, Linux/Windows native runners.

---

## 4. Quickstart Guide

### Option A: Docker Compose
```bash
cp .env.example .env
docker compose up -d --build
```
- Web Application: `http://localhost:5173`
- API & Swagger Docs: `http://localhost:8000/docs`

### Option B: Native Development Run
```bash
# 1. Start Backend
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
pip install -r requirements.txt
python -m app.main

# 2. Start Frontend
cd ../frontend
npm install
npm run dev
```

---

## 5. Security & Verification Strategy

- **STRIDE Threat Model**: Detailed threat vectors, mitigations, and trust boundaries documented in [THREAT_MODEL.md](THREAT_MODEL.md).
- **Security Controls**: Password hashing via Argon2id, RBAC authorization, tamper-evident audit logging, and defensive file parsing detailed in [SECURITY.md](SECURITY.md).
- **API Contracts**: OpenAPI 3.0 specification documented in [API_DOCUMENTATION.md](API_DOCUMENTATION.md).
- **Database Schema**: Normalised multi-tenant schema with indexed relationships documented in [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).
- **Dual-SBOM Verification**: Mathematical proof of vulnerability resolution by diffing pre- and post-remediation SBOM documents.
