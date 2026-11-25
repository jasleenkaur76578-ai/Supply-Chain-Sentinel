# Supply Chain Sentinel — Deployment Guide
**Architecture:** Containerized Multi-Tier Microservice Platform  
**Target Environments:** Local Workstation, On-Premises Linux VM, Kubernetes / Docker Compose  

---

## 1. Prerequisites

- **Docker:** Engine 24.0+ and Docker Compose v2.20+
- **Host Runtime (for direct local execution):**
  - Python 3.12+
  - Node.js 20+ LTS / npm 10+
  - Git 2.40+

---

## 2. Docker Compose Quickstart (Recommended)

1. **Clone repository:**
   ```bash
   git clone https://github.com/enterprise/supply-chain-sentinel.git
   cd supply-chain-sentinel
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your secrets or use sensible defaults for local evaluation
   ```

3. **Launch complete platform:**
   ```bash
   docker compose up -d --build
   ```

4. **Verify container health:**
   ```bash
   docker compose ps
   ```

5. **Access services:**
   - **Frontend UI:** `http://localhost:5173`
   - **Backend REST API:** `http://localhost:8000/api/v1`
   - **OpenAPI / Swagger Docs:** `http://localhost:8000/docs`
   - **PostgreSQL Database:** `localhost:5432`

---

## 3. Direct Native Development Setup

### 3.1 Backend (FastAPI + Python 3.12)
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
alembic upgrade head
python -m app.main
```
The backend initializes the database (SQLite for zero-config local run, or PostgreSQL when `DATABASE_URL` is set) and seeds demonstration data.

### 3.2 Frontend (React + TypeScript + Vite)
```bash
cd frontend
npm install
npm run dev
```
Available at `http://localhost:5173`.
