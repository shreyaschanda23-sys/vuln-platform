# VULN//PLATFORM

A full-stack automated vulnerability scanning and management platform. Orchestrates 13 industry-standard security tools into a single pipeline, enriches findings with real-time threat intelligence, and scores risk using CVSS, EPSS, and CISA KEV data.

Built as a hackathon project for Tata Technologies Innovent.

## What it does

Point it at a domain and it runs a full reconnaissance-to-report pipeline automatically:

1. **Asset discovery** — subfinder + amass find subdomains concurrently
2. **Port scanning** — masscan + nmap identify open ports and running services
3. **Live host detection** — httpx probes for live endpoints, extracts tech stack and titles
4. **Crawling** — katana discovers additional pages and endpoints, filtered for scope and validity
5. **Vulnerability scanning** — nuclei checks thousands of CVE/misconfiguration templates, batched for concurrency
6. **Deep scanning** (opt-in) — ffuf, sqlmap, dalfox, trufflehog, and gowitness for directory fuzzing, SQL injection, XSS, secret detection, and screenshots
7. **Enrichment** — every finding gets a CVSS score (NVD), exploitation probability (EPSS), and known-exploited status (CISA KEV)
8. **Validation** — false-positive filtering based on evidence quality and confidence signals
9. **Scoring** — a weighted risk score (0–100) combining severity, exploitability, and exposure
10. **Reporting** — export findings as PDF, HTML, CSV, or JSON

Live scan progress streams to the frontend over WebSockets in real time.

## Tech stack

**Backend:** FastAPI, SQLAlchemy, Alembic, PostgreSQL, Celery, Redis, APScheduler
**Frontend:** React, Vite, Tailwind CSS, Zustand, Recharts
**Scanners:** subfinder, amass, masscan, nmap, httpx, katana, nuclei, ffuf, sqlmap, dalfox, trufflehog, linkfinder, gowitness
**Enrichment:** NVD API, FIRST.org EPSS API, CISA KEV catalog

The FastAPI process and Celery worker run as separate processes and communicate scan progress via Redis pub/sub, since the worker has no direct access to the API's WebSocket connections.

## Setup

**Prerequisites:** Python 3.13, Node 20+, PostgreSQL, Redis, and the scanner binaries listed above installed on your system (or use the provided Docker setup — see below).

```bash
# Clone
git clone https://github.com/shreyaschanda23-sys/vuln-platform.git
cd vuln-platform

# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp ../.env.example ../.env
# edit .env with your DB/Redis credentials

alembic upgrade head
python scripts/create_admin.py   # create your first admin user

# Terminal 1: API
uvicorn main:app --reload

# Terminal 2: worker
celery -A worker.celery.celery_app worker --loglevel=info

# Frontend
cd ../frontend
npm install
npm run dev
```

Visit `http://localhost:5173` and log in with the admin account you created.

### Docker

A `docker-compose.yml` is included covering Postgres, Redis, backend, worker, and frontend. `docker-compose up` works for the backend, frontend, Postgres, and Redis services. The worker image (which compiles 13 scanner binaries) currently has a known incomplete tool install — see `docker/Dockerfile.worker` for status.

## A note on scope

This tool sends real network traffic (port scans, HTTP requests, fuzzing) to whatever domain you point it at. **Only scan domains you own or have explicit authorization to test.** Scanning third parties without permission may violate computer misuse laws depending on your jurisdiction.

## License

MIT — see [LICENSE](LICENSE) for details.
