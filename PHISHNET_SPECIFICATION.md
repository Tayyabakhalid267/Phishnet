<!--
PHISHNET Specification
Generated: concise, developer-oriented specification document for the PHISHNET project.
Saved at repo root as PHISHNET_SPECIFICATION.md
-->
# PHISHNET — Complete Specification

Version: 1.0

Last updated: 2025-11-04

## Overview

PHISHNET is an AI-powered phishing detection, analysis, visualization, and response platform. It supports multi-channel ingestion (email, URL, files), real-time analysis using ensemble AI models and heuristics, and a SOC/admin UI for visualization, triage, and historical forensics.

This specification documents functional and non-functional requirements, API contracts, data models, UI/UX expectations, AI model specifications, security controls, deployment and testing guidance, monitoring, and acceptance criteria.

## Goals and Success Criteria

- Detect phishing campaigns across email, links, and attachments with high precision and recall for common phishing patterns.
- Deliver actionable analysis (threat level, supporting evidence) to analysts with explainability hints.
- Provide scalable ingestion and analysis pipelines suitable for enterprise usage.
- Maintain secure handling of potentially sensitive data with role-based access and optional client-side zero-knowledge mode.

Success metrics:
- Detection precision >= 90% and recall >= 85% on representative internal test sets (MVP target).
- End-to-end median analysis latency: < 2s for URL checks, < 6s for email (non-attachment), < 30s for file attachments (sandboxed or remote analysis pipeline).

## Actors & Roles

- Anonymous / Dev User: quick local scans using localStorage-based dev auth.
- Registered User: analyst or general user who can submit scans and view personal activity.
- Analyst: can triage, annotate, and escalate findings.
- Admin: role-based access to system configuration, user management, and global analytics.

## Functional Requirements

1. Ingestion
   - Email upload: accept .eml, .msg, .txt with multipart headers and body preserved.
   - Copy-paste analyzer: accept raw headers and body text.
   - Link scanner: bulk URLs; each URL queued for analysis.
   - Attachment scanning: accept PDF, DOCX, ZIP, images; extract artifacts for analysis.
   - Inbox integration (MVP opt): IMAP/OAuth connectors for periodic ingest.

2. Analysis
   - NLP social-engineering analysis (subject/body/headers).
   - URL/domain analysis (DNS, WHOIS, SSL cert checks, redirection chain analysis).
   - Attachment static analysis (signature lookups, metadata, heuristics) and optional sandbox detonation pipeline.
   - Header forensics (DKIM, SPF, DMARC validation and trust scoring).
   - Threat Intelligence enrichment (VirusTotal, PhishTank, AbuseIPDB, optional).
   - Ensemble scoring that combines heuristics, ML classifiers and reputation signals to produce: threat_level (LOW/MEDIUM/HIGH), threat_score (0-100), and a structured evidence list.

3. UI & Workflows
   - Submit scans and view results with clear evidence and recommended next steps.
   - Admin dashboard: live feed, user activity, aggregate metrics (top domains, top senders, trends), and global threat map visualization.
   - User activity/history and ability to export findings (CSV/JSON).
   - Role-based access controls (Admin, Analyst, Viewer).

4. Logging & Audit
   - Per-user activity logs (in local development via `localStorage` keys: `phishnet_user`, `phishnet_registered_users`, `phishnet_user_activity`, and `phishnet_user_activity_<ID>`).
   - Server-side request and analysis logs with safe redaction for PII when configured.

## Non-Functional Requirements

- Performance: scale to hundreds of concurrent URL scans and dozens of email scans per minute on commodity VM clusters.
- Availability: 99.5% for core services in production.
- Security: secrets in environment variables or secret manager; HTTPS enforced; RBAC for admin APIs.
- Privacy: optional zero-knowledge client-side encryption mode for GDPR-sensitive deployments.

## API Contracts

Base assumptions: backend served on `NEXT_PUBLIC_API_URL` (frontend env defaults to http://localhost:8005 in this repo). Use JSON over HTTPS in production.

1. POST /analyze/url
   - Request JSON:
     - url: string
     - userId?: string
     - metadata?: object
   - Response JSON:
     - id: string (analysis id)
     - threat_level: "LOW" | "MEDIUM" | "HIGH"
     - threat_score: number (0-100)
     - evidence: Array<{ type: string, description: string, detail?: any }>
     - model_versions: object

2. POST /analyze/email
   - Request: multipart/form-data or JSON with { raw_email: string, attachments?: [] }
   - Response: same shape as /analyze/url plus header_forensics structure

3. POST /analyze/file
   - Request: file upload (multipart/form-data), userId optional
   - Response: analysis object, may include sandbox verdict or a pending status and callback URL

4. GET /analytics/dashboard
   - Query params: timeframe=24h|7d|30d, topN
   - Response: aggregated metrics (counts, top domains, top senders, trending clusters)

5. WebSocket /ws or /ws/feeds
   - For live feed updates (new analysis results, alerts). Messages: standardized event envelope { type, ts, payload }

Authentication
\- Dev mode: localStorage user tokens for frontend; production: JWT Bearer tokens with refresh, issued by auth router.

## Data Models (simplified)

User
\- id: string
\- username: string
\- email: string
\- role: enum(Admin, Analyst, Viewer)

ScanResult
\- id: string
\- submitted_by: user id
\- type: enum(url,email,file)
\- input: object (url, raw_email, file metadata)
\- threat_level: LOW|MEDIUM|HIGH
\- threat_score: number
\- evidence: array
\- model_versions: object
\- created_at, updated_at

Activity (for localStorage dev logging)
\- userId: string
\- action: string (scan_submitted, scan_result_viewed, login)
\- meta: object
\- ts: ISO timestamp

## AI Model Specifications

1. Inputs & Features
   - Text: subject, body, headers, extracted text from attachments
   - URL features: domain age, certificate validity, redirection counts, Levenshtein distance to brand names, path entropy
   - Behavioral: sender history, time-of-day anomalies
   - Visual: screenshots of pages (for fake page detection) as CNN input

2. Model Types / Ensemble
   - Transformer-based classifier (DistilBERT/miniLM) for social-engineering detection; fine-tuned with phishing corpora.
   - Sentence-transformer embeddings for semantic similarity and clustering.
   - Gradient boosting model (LightGBM/XGBoost) for tabular signals (DNS, TF, header heuristics).
   - CNN-based model for rendered page image classification.
   - Final ensemble meta-learner that combines model outputs and produces calibrated probability -> threat_score.

3. Outputs & Explainability
   - Per-model scores and top contributing features.
   - Human-readable evidence list (e.g., "Sender domain age < 6 months", "Subject uses urgent call-to-action", "Certificate mismatches brand domain").

4. Versioning & Retraining
   - Model versions included in response payload. Maintain stable model registry with semantic versioning (major.minor.patch).

## UI / UX Specifications

\- Theme: cyberpunk dark (deep blue background, neon green accents, alert red for high threats).
\- Pages: Landing, Scan (url/email/file), Results, Admin Dashboard, Reports, User Activity.
\- Result view: clear threat_level badge, threat_score gauge (0-100), evidence list with expandable details, action buttons (mark false positive, escalate, export).
\- Admin: searchable live feed, filters (threat_level, source, timeframe), visualizations (time-series, geographic map), user management.

Accessibility
\- Ensure high contrast and keyboard navigable components.

## Security Requirements

\- Secrets: stored in environment variables or secret manager (do not commit keys).
\- Transport: enforce TLS/HTTPS in production, HSTS.
\- Authentication: JWT w/ refresh, role-based authorization on endpoints.
\- Input sanitization: sanitize and safely handle file uploads, HTML rendering (CSP), and attachments. Use sandboxing for any code execution.
\- Data retention: configurable retention policy and PII redaction rules.

## Deployment & Infrastructure

Minimum production components:
\- API service (FastAPI/Uvicorn/Gunicorn behind ASGI) — port 8000/8005.
\- Frontend (Next.js) — served via Vercel/Netlify or behind CDN.
\- Persistent storage: PostgreSQL for user and scan metadata.
\- Cache/queue: Redis for websocket pub/sub, task queue (RQ/Celery) and rate-limiting.
\- Object storage: S3-compatible for attachments/snapshots.
\- Sandbox cluster: optional isolated sandbox VMs/containers for file detonation.
\- Monitoring: Prometheus, Grafana, ELK/Opensearch for logs.

Docker & K8s
\- Provide Dockerfile for API and frontend; Helm charts or Kubernetes manifests for production clusters.

Ports (dev defaults used in this repo)
\- Backend: 8005 (enterprise launcher start-up in this workspace)
\- Frontend: 3000 (Next.js dev falls back to 3001 if port 3000 in use)
\- Debug static server: 8080 (dev helper pages)

Environment Variables (core)
\- DATABASE_URL, REDIS_URL, SECRET_KEY, VIRUSTOTAL_API_KEY, PHISHTANK_API_KEY, NEXT_PUBLIC_API_URL, NEXT_PUBLIC_WEBSOCKET_URL

## Testing Strategy

1. Unit tests: Python pytest for backend business logic, TypeScript/Jest for frontend components.
2. Integration tests: API contract tests using pytest + HTTP client, verifying analysis flows and auth.
3. E2E tests: Playwright-based flows for scan submission to result retrieval and admin triage.
4. Model evaluation: holdout datasets, cross-validation, and ongoing drift detection.

Acceptance Test Examples
\- Submit a benign URL and receive LOW threat_level and details within 2s.
\- Submit a known phishing URL (test set) and receive HIGH threat_level with evidence including domain age and reputation match.

## Monitoring, Logging & Alerting

\- Metrics: request latency, analysis latency per type, false positive rate (if labelled), queue length, CPU/GPU utilization for model servers.
\- Logs: structured JSON logs, safe mode for redaction of sensitive fields.
\- Alerts: high error rates, queue backlog thresholds, model performance degradation alerts.

## Operational Playbooks (short)

\- Incident: Stop ingestion if surge of suspicious activity; notify admins; scale analysis workers; begin forensics.
\- Model rollback: keep previous model artifacts and configuration to quickly revert if new model causes regression.

## Privacy & Compliance

\- GDPR: support data export and deletion (right to be forgotten). Offer zero-knowledge encryption mode where raw payloads are stored client-side only.

## Acceptance Criteria (MVP)

1. Basic URL, email, and file scanning flows work end-to-end in dev with expected response contract.
2. Admin dashboard shows live feed & user activity produced by the frontend dev localStorage debug pages.
3. Documentation (this spec + README) is present in the repo and owners can run dev servers using README steps.

## Next Steps & Optional Enhancements

\- Provide DOCX/PDF export of this specification for stakeholder sign-off.
\- Create `start_all.bat` and `start_all.sh` to spin up backend, frontend, and debug servers for convenience in dev.
\- Add CI pipeline (GitHub Actions) with linting, unit tests, and simple integration tests.
\- Harden auth with an identity provider (Keycloak/OAuth2) for enterprise deployments.

---

File saved: `PHISHNET_SPECIFICATION.md` (repo root)

If you'd like, I can also:
\- Export this to DOCX/PDF and place it in the repo.
\- Generate a `start_all.bat` to launch backend, frontend and debug server on Windows.
\- Add a minimal GitHub Actions CI pipeline skeleton.
