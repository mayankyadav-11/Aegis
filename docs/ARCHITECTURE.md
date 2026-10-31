# AEGIS 2.0 — Architecture & Specifications

## Overview
AEGIS is an AI-powered phishing and scam detection platform targeting digital threats across Email, SMS, URLs, and Instant Messages (with special focus on Indian threat vectors: KYC freeze scams, UPI refund bait, electricity disconnection threats, and government impersonation).

## Directory Structure
* `frontend/`: Next.js (App Router), TypeScript, Tailwind CSS, and shadcn/ui application.
* `backend/`: Python + FastAPI detection pipeline, ML classifiers, and Link Inspector (Phase B1 onwards).
* `docs/`: System documentation, data contracts, and specifications.

## Shared Data Contract (PRD Section 8)
Every analysis endpoint adheres to the canonical `AnalysisResult` schema:
* `case_id`: Unique identifier (e.g. `AEG-2026-0001`).
* `input_type`: `email | sms | url | message | text`.
* `risk_score`: 0–100 risk indicator score.
* `risk_level`: `low | medium | high | critical`.
* `verdict`: `safe | suspicious | malicious`.
* `signal_scores`: Breakdown across `nlp`, `url`, `sender`, `email_auth`, and `context`.
* `findings`: Array of granular explainable findings with category, severity, evidence, explanation, and action.
* `link_trail`: Safe server-side redirect hops, landing page status, and flagged form elements.
* `highlights`: Extracted substring ranges tagged with threat categories.
* `evidence_hash`: Canonical SHA-256 digest of the investigation report for tamper verification.

