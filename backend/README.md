# AEGIS 2.0 — Backend Service

AI-powered phishing, scam detection, and threat intelligence backend built with **FastAPI**, **Pydantic**, and **Python**.

---

## Architecture Overview

AEGIS 2.0 combines **deterministic, rule-based security engines** with **pretrained Gemini AI** for explainable contextual intelligence:

1. **Deterministic Security Engines (Pure Python):**
   - **Input Normalisation (`core/normalizer.py`):** NFKC Unicode normalisation, invisible zero-width character detection and stripping, homoglyph look-alike character detection, and URL extraction.
   - **URL & SSRF Inspector (`detectors/url_detector.py`):** Lexical feature analysis, suspicious TLD detection, IP literals, shorteners, and guarded redirect following with strict SSRF protection (blocks RFC 1918, loopback, link-local, and cloud metadata 169.254.169.254).
   - **Brand Impersonation Registry (`detectors/brand_detector.py`):** Curated database of trusted Indian and global brands (SBI, HDFC, ICICI, Income Tax Dept, India Post, etc.) to flag typosquatting and deceptive domains.
   - **Indian Social Engineering Engine (`detectors/brand_detector.py`):** Detection of KYC freeze panic, electricity disconnection threats, UPI cashback traps, Telegram task scams, and TRAI non-compliant 10-digit mobile senders.
   - **Email Forensics (`detectors/email_detector.py`):** Display name spoofing, Reply-To mismatches, and honest header parsing (`Authentication-Results`, `Received-SPF`).

2. **Pretrained Gemini Contextual Intelligence (`core/gemini_analyzer.py`):**
   - Executes **one consolidated LLM request** per message.
   - Enforces strict prompt-injection defense (treats all submitted text as untrusted external data).
   - Uses a cost-effective, high-speed Flash model (`gemini-2.5-flash` configurable via environment variables).
   - **Graceful Fallback:** If `GEMINI_API_KEY` is omitted or an API call fails, the backend seamlessly completes analysis using deterministic security findings alone without crashing.

3. **Canonical Data Contract (`schemas.py`):**
   - Implements the PRD Section 8 `AnalysisResponse` schema across all endpoints, ensuring 100% interoperability with the frontend TypeScript layer.

---

## Quick Start

### 1. Set Up Environment

```bash
# Navigate to the backend directory
cd backend

# Create virtual environment (if not already created)
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

```bash
# Copy template
cp .env.example .env
```

Edit `.env` to configure your Gemini API Key:
```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```
*(If left empty, AEGIS automatically operates in deterministic-only fallback mode.)*

### 3. Run Development Server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`. Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### 4. Run Automated Tests

```bash
pytest -v
```

---

## Implemented API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health, active AI model, and detector status |
| `POST` | `/api/analyze/url` | URL lexical & SSRF inspection + brand impersonation |
| `POST` | `/api/analyze/text` | Text & chat message analysis with embedded URL extraction |
| `POST` | `/api/analyze/sms` | SMS analysis with TRAI DLT header & KYC threat checks |
| `POST` | `/api/analyze/email` | Email header forensics, display name spoofing & body inspection |
