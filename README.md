# AEGIS 2.0

> **Detect the Threat. Understand the Risk. Protect the User.**

AEGIS is an AI-powered multi-channel phishing detection, threat intelligence, and digital evidence verification platform. It analyzes suspicious Emails, SMS messages, URLs, and Instant Messages to produce explainable risk scores, threat vector breakdowns, and cryptographic audit proofs.

---

## Repository Structure

```text
Aegis/
├── frontend/               # Next.js 14 App Router, TypeScript, Tailwind CSS
│   ├── app/                # Pages and routing (/dashboard, /analyze, /results, /history, /verify, /redteam)
│   ├── components/         # UI components & Dot-Matrix Hands hero canvas
│   ├── lib/                # API client layer & mock investigation datasets
│   ├── public/             # Static assets (including downloaded hands source sheet)
│   ├── types/              # TypeScript types mirroring PRD Section 8 data contract
│   ├── tailwind.config.js  # AEGIS security console design tokens
│   └── package.json        # Frontend dependencies & scripts
│
├── backend/                # Python + FastAPI backend service (planned)
│   └── README.md           # Architecture and setup guidelines for backend
│
├── docs/                   # System design, data contracts, and architectural specs
│   └── ARCHITECTURE.md     # Architecture overview and PRD data contract summary
│
├── .gitignore              # Repository-wide ignore rules (Node, Python, secrets)
└── README.md               # Project root documentation
```

---

## Quick Start (Frontend)

To run the frontend application locally:

```bash
# 1. Navigate into the frontend directory
cd frontend

# 2. Run the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Tech Stack

* **Frontend:** Next.js (App Router), React, TypeScript, Tailwind CSS, Lucide Icons.
* **Design System:** Jet Black background (`#050507`), Surface cards (`#0D0D12`), Royal Amethyst (`#7B3FE4`), Electric Cyan (`#00E5FF`), and strictly decoupled risk severity indicators.
* **Backend (Upcoming):** Python, FastAPI, Scikit-learn (URL lexical & NLP TF-IDF), Isolation Forest, and guarded Link Inspector.

