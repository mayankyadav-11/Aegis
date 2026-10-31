# AEGIS 2.0 — Backend Service

This directory is reserved for the AEGIS 2.0 detection and analysis backend.

## Overview
The backend service will be built using **Python** and **FastAPI**, implementing:
* Multi-channel threat detection (Email header forensics, SMS & text analysis, URL lexical inspection, and server-side link inspection).
* ML-driven classification (URL lexical model, TF-IDF + Logistic Regression for NLP, Isolation Forest for anomaly detection).
* Curated Indian brand impersonation registry & Hinglish social-engineering indicators.
* Cryptographic evidence hashing and integrity verification (PRD Section 8 contract).

## Architecture Note
Backend development is decoupled from the frontend application and will be implemented in subsequent phases. No backend code or dependencies are initialized here yet.

