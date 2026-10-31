"""
AEGIS 2.0 Backend — FastAPI Application Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from config import settings

app = FastAPI(
    title="AEGIS 2.0 — AI Phishing & Scam Detection API",
    description=(
        "Multi-channel phishing detection, threat intelligence, "
        "and digital evidence verification platform."
    ),
    version="0.1.0",
)

# CORS — allow the Next.js frontend during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Session-ID", "X-Storage-Mode", "X-Org-ID", "Content-Disposition"],
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )

