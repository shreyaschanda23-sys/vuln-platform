from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings

from api.routes import auth, domains, scans, findings, reports
from api.routes.websocket import router as websocket_router

app = FastAPI(
    title="Vuln Platform",
    description="Automated vulnerability management platform",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(websocket_router)


@app.get("/")
def root():
    return {"status": "ok", "message": "Vuln Platform API running"}


@app.get("/health")
def health():
    return {"status": "healthy"}