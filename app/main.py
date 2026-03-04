from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.api.routes_ingest import router as ingest_router
from app.api.routes_cases import router as cases_router
from app.api.routes_rules import router as rules_router
from app.api.routes_ui import router as ui_router
from app.db.session import init_db

app = FastAPI(title="DFIR AI Assistant (Local MVP)", version="0.1.0")

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(ingest_router, prefix="/ingest", tags=["ingest"])
app.include_router(cases_router, prefix="/cases", tags=["cases"])
app.include_router(rules_router, prefix="/rules", tags=["rules"])
app.mount("/static", StaticFiles(directory="ui/static"), name="static")
app.include_router(ui_router, tags=["ui"])

@app.get("/")
def root():
    return {"ok": True, "service": "dfir-ai-assistant", "version": "0.1.0"}


@app.get("/status")
def status():
    # lightweight health/status endpoint (useful for deployments later)
    return {"status": "ok", "service": "dfir-ai-assistant"}