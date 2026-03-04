import json
from typing import List, Dict, Any
from fastapi import APIRouter, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db.models import Case, Event
from app.core.normalize import normalize_event

router = APIRouter()

def _read_events_from_upload(contents: bytes) -> List[Dict[str, Any]]:
    text = contents.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    # Accept JSON array OR JSON lines
    if text.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("JSON must be an array of events.")
        return data

    # JSON lines
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events

@router.post("/file")
async def ingest_file(case_name: str, file: UploadFile = File(...)):
    contents = await file.read()
    try:
        raw_events = _read_events_from_upload(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON input: {e}")

    if not raw_events:
        raise HTTPException(status_code=400, detail="No events found in file.")

    db: Session = SessionLocal()
    try:
        c = Case(name=case_name)
        db.add(c)
        db.commit()
        db.refresh(c)

        normed = [normalize_event(obj) for obj in raw_events]
        for e in normed:
            db.add(Event(
    case_id=c.id,
    ts=e["ts"],
    host=e["host"],
    channel=e["channel"],
    event_id=e["event_id"],
    level=e["level"],
    user=e["user"],
    src_ip=e["src_ip"],
    process_name=e["process_name"],
    command_line=e["command_line"],
    parent_process=e["parent_process"],
    logon_type=e["logon_type"],
    raw_json=e["raw_json"],
))
        db.commit()

        return {"case_id": c.id, "ingested_events": len(normed)}
    finally:
        db.close()