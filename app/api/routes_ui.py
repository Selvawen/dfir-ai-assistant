from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.db.models import Case, Event
from app.core.detections import detect
from app.core.scoring import score_case
from app.core.summary import summarize
from app.core.iocs import extract_iocs
from app.core.timeline import build_timeline
from app.core.rules_engine import load_rules, run_rules
from app.core.categorize import top_category, categories_present

router = APIRouter()
templates = Jinja2Templates(directory="ui/templates")


def _load_case_events(db: Session, case_id: int):
    rows = db.query(Event).filter(Event.case_id == case_id).all()
    events = []
    for r in rows:
        events.append({
            "ts": r.ts,
            "host": r.host,
            "channel": r.channel,
            "event_id": r.event_id,
            "level": r.level,
            "user": r.user,
            "src_ip": r.src_ip,
            "process_name": r.process_name,
            "command_line": r.command_line,
            "parent_process": r.parent_process,
            "logon_type": r.logon_type,
        })
    return events


@router.get("/ui", response_class=HTMLResponse)
def ui_home(request: Request, q: str = "", sev: str = "all", sort: str = "newest"):
    db: Session = SessionLocal()
    try:
        query = db.query(Case)

        # If q is numeric, allow exact ID search too
        q_stripped = (q or "").strip()
        if q_stripped:
            if q_stripped.isdigit():
                query = query.filter(Case.id == int(q_stripped))
            else:
                # name contains (case-insensitive)
                query = query.filter(Case.name.ilike(f"%{q_stripped}%"))

        cases = query.order_by(Case.id.desc()).limit(50).all()

        # Rule pack info
        rules, manifest, validation = load_rules("rules")
        pack = (manifest or {}).get("pack", {})

        # Light “preview” scores (optional)
        case_cards = []
        for c in cases:
            events = _load_case_events(db, c.id)
            builtin = detect(events)
            rule_dets = run_rules(events, rules) if rules else []
            dets = builtin + rule_dets
            score = score_case(dets, events)
            category = top_category(dets)
            case_cards.append({
                "id": c.id,
                "name": c.name,
                "status": getattr(c, "status", "Open"),
                "created_at": str(c.created_at),
                "score": score,
                "detections_count": len(dets),
                "hosts": score.get("hosts", []),
                "category": category,
            })

        # --- filter by severity label (based on computed score label)
        sev = (sev or "all").lower().strip()
        sort = (sort or "newest").lower().strip()

        allowed = {"all", "medplus", "highplus", "critical"}
        if sev not in allowed:
            sev = "all"

        def rank(label: str) -> int:
            return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get((label or "").lower(), 0)

        if sev == "medplus":
            case_cards = [c for c in case_cards if rank(c["score"]["label"]) >= 1]
        elif sev == "highplus":
            case_cards = [c for c in case_cards if rank(c["score"]["label"]) >= 2]
        elif sev == "critical":
            case_cards = [c for c in case_cards if rank(c["score"]["label"]) >= 3]

        # --- sorting
        if sort == "score":
            case_cards.sort(key=lambda c: (rank(c["score"]["label"]), c["score"]["score"]), reverse=True)
        else:
            # newest (default) — higher ID = newer
            case_cards.sort(key=lambda c: c["id"], reverse=True)

        return templates.TemplateResponse(
            "home.html",
            {
                "request": request,
                "q": q_stripped,
                "sev": sev,
                "sort": sort,
                "pack": pack,
                "rules_loaded": len(rules),
                "rules_validation": validation,
                "cases": case_cards,
            },
        )
    finally:
        db.close()


@router.get("/ui/cases/{case_id}", response_class=HTMLResponse)
def ui_case(request: Request, case_id: int):
    db: Session = SessionLocal()
    try:
        c = db.query(Case).filter(Case.id == case_id).first()
        if not c:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "message": "Case not found",
            }, status_code=404)

        events = _load_case_events(db, case_id)

        # Detections (builtin + rules)
        rules, manifest, validation = load_rules("rules")
        builtin = detect(events)
        rule_dets = run_rules(events, rules) if rules else []

        # Merge (keep it simple for UI)
        dets = builtin + rule_dets

        cats = categories_present(dets)

        score = score_case(dets, events)
        summary = summarize(dets, score, events)

        iocs = extract_iocs(events, top_n=10)
        timeline = build_timeline(events, limit=80)

        return templates.TemplateResponse(
            "case.html",
            {
                "request": request,
                "case": {"id": c.id, "name": c.name, "created_at": str(c.created_at), "status": getattr(c, "status", "Open")},
                "pack": (manifest or {}).get("pack", {}),
                "score": score,
                "summary": summary,
                "detections": dets,
                "iocs": iocs,
                "timeline": timeline,
                "categories": cats,
            },
        )
    finally:
        db.close()


@router.post("/ui/cases/{case_id}/status")
def ui_set_status(request: Request, case_id: int, status: str = Form(...)):
    allowed = {"Open", "In Progress", "Resolved"}
    if status not in allowed:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "message": "Invalid status",
            },
            status_code=400,
        )

    db: Session = SessionLocal()
    try:
        c = db.query(Case).filter(Case.id == case_id).first()
        if not c:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "message": "Case not found",
                },
                status_code=404,
            )

        c.status = status
        db.commit()
    finally:
        db.close()

    return RedirectResponse(url=f"/ui/cases/{case_id}", status_code=303)

