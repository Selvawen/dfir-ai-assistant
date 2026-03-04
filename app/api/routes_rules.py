from fastapi import APIRouter
from app.core.rules_engine import load_rules

router = APIRouter()


@router.get("/")
def list_rules():
    rules, manifest, report = load_rules("rules")
    # Return only “catalog” fields for listing
    catalog = []
    for r in rules:
        catalog.append({
            "id": r.get("id", ""),
            "title": r.get("title", ""),
            "severity": r.get("severity", ""),
            "description": r.get("description", ""),
            "mitre": r.get("mitre", []),
        })
    return {
        "pack": manifest.get("pack", {}),
        "rules_loaded": len(rules),
        "rules": catalog,
        "validation": report,
    }


@router.get("/validate")
def validate_rules():
    rules, manifest, report = load_rules("rules")
    ok = all(item.get("ok") for item in report) if report else True
    return {"pack": manifest.get("pack", {}), "ok": ok, "validation": report, "rules_loaded": len(rules)}

