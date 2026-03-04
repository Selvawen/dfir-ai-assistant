from typing import List, Dict, Any

def build_timeline(events: List[Dict[str, Any]], limit: int = 200) -> List[Dict[str, Any]]:
    # Sort by timestamp string (works for ISO8601)
    ordered = sorted(events, key=lambda e: e.get("ts", ""))
    return ordered[:limit]

def timeline_markdown(events: List[Dict[str, Any]], limit: int = 120) -> str:
    ordered = build_timeline(events, limit=limit)
    lines = ["# Incident Timeline", ""]
    for e in ordered:
        lines.append(f"- **{e.get('ts','')}** | host={e.get('host','')} | event_id={e.get('event_id','')} | user={e.get('user','')} | src_ip={e.get('src_ip','')}")
    return "\n".join(lines)