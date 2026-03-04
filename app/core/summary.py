from typing import List, Dict, Any
from collections import Counter

def summarize(detections: List[Dict[str, Any]], score: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    if not events:
        return "No events were provided."

    # Basic timeline bounds
    ts_sorted = sorted([e.get("ts","") for e in events if e.get("ts")])
    start = ts_sorted[0] if ts_sorted else "unknown"
    end = ts_sorted[-1] if ts_sorted else "unknown"

    hosts = sorted({e.get("host","unknown") for e in events if e.get("host")})
    users = [e.get("user","unknown") for e in events if e.get("user") and e.get("user") != "unknown"]
    top_user = Counter(users).most_common(1)[0][0] if users else "unknown"

    top_titles = [d["title"] for d in detections[:5]]

    lines = []
    lines.append(f"Case risk is **{score['label']}** (score {score['score']}/100).")
    lines.append(f"Time window: {start} → {end}.")
    lines.append(f"Scope: {len(hosts)} host(s). Primary account observed: `{top_user}`.")
    lines.append("")
    lines.append("Top findings:")
    for t in top_titles[:3]:
        lines.append(f"- {t}")

    return "\n".join(lines)