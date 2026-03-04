from typing import List, Dict, Any

SEV_POINTS = {"low": 8, "medium": 18, "high": 30, "critical": 45}


def score_case(detections: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = 0

    # Base: unique detections matter more than raw count
    score += sum(SEV_POINTS.get(d["severity"], 8) for d in detections)

    hosts = {e["host"] for e in events if e.get("host") and e.get("host") != "unknown"}
    users = {e["user"] for e in events if e.get("user") and e.get("user") != "unknown"}

    # Scope boosts
    if len(hosts) >= 2:
        score += 10
    if len(hosts) >= 5:
        score += 10

    # Strong behavior boosts
    titles = " ".join([d["title"].lower() for d in detections])
    if "encoded" in titles or "powershell" in titles:
        score += 10
    if "service" in titles and "created" in titles:
        score += 10
    if "lateral movement" in titles:
        score += 10
    if "brute force" in titles:
        score += 8

    # Cap
    score = min(100, score)

    label = "low"
    if score >= 85: label = "critical"
    elif score >= 65: label = "high"
    elif score >= 35: label = "medium"

    confidence = "medium"
    if len(detections) >= 4:
        confidence = "high"
    if len(events) > 200:
        confidence = "high"

    return {
        "score": score,
        "label": label,
        "confidence": confidence,
        "hosts": sorted(list(hosts)),
        "users": sorted(list(users)),
    }