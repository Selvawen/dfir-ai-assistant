from typing import List, Dict, Any


def categorize_detection(title: str) -> str:
    t = (title or "").lower()

    # Auth / Credential access / brute force
    if "failed logon" in t or "brute force" in t or "logon" in t:
        return "Auth"

    # Lateral movement / remote services
    if "lateral" in t or "remote-logged" in t or "remote logon" in t:
        return "Lateral"

    # Execution / scripting / LOLBins
    if "powershell" in t or "lolbin" in t or "office application spawned" in t or "command line" in t:
        return "Execution"

    # Persistence
    if "service created" in t or "scheduled task" in t or "persistence" in t:
        return "Persistence"

    return "Other"


def top_category(detections: List[Dict[str, Any]]) -> str:
    """
    Returns the highest-priority category seen in detections.
    Priority order chosen to match SOC triage feel.
    """
    if not detections:
        return "None"

    cats = {categorize_detection(d.get("title", "")) for d in detections}

    priority = ["Execution", "Persistence", "Lateral", "Auth", "Other"]
    for p in priority:
        if p in cats:
            return p
    return "Other"


def categories_present(detections: List[Dict[str, Any]]) -> List[str]:
    if not detections:
        return ["None"]

    cats = sorted({categorize_detection(d.get("title", "")) for d in detections})
    # SOC-friendly order
    order = {"Execution": 0, "Persistence": 1, "Lateral": 2, "Auth": 3, "Other": 4}
    cats.sort(key=lambda c: order.get(c, 99))
    return cats

