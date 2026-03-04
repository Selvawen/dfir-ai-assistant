from typing import List, Dict, Any


def recommend_actions(detections: List[Dict[str, Any]]) -> List[str]:
    titles = " ".join(d["title"].lower() for d in detections)

    actions = []
    if "failed logons" in titles or "brute force" in titles:
        actions.append("Review authentication logs for the source IP(s); consider blocking or rate-limiting; verify whether the account had a valid password compromise attempt.")
    if "lateral movement" in titles or "remote-logged" in titles:
        actions.append("Validate whether remote logons were expected; confirm the source host; check for additional touched hosts and remote execution tooling.")
    if "service created" in titles:
        actions.append("Identify the created service name/path; validate its binary; disable and remove if unauthorized; review SCM/service creation logs for parent process context.")
    if "powershell" in titles or "encoded" in titles:
        actions.append("Collect PowerShell operational logs if available; decode and review the payload; isolate host if execution is unauthorized; hunt for download/execution follow-ons.")
    if "office application spawned" in titles:
        actions.append("Review email and document origin; check for macro execution indicators; quarantine the document and scan endpoints for similar artifacts.")

    if not actions:
        actions.append("No specific response actions were triggered by the current detections. Consider expanding telemetry coverage and rerunning analysis.")

    return actions


def likely_happened(detections: List[Dict[str, Any]]) -> str:
    titles = " ".join(d["title"].lower() for d in detections)

    parts = []
    if "failed logons" in titles:
        parts.append("A burst of failed logon attempts suggests password guessing or scripted authentication attempts.")
    if "remote-logged into multiple hosts" in titles:
        parts.append("The same account accessed multiple hosts via remote logon, consistent with lateral movement or admin pivoting.")
    if "service created" in titles:
        parts.append("A new Windows service was created, which can indicate persistence or remote execution via service control mechanisms.")
    if "suspicious powershell" in titles:
        parts.append("Encoded PowerShell activity suggests obfuscated scripting and potential download/execute behavior.")
    if "office application spawned" in titles:
        parts.append("Office spawning a scripting process can indicate a phishing/macro execution chain.")

    if not parts:
        return "No clear incident narrative could be inferred from the current detection set."

    return " ".join(parts)

