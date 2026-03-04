from typing import List, Dict, Any
from app.core.mitre import (
    mitre_for_bruteforce,
    mitre_for_encoded_powershell,
    mitre_for_lolbin,
    mitre_for_remote_logon,
    mitre_for_service_creation,
    mitre_for_schtask,
)

LOL_BINS = {
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "certutil.exe",
}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

def _contains_any(s: str, needles: List[str]) -> bool:
    sl = (s or "").lower()
    return any(n.lower() in sl for n in needles)

def detect(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    dets: List[Dict[str, Any]] = []

    # --- Brute force-ish: 4625 failed logons
    failed = [e for e in events if e["event_id"] == "4625"]
    if len(failed) >= 10:
        dets.append({
            "title": "High volume failed logons (possible brute force)",
            "severity": "high",
            "mitre": mitre_for_bruteforce(),
            "evidence_events": failed[:100],
        })

    # --- Remote logon (4624) + lateral movement heuristic
    # Note: Windows Security 4624 LogonType:
    # 3 = Network, 10 = RemoteInteractive (RDP)
    remote_logons = [
        e for e in events
        if e["event_id"] == "4624" and e.get("logon_type") in {"3", "10"}
    ]

    # Group remote logons by user
    user_to_hosts = {}
    for e in remote_logons:
        u = e.get("user", "unknown")
        user_to_hosts.setdefault(u, set()).add(e.get("host", "unknown"))

    suspicious_spread_users = [u for u, hs in user_to_hosts.items() if len(hs) >= 2 and u != "unknown"]
    if suspicious_spread_users:
        ev = [e for e in remote_logons if e.get("user") in suspicious_spread_users]
        dets.append({
            "title": "Same user remote-logged into multiple hosts (possible lateral movement)",
            "severity": "high",
            "mitre": mitre_for_remote_logon(),
            "evidence_events": ev[:120],
        })

    # --- Service creation (7045) after remote logons is a strong lateral movement / persistence hint
    svc = [e for e in events if e["event_id"] == "7045"]
    if svc:
        dets.append({
            "title": "New Windows service created (possible persistence / remote execution)",
            "severity": "high",
            "mitre": mitre_for_service_creation(),
            "evidence_events": svc[:80],
        })

    # --- Scheduled task (4698)
    task = [e for e in events if e["event_id"] == "4698"]
    if task:
        dets.append({
            "title": "Scheduled task created (possible persistence)",
            "severity": "medium",
            "mitre": mitre_for_schtask(),
            "evidence_events": task[:80],
        })

    # --- Sysmon process creation (EventID 1 in many exports)
    proc_events = [e for e in events if e["event_id"] in {"1", "Sysmon-1"} or (e.get("channel","").lower() == "sysmon" and e.get("event_id") == "1")]

    # Encoded PowerShell
    enc_ps = [
        e for e in proc_events
        if (e.get("process_name") or "").lower() == "powershell.exe"
        and _contains_any(e.get("command_line",""), ["-enc", "-encodedcommand", "frombase64string", "iex", "downloadstring"])
    ]
    if enc_ps:
        dets.append({
            "title": "Suspicious PowerShell command line (encoded / download / IEX patterns)",
            "severity": "high",
            "mitre": mitre_for_encoded_powershell(),
            "evidence_events": enc_ps[:80],
        })

    # Office spawning script engines / LOLBins
    office_spawn = [
        e for e in proc_events
        if (e.get("parent_process") or "").lower() in OFFICE_PARENTS
        and (e.get("process_name") or "").lower() in {"powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
    ]
    if office_spawn:
        dets.append({
            "title": "Office application spawned a scripting/LOLBIN process (possible phishing/macro chain)",
            "severity": "high",
            "mitre": mitre_for_lolbin(),
            "evidence_events": office_spawn[:80],
        })

    # Generic LOLBin usage
    lolbin = [
        e for e in proc_events
        if (e.get("process_name") or "").lower() in LOL_BINS
        and _contains_any(e.get("command_line",""), ["http", "https", "download", "payload", "base64", "invoke"])
    ]
    if lolbin:
        dets.append({
            "title": "Suspicious LOLBin usage (command line indicates download/execute behavior)",
            "severity": "medium",
            "mitre": mitre_for_lolbin(),
            "evidence_events": lolbin[:80],
        })

    return dets