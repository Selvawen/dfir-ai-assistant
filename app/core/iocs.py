from typing import List, Dict, Any
from collections import Counter
import re
import base64

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _try_decode_powershell_encoded(cmd: str) -> str:
    """
    Tries to decode PowerShell -enc/-EncodedCommand payloads (usually UTF-16LE base64).
    Returns decoded string or "".
    """
    if not cmd:
        return ""
    low = cmd.lower()
    if "-enc" not in low and "-encodedcommand" not in low:
        return ""

    parts = cmd.split()
    # naive: find token after -enc or -encodedcommand
    for i, p in enumerate(parts):
        pl = p.lower()
        if pl in {"-enc", "-encodedcommand"} and i + 1 < len(parts):
            b64 = parts[i + 1].strip("\"' ")
            try:
                raw = base64.b64decode(b64)
                # PowerShell commonly uses UTF-16LE
                try:
                    decoded = raw.decode("utf-16le", errors="ignore")
                    decoded = decoded.replace("\x00", "")
                    return decoded
                except Exception:
                    return raw.decode("utf-8", errors="replace")
            except Exception:
                return ""
    return ""


def extract_iocs(events: List[Dict[str, Any]], top_n: int = 10) -> Dict[str, Any]:
    ips = []
    users = []
    hosts = []
    procs = []
    cmdlines = []
    urls = []

    for e in events:
        h = e.get("host") or ""
        u = e.get("user") or ""
        ip = e.get("src_ip") or ""
        p = e.get("process_name") or ""
        cl = e.get("command_line") or ""

        if h and h != "unknown":
            hosts.append(h)
        if u and u != "unknown":
            users.append(u)
        if ip:
            ips.append(ip)
        if p:
            procs.append(p.lower())
        if cl:
            cmdlines.append(cl)

            decoded = _try_decode_powershell_encoded(cl)
            if decoded:
                # treat decoded content like a “virtual command line” for IOC extraction
                cmdlines.append(f"[decoded] {decoded[:250]}")
                if "http://" in decoded.lower() or "https://" in decoded.lower():
                    for token in decoded.split():
                        t = token.strip("\"'()[]{}<>;,")
                        if t.lower().startswith("http://") or t.lower().startswith("https://"):
                            urls.append(t)
                for m in IP_RE.findall(decoded):
                    ips.append(m)

            # Pull URLs (simple heuristic)
            if "http://" in cl.lower() or "https://" in cl.lower():
                # naive split
                for token in cl.split():
                    t = token.strip("\"'()[]{}<>;,")
                    if t.lower().startswith("http://") or t.lower().startswith("https://"):
                        urls.append(t)

            # Also grab IPs embedded in command line
            for m in IP_RE.findall(cl):
                ips.append(m)

    return {
        "top_hosts": Counter(hosts).most_common(top_n),
        "top_users": Counter(users).most_common(top_n),
        "top_src_ips": Counter(ips).most_common(top_n),
        "top_processes": Counter(procs).most_common(top_n),
        "top_command_lines": Counter(cmdlines).most_common(min(5, top_n)),
        "urls": Counter(urls).most_common(top_n),
    }