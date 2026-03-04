import json
from typing import Any, Dict

def _get(d: Dict[str, Any], *keys, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default

def _lower(s: Any) -> str:
    return "" if s is None else str(s).lower()

def normalize_event(obj: Dict[str, Any]) -> Dict[str, str]:
    """
    Normalizes Windows Security + Sysmon + generic JSON/EDR exports.
    """
    ts = _get(obj, "Timestamp", "timestamp", "TimeCreated", "time", "EventTime", default="")

    host = _get(obj, "DeviceName", "Computer", "Hostname", "host", default="unknown")

    # Channel/log name varies
    channel = _get(obj, "Channel", "channel", "LogName", "provider", default="unknown")

    # Event ID can be int/str or nested for Sysmon-like objects
    event_id = _get(obj, "EventID", "event_id", "Id", "EventId", default="unknown")
    event_id = str(event_id)

    level = _get(obj, "Level", "level", "Severity", default="unknown")

    # User fields vary
    user = _get(
        obj,
        "InitiatingProcessAccountName",
        "AccountName",
        "SubjectUserName",
        "User",
        "user",
        "UserName",
        default="unknown",
    )

    # Source IP fields vary
    src_ip = _get(obj, "IpAddress", "SourceIp", "src_ip", "RemoteIP", "RemoteAddress", default="")
    src_ip = "" if src_ip is None else str(src_ip)

    # Process fields (Sysmon/EDR)
    process_name = _get(
        obj,
        "Image",                 # Sysmon often uses full path in Image
        "ProcessName",
        "process_name",
        "InitiatingProcessFileName",
        default="",
    )
    process_name = "" if process_name is None else str(process_name)

    # If Image is a path, keep just the leaf name for matching
    if "\\" in process_name:
        process_leaf = process_name.split("\\")[-1]
    else:
        process_leaf = process_name

    command_line = _get(
        obj,
        "CommandLine",
        "command_line",
        "InitiatingProcessCommandLine",
        default="",
    )
    command_line = "" if command_line is None else str(command_line)

    parent_process = _get(
        obj,
        "ParentImage",
        "ParentProcessName",
        "parent_process",
        "InitiatingProcessParentFileName",
        default="",
    )
    parent_process = "" if parent_process is None else str(parent_process)
    if "\\" in parent_process:
        parent_leaf = parent_process.split("\\")[-1]
    else:
        parent_leaf = parent_process

    # Logon type (Windows Security)
    logon_type = _get(obj, "LogonType", "logon_type", default="")
    logon_type = "" if logon_type is None else str(logon_type)

    return {
        "ts": str(ts),
        "host": str(host),
        "channel": str(channel),
        "event_id": event_id,
        "level": str(level),
        "user": str(user),
        "src_ip": src_ip,
        "process_name": process_leaf,
        "command_line": command_line,
        "parent_process": parent_leaf,
        "logon_type": logon_type,
        "raw_json": json.dumps(obj, ensure_ascii=False),
    }