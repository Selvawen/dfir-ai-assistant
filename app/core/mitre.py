from typing import List, Dict

def mitre_for_bruteforce() -> List[Dict[str, str]]:
    return [{"technique": "T1110", "name": "Brute Force"}]

def mitre_for_remote_logon() -> List[Dict[str, str]]:
    return [
        {"technique": "T1021", "name": "Remote Services"},
        {"technique": "T1078", "name": "Valid Accounts"},
    ]

def mitre_for_service_creation() -> List[Dict[str, str]]:
    return [{"technique": "T1543.003", "name": "Create or Modify System Process: Windows Service"}]

def mitre_for_schtask() -> List[Dict[str, str]]:
    return [{"technique": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task"}]

def mitre_for_encoded_powershell() -> List[Dict[str, str]]:
    return [{"technique": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"}]

def mitre_for_lolbin() -> List[Dict[str, str]]:
    return [
        {"technique": "T1059", "name": "Command and Scripting Interpreter"},
        {"technique": "T1218", "name": "System Binary Proxy Execution"},
    ]