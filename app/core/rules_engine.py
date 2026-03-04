from __future__ import annotations
from typing import Any, Dict, List, Tuple
import os
import yaml

Rule = Dict[str, Any]

REQUIRED_RULE_KEYS = {"id", "title", "severity", "match"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_OPS = {"equals", "contains", "contains_any"}

def load_manifest(rules_dir: str = "rules") -> Dict[str, Any]:
    path = os.path.join(rules_dir, "manifest.yml")
    if not os.path.isfile(path):
        return {"pack": {"name": "Unnamed Pack", "version": "0.0.0"}, "rules": []}
    with open(path, "r", encoding="utf-8") as f:
        m = yaml.safe_load(f) or {}
    m.setdefault("pack", {"name": "Unnamed Pack", "version": "0.0.0"})
    m.setdefault("rules", [])
    return m


def validate_rule(rule: Rule) -> List[str]:
    errors: List[str] = []

    missing = REQUIRED_RULE_KEYS - set(rule.keys())
    if missing:
        errors.append(f"Missing required keys: {sorted(list(missing))}")

    sev = str(rule.get("severity", "")).lower()
    if sev and sev not in ALLOWED_SEVERITIES:
        errors.append(f"Invalid severity '{rule.get('severity')}'. Allowed: {sorted(list(ALLOWED_SEVERITIES))}")

    match = rule.get("match")
    if not isinstance(match, dict):
        errors.append("match must be an object containing 'all' or 'any'")
        return errors

    if "all" not in match and "any" not in match:
        errors.append("match must include 'all' or 'any'")
        return errors

    block_key = "all" if "all" in match else "any"
    conds = match.get(block_key)
    if not isinstance(conds, list) or not conds:
        errors.append(f"match.{block_key} must be a non-empty list")
        return errors

    for i, c in enumerate(conds):
        if not isinstance(c, dict):
            errors.append(f"Condition #{i} must be an object")
            continue
        if "field" not in c or "op" not in c or "value" not in c:
            errors.append(f"Condition #{i} must include field/op/value")
            continue
        if c["op"] not in ALLOWED_OPS:
            errors.append(f"Condition #{i} has invalid op '{c['op']}'. Allowed: {sorted(list(ALLOWED_OPS))}")
        if c["op"] == "contains_any" and not isinstance(c["value"], list):
            errors.append(f"Condition #{i} op contains_any requires value to be a list")

    return errors


def load_rules(rules_dir: str = "rules") -> Tuple[List[Rule], Dict[str, Any], List[Dict[str, Any]]]:
    """
    Returns: (rules, manifest, validation_report)
    validation_report items: {file, rule_id?, ok, errors[]}
    """
    manifest = load_manifest(rules_dir)
    rules: List[Rule] = []
    report: List[Dict[str, Any]] = []

    # Prefer explicit manifest list if present
    files = manifest.get("rules") or []
    if not files:
        # fallback: load all yaml files except manifest
        files = [f for f in os.listdir(rules_dir) if f.endswith((".yml", ".yaml")) and f != "manifest.yml"]

    for name in files:
        path = os.path.join(rules_dir, name)
        if not os.path.isfile(path):
            report.append({"file": name, "ok": False, "errors": ["File not found"]})
            continue

        with open(path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f) or {}

        errs = validate_rule(rule)
        rid = rule.get("id", "")
        if errs:
            report.append({"file": name, "rule_id": rid, "ok": False, "errors": errs})
            continue

        report.append({"file": name, "rule_id": rid, "ok": True, "errors": []})
        rules.append(rule)

    return rules, manifest, report


def _get_field(event: Dict[str, Any], field: str) -> str:
    v = event.get(field, "")
    return "" if v is None else str(v)


def _op_equals(val: str, rule_val: str) -> bool:
    return val.lower() == str(rule_val).lower()


def _op_contains(val: str, needle: str) -> bool:
    return needle.lower() in val.lower()


def _op_contains_any(val: str, needles: List[str]) -> bool:
    low = val.lower()
    return any(str(n).lower() in low for n in needles)


def _match_condition(event: Dict[str, Any], cond: Dict[str, Any]) -> bool:
    field = cond["field"]
    op = cond["op"]
    rule_val = cond.get("value", "")

    val = _get_field(event, field)

    if op == "equals":
        return _op_equals(val, str(rule_val))
    if op == "contains":
        return _op_contains(val, str(rule_val))
    if op == "contains_any":
        if not isinstance(rule_val, list):
            return False
        return _op_contains_any(val, rule_val)

    # Unknown operator => fail closed
    return False


def _match_block(event: Dict[str, Any], block: Dict[str, Any]) -> bool:
    if "all" in block:
        return all(_match_condition(event, c) for c in block["all"])
    if "any" in block:
        return any(_match_condition(event, c) for c in block["any"])
    return False


def run_rules(events: List[Dict[str, Any]], rules: List[Rule]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    for rule in rules:
        block = rule.get("match", {})
        matched = [e for e in events if _match_block(e, block)]

        if matched:
            detections.append({
                "title": rule.get("title", "Rule Match"),
                "severity": str(rule.get("severity", "low")).lower(),
                "mitre": rule.get("mitre", []),
                "rule_id": rule.get("id", ""),
                "description": rule.get("description", ""),
                "evidence_events": matched[:100],
            })
    return detections

