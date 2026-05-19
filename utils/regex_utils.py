# utils/regex_utils.py
import json
import re
from pathlib import Path
from typing import Any

RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "rules.json"

DEFAULT_RULES = [
    {
        "rule_id": "CONF_KEYWORD_SENSITIVE",
        "name": "涉密关键词",
        "pattern": "涉密",
        "type": "keyword",
        "risk_level": "high",
        "description": "命中常见保密审计关键词：涉密。"
    },
    {
        "rule_id": "CONF_KEYWORD_SECRET",
        "name": "秘密关键词",
        "pattern": "秘密",
        "type": "keyword",
        "risk_level": "high",
        "description": "命中常见密级标识关键词：秘密。"
    },
    {
        "rule_id": "CONF_KEYWORD_CONFIDENTIAL",
        "name": "机密关键词",
        "pattern": "机密",
        "type": "keyword",
        "risk_level": "high",
        "description": "命中常见密级标识关键词：机密。"
    },
    {
        "rule_id": "CONF_KEYWORD_TOP_SECRET",
        "name": "绝密关键词",
        "pattern": "绝密",
        "type": "keyword",
        "risk_level": "critical",
        "description": "命中常见密级标识关键词：绝密。"
    },
    {
        "rule_id": "CONF_KEYWORD_PROTECT",
        "name": "保密关键词",
        "pattern": "保密",
        "type": "keyword",
        "risk_level": "medium",
        "description": "命中常见保密管理关键词：保密。"
    },
    {
        "rule_id": "CONF_KEYWORD_LEAK",
        "name": "泄密关键词",
        "pattern": "泄密",
        "type": "keyword",
        "risk_level": "high",
        "description": "命中常见泄密风险关键词：泄密。"
    },
]


def _keyword_to_fuzzy_pattern(keyword: str) -> str:
    """
    将关键词转换为模糊匹配正则。
    例如: '绝密' -> '绝[\\s\\W_]*密'
    """
    return r"[\s\W_]*".join(re.escape(ch) for ch in keyword)


def _normalize_rule(raw_rule: dict[str, Any], index: int) -> dict[str, Any] | None:
    pattern = str(raw_rule.get("pattern", "")).strip()
    if not pattern:
        return None

    rule_type = str(raw_rule.get("type", "keyword")).strip().lower()
    if rule_type not in {"keyword", "regex"}:
        rule_type = "keyword"

    return {
        "rule_id": str(raw_rule.get("rule_id") or f"RULE_{index:03d}"),
        "name": str(raw_rule.get("name") or raw_rule.get("rule_id") or f"Rule {index}"),
        "pattern": pattern,
        "type": rule_type,
        "risk_level": str(raw_rule.get("risk_level") or "medium"),
        "description": str(raw_rule.get("description") or ""),
    }


def load_rules(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load audit rules from JSON config, falling back to built-in defaults."""
    rules_file = Path(path) if path else RULES_PATH
    try:
        raw_rules = json.loads(rules_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw_rules = DEFAULT_RULES

    rules = []
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            continue
        rule = _normalize_rule(raw_rule, index)
        if rule:
            rules.append(rule)

    return rules or DEFAULT_RULES


def compile_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compile keyword and regex rules into regex objects."""
    compiled_rules = []
    for rule in rules:
        pattern_text = rule["pattern"]
        if rule["type"] == "keyword":
            pattern_text = _keyword_to_fuzzy_pattern(pattern_text)

        try:
            compiled_pattern = re.compile(pattern_text)
        except re.error:
            continue

        compiled_rule = dict(rule)
        compiled_rule["compiled_pattern"] = compiled_pattern
        compiled_rules.append(compiled_rule)

    return compiled_rules


COMPILED_RULES = compile_rules(load_rules())


def extract_secrets_from_text(text: str, line_num: str | int) -> list[dict[str, str]]:
    """
    扫描传入的一段文本，提取所有涉密信息及其上下文。
    返回字段可直接映射到 ScanResult。
    """
    results = []
    if not text:
        return results

    for rule in COMPILED_RULES:
        pattern = rule["compiled_pattern"]
        for match in pattern.finditer(text):
            found_word = match.group()
            start_idx = match.start()
            end_idx = match.end()

            context_start = max(0, start_idx - 15)
            context_end = min(len(text), end_idx + 15)
            context = text[context_start:context_end].replace('\n', ' ').strip()

            results.append({
                "keyword": found_word,
                "line_number": str(line_num),
                "context": context,
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "risk_level": rule["risk_level"],
                "rule_description": rule["description"],
                "rule_type": rule["type"],
            })

    return results
