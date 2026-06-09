# utils/regex_utils.py
import json
import re
from pathlib import Path
from typing import Any, Iterable

RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "rules.json"
DEFAULT_KEYWORDS = ["涉密", "秘密", "机密", "绝密", "保密", "泄密"]
DEFAULT_KEYWORDS_TEXT = ", ".join(DEFAULT_KEYWORDS)

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
    {
        "rule_id": "CONF_REGEX_CLASSIFICATION_MARK",
        "name": "密级格式标识",
        "pattern": r"(秘密|机密|绝密)\s*[★☆\-—_]*\s*(启用前|资料|文件)?",
        "type": "regex",
        "risk_level": "critical",
        "description": "识别类似“绝密★启用前”以及带空格/符号分隔的密级标识。"
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


def _split_user_rule_text(value: str | Iterable[str] | None) -> list[str]:
    """Split GUI input text into individual keyword/regex patterns."""
    if value is None:
        return []
    if isinstance(value, str):
        chunks = re.split(r"[,，;；\n\r]+", value)
    else:
        chunks = list(value)
    seen = set()
    items = []
    for chunk in chunks:
        item = str(chunk).strip()
        if item and item not in seen:
            seen.add(item)
            items.append(item)
    return items


def build_keyword_rules(keywords: str | Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Build the active keyword rule list from user-editable GUI input."""
    keyword_items = _split_user_rule_text(keywords)
    if not keyword_items:
        keyword_items = DEFAULT_KEYWORDS

    rules: list[dict[str, Any]] = []
    for idx, keyword in enumerate(keyword_items, start=1):
        risk = "critical" if keyword == "绝密" else "high" if keyword in {"涉密", "秘密", "机密", "泄密"} else "medium"
        rules.append({
            "rule_id": f"ACTIVE_KEYWORD_{idx:03d}",
            "name": f"检测关键词：{keyword}",
            "pattern": keyword,
            "type": "keyword",
            "risk_level": risk,
            "description": "用户界面中当前启用的检测关键词。",
        })
    return rules


def build_regex_rules(regexes: str | Iterable[str] | None = None,
                      include_default_regex: bool = True) -> list[dict[str, Any]]:
    """Build regex rules from JSON default regex rules plus GUI-entered regexes."""
    rules: list[dict[str, Any]] = []
    if include_default_regex:
        for raw_rule in load_rules():
            if str(raw_rule.get("type", "")).lower() == "regex":
                rules.append(raw_rule)

    for idx, pattern in enumerate(_split_user_rule_text(regexes), start=1):
        rules.append({
            "rule_id": f"USER_REGEX_{idx:03d}",
            "name": f"用户自定义正则 {idx}",
            "pattern": pattern,
            "type": "regex",
            "risk_level": "high",
            "description": "用户在界面中临时添加的正则检测规则。",
        })
    return rules


def build_custom_rules(extra_keywords: str | Iterable[str] | None = None,
                       extra_regexes: str | Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Backward-compatible alias: build rules from GUI-entered keywords and regexes."""
    return build_keyword_rules(extra_keywords) + build_regex_rules(extra_regexes)


def compile_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compile keyword and regex rules into regex objects."""
    compiled_rules = []
    for index, rule in enumerate(rules, start=1):
        normalized = _normalize_rule(rule, index)
        if not normalized:
            continue
        pattern_text = normalized["pattern"]
        if normalized["type"] == "keyword":
            pattern_text = _keyword_to_fuzzy_pattern(pattern_text)

        try:
            compiled_pattern = re.compile(pattern_text)
        except re.error:
            continue

        compiled_rule = dict(normalized)
        compiled_rule["compiled_pattern"] = compiled_pattern
        compiled_rules.append(compiled_rule)

    return compiled_rules


COMPILED_RULES = compile_rules(load_rules())


def configure_runtime_rules(keywords: str | Iterable[str] | None = None,
                            regexes: str | Iterable[str] | None = None,
                            include_default_regex: bool = True,
                            include_default: bool | None = None,
                            extra_keywords: str | Iterable[str] | None = None,
                            extra_regexes: str | Iterable[str] | None = None) -> int:
    """
    Rebuild the active rule set from GUI-editable keywords and optional regex rules.

    keywords is treated as the active keyword list, not merely as an extra list.
    The GUI can still keep JSON regex rules enabled by default so 密级格式 remains covered.
    include_default/extra_* are accepted for backward compatibility with older calls.
    """
    global COMPILED_RULES

    if keywords is None and extra_keywords is not None:
        keywords = extra_keywords
    if regexes is None and extra_regexes is not None:
        regexes = extra_regexes

    if include_default is True:
        runtime_rules = load_rules() + build_keyword_rules(keywords) + build_regex_rules(regexes, include_default_regex=False)
    else:
        runtime_rules = build_keyword_rules(keywords) + build_regex_rules(regexes, include_default_regex=include_default_regex)

    COMPILED_RULES = compile_rules(runtime_rules)
    return len(COMPILED_RULES)


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
