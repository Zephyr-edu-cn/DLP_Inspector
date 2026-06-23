from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ScanResult:
    """单条敏感信息或异常记录"""
    source_type: str
    source_path: str
    keyword: str
    line_number: str
    context: str
    rule_id: str = ""
    rule_name: str = ""
    risk_level: str = ""
    rule_description: str = ""
    error_msg: str = ""
    is_encrypted: bool = False


@dataclass
class ScanSummary:
    """单次扫描任务的总体统计、结果与附加元数据"""
    task_name: str
    total_scanned: int = 0
    total_secrets: int = 0
    scanned_details: Dict[str, int] = field(default_factory=dict)
    results: List[ScanResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
