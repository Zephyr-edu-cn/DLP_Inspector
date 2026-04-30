# models/data_models.py
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ScanResult:
    """单条涉密告警记录"""
    source_type: str     
    source_path: str     
    keyword: str         
    line_number: str     
    context: str         
    error_msg: str = ""        # 防止解析加密文件时报错崩溃
    is_encrypted: bool = False

@dataclass
class ScanSummary:
    """单次扫描任务的总体统计与结果汇聚"""
    task_name: str
    total_scanned: int = 0
    total_secrets: int = 0
    scanned_details: Dict[str, int] = field(default_factory=dict)
    results: List[ScanResult] = field(default_factory=list)