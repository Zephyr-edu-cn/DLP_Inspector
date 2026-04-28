#models/data_models.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class ScanResult:
    """
    统一检查实体类
    用 dataclass 减少 boilerplate
    """
    source_type: str  # 数据来源类型，如 "文件", "数据库", "API"
    source_path: str  # 数据来源路径：文件绝对路径、网页URL 或 数据库表名
    keyword: str      # 命中的关键字串
    line_number: str  # 发生位置：第几行、哪个字段
    context: str      # 涉密上下文(截取前后文以展示凭证)
    error_msg: Optional[str] = None  # 异常记录：如 "文件已加密，无法读取"

    def to_dict(self):
        """将对象转为字典，方便后续渲染到 HTML 模板中"""
        return {
            "source_type": self.source_type,
            "source_path": self.source_path,
            "keyword": self.keyword,
            "line_number": self.line_number,
            "context": self.context,
            "error_msg": self.error_msg
        }