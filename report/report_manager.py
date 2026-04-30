# report/report_manager.py
import os
import pandas as pd
from datetime import datetime
from models.data_models import ScanSummary

class ReportManager:
    # 这里将默认输出目录设置为外层的 audit_reports
    def __init__(self, output_dir="audit_reports"):
        """初始化报告管理器，确保输出目录存在于项目根目录"""
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_excel_report(self, summary: ScanSummary) -> str:
        """接收 ScanSummary，生成带双 Sheet 的专业 Excel 报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"DLP_Audit_{summary.task_name}_{timestamp}.xlsx"
        file_path = os.path.join(self.output_dir, file_name)

        # ==========================================
        # Sheet 1: 检查概述 
        # ==========================================
        details_list = [f"{key}: {val}" for key, val in summary.scanned_details.items()]
        details_str = "\n".join(details_list) if details_list else "无详细分类"

        summary_data = {
            "审计指标": ["任务名称", "扫描总数", "发现涉密记录总数", "各类型/分类分布明细"],
            "统计结果": [summary.task_name, summary.total_scanned, summary.total_secrets, details_str]
        }
        df_summary = pd.DataFrame(summary_data)

        # ==========================================
        # Sheet 2: 涉密明细 
        # ==========================================
        details_data = []
        for res in summary.results:
            if not res.error_msg: 
                details_data.append({
                    "数据来源": res.source_type,
                    "具体路径/链接/表名": res.source_path,
                    "命中行号/位置": res.line_number,
                    "涉密关键字": res.keyword,
                    "上下文证据": res.context
                })
        
        if not details_data:
            df_details = pd.DataFrame(columns=["数据来源", "具体路径/链接/表名", "命中行号/位置", "涉密关键字", "上下文证据"])
        else:
            df_details = pd.DataFrame(details_data)

        # ==========================================
        # 写入 Excel 文件
        # ==========================================
        try:
            with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
                df_summary.to_excel(writer, sheet_name='检查概述', index=False)
                df_details.to_excel(writer, sheet_name='涉密明细清单', index=False)
            
            return os.path.abspath(file_path)
        except Exception as e:
            print(f"\n生成报告时发生错误: {e}")
            return ""