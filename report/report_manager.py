# report/report_manager.py
import os
import re
import zipfile
from datetime import datetime
from xml.sax.saxutils import escape

from models.data_models import ScanSummary


class ReportManager:
    def __init__(self, output_dir="audit_reports"):
        """初始化报告管理器，确保输出目录存在于项目根目录"""
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_excel_report(self, summary: ScanSummary) -> str:
        """接收 ScanSummary，生成 summary/findings/errors 三个 Sheet 的 Excel 报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_task_name = self._safe_filename(summary.task_name)
        file_name = f"DLP_Audit_{safe_task_name}_{timestamp}.xlsx"
        file_path = os.path.join(self.output_dir, file_name)

        sheets = self._build_report_sheets(summary)

        try:
            self._write_with_pandas(file_path, sheets)
            return os.path.abspath(file_path)
        except ImportError:
            self._write_minimal_xlsx(file_path, sheets)
            return os.path.abspath(file_path)
        except Exception as e:
            print(f"\n生成报告时发生错误: {e}")
            return ""

    def generate_combined_excel_report(self, summaries: list[ScanSummary]) -> str:
        """生成综合检查报告：overall_summary + all_findings + all_errors + 各任务 summary。"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"DLP_Audit_综合涉密信息检查_{timestamp}.xlsx"
        file_path = os.path.join(self.output_dir, file_name)

        sheets = self._build_combined_report_sheets(summaries)
        try:
            self._write_with_pandas(file_path, sheets)
            return os.path.abspath(file_path)
        except ImportError:
            self._write_minimal_xlsx(file_path, sheets)
            return os.path.abspath(file_path)
        except Exception as e:
            print(f"\n生成综合报告时发生错误: {e}")
            return ""

    def _build_combined_report_sheets(self, summaries: list[ScanSummary]) -> dict[str, list[list[object]]]:
        total_scanned = sum(summary.total_scanned for summary in summaries)
        all_results = [res for summary in summaries for res in summary.results]
        findings = [res for res in all_results if not res.error_msg]
        errors = [res for res in all_results if res.error_msg]

        overall_rows = [["metric", "value"]]
        overall_rows.extend([
            ["task_name", "综合涉密信息检查"],
            ["task_count", len(summaries)],
            ["total_scanned", total_scanned],
            ["total_findings", len(findings)],
            ["total_errors", len(errors)],
        ])
        for summary in summaries:
            overall_rows.append([f"{summary.task_name} - scanned", summary.total_scanned])
            overall_rows.append([f"{summary.task_name} - findings", len([r for r in summary.results if not r.error_msg])])
            overall_rows.append([f"{summary.task_name} - errors", len([r for r in summary.results if r.error_msg])])
            if summary.scanned_details:
                details = "\n".join([f"{key}: {val}" for key, val in summary.scanned_details.items()])
                overall_rows.append([f"{summary.task_name} - details", details])

        finding_rows = [[
            "task_name",
            "source_type",
            "source_path",
            "location",
            "rule_id",
            "rule_name",
            "risk_level",
            "keyword",
            "context",
            "rule_description",
        ]]
        error_rows = [[
            "task_name",
            "source_type",
            "source_path",
            "location",
            "keyword",
            "error_msg",
            "context",
        ]]

        for summary in summaries:
            for res in summary.results:
                if res.error_msg:
                    error_rows.append([
                        summary.task_name,
                        res.source_type,
                        res.source_path,
                        res.line_number,
                        res.keyword,
                        res.error_msg,
                        res.context,
                    ])
                else:
                    finding_rows.append([
                        summary.task_name,
                        res.source_type,
                        res.source_path,
                        res.line_number,
                        res.rule_id,
                        res.rule_name,
                        res.risk_level,
                        res.keyword,
                        res.context,
                        res.rule_description,
                    ])

        sheets = {
            "overall_summary": overall_rows,
            "all_findings": finding_rows,
            "all_errors": error_rows,
        }

        # 保留每个子任务的 summary，便于老师快速核对每个任务的扫描数量
        for index, summary in enumerate(summaries, start=1):
            sheet_name = self._safe_sheet_name(f"{index}_{summary.task_name}_summary")
            sheets[sheet_name] = self._build_report_sheets(summary)["summary"]

        return sheets

    def _build_report_sheets(self, summary: ScanSummary) -> dict[str, list[list[object]]]:
        findings = [res for res in summary.results if not res.error_msg]
        errors = [res for res in summary.results if res.error_msg]

        details_list = [f"{key}: {val}" for key, val in summary.scanned_details.items()]
        details_str = "\n".join(details_list) if details_list else "无详细分类"

        summary_rows = [
            ["metric", "value"],
            ["task_name", summary.task_name],
            ["total_scanned", summary.total_scanned],
            ["total_findings", len(findings)],
            ["total_errors", len(errors)],
            ["scanned_details", details_str],
        ]

        finding_rows = [[
            "source_type",
            "source_path",
            "location",
            "rule_id",
            "rule_name",
            "risk_level",
            "keyword",
            "context",
            "rule_description",
        ]]
        for res in findings:
            finding_rows.append([
                res.source_type,
                res.source_path,
                res.line_number,
                res.rule_id,
                res.rule_name,
                res.risk_level,
                res.keyword,
                res.context,
                res.rule_description,
            ])

        error_rows = [[
            "source_type",
            "source_path",
            "location",
            "keyword",
            "error_msg",
            "context",
        ]]
        for res in errors:
            error_rows.append([
                res.source_type,
                res.source_path,
                res.line_number,
                res.keyword,
                res.error_msg,
                res.context,
            ])

        return {
            "summary": summary_rows,
            "findings": finding_rows,
            "errors": error_rows,
        }

    def _write_with_pandas(self, file_path: str, sheets: dict[str, list[list[object]]]) -> None:
        import pandas as pd

        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            for sheet_name, rows in sheets.items():
                header = rows[0]
                body = rows[1:]
                df = pd.DataFrame(body, columns=header)
                df.to_excel(writer, sheet_name=sheet_name, index=False)

    def _write_minimal_xlsx(self, file_path: str, sheets: dict[str, list[list[object]]]) -> None:
        """Write a small standards-compliant XLSX without pandas/openpyxl."""
        with zipfile.ZipFile(file_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", self._content_types_xml(len(sheets)))
            archive.writestr("_rels/.rels", self._root_rels_xml())
            archive.writestr("xl/workbook.xml", self._workbook_xml(list(sheets.keys())))
            archive.writestr("xl/_rels/workbook.xml.rels", self._workbook_rels_xml(len(sheets)))

            for index, rows in enumerate(sheets.values(), start=1):
                archive.writestr(f"xl/worksheets/sheet{index}.xml", self._worksheet_xml(rows))

    def _worksheet_xml(self, rows: list[list[object]]) -> str:
        row_xml = []
        for row_idx, row in enumerate(rows, start=1):
            cells = []
            for col_idx, value in enumerate(row, start=1):
                cell_ref = f"{self._column_name(col_idx)}{row_idx}"
                cell_value = self._clean_cell(value)
                cells.append(
                    f'<c r="{cell_ref}" t="inlineStr"><is><t>{escape(cell_value)}</t></is></c>'
                )
            row_xml.append(f'<row r="{row_idx}">{"".join(cells)}</row>')

        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(row_xml)}</sheetData>'
            '</worksheet>'
        )

    def _content_types_xml(self, sheet_count: int) -> str:
        overrides = [
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
            '<Default Extension="xml" ContentType="application/xml"/>',
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        ]
        for index in range(1, sheet_count + 1):
            overrides.append(
                f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            f'{"".join(overrides)}'
            '</Types>'
        )

    def _root_rels_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>'
        )

    def _workbook_xml(self, sheet_names: list[str]) -> str:
        sheet_xml = []
        for index, sheet_name in enumerate(sheet_names, start=1):
            sheet_xml.append(
                f'<sheet name="{escape(sheet_name)}" sheetId="{index}" r:id="rId{index}"/>'
            )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<sheets>{"".join(sheet_xml)}</sheets>'
            '</workbook>'
        )

    def _workbook_rels_xml(self, sheet_count: int) -> str:
        rels = []
        for index in range(1, sheet_count + 1):
            rels.append(
                f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
            )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'{"".join(rels)}'
            '</Relationships>'
        )

    def _column_name(self, index: int) -> str:
        name = ""
        while index:
            index, remainder = divmod(index - 1, 26)
            name = chr(65 + remainder) + name
        return name

    def _clean_cell(self, value: object) -> str:
        text = "" if value is None else str(value)
        return re.sub(r'[\000-\010]|[\013-\014]|[\016-\037]', '', text)

    def _safe_sheet_name(self, value: str) -> str:
        cleaned = re.sub(r'[\\/:*?"<>|\[\]]+', '_', value).strip()
        return (cleaned or "sheet")[:31]

    def _safe_filename(self, value: str) -> str:
        cleaned = re.sub(r'[\\/:*?"<>|]+', '_', value)
        return cleaned.strip() or "DLP_Audit"
