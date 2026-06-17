import json
import builtins
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.db_scanner import DBScanner
from core.file_scanner import FileScanner
from core.web_scanner import WebScanner
from models.data_models import ScanResult, ScanSummary
from report.report_manager import ReportManager
from utils.regex_utils import compile_rules, load_rules


class RuleTests(unittest.TestCase):
    def test_load_rules_and_compile_fuzzy_keyword(self):
        rules = [
            {
                "rule_id": "TEST_SECRET",
                "name": "测试关键词",
                "pattern": "绝密",
                "type": "keyword",
                "risk_level": "critical",
                "description": "synthetic",
            },
            {
                "rule_id": "TEST_MARK",
                "name": "测试正则",
                "pattern": r"机密\s*文件",
                "type": "regex",
                "risk_level": "high",
                "description": "synthetic",
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_path = Path(temp_dir) / "rules.json"
            rules_path.write_text(
                json.dumps(rules, ensure_ascii=False), encoding="utf-8"
            )
            loaded = load_rules(rules_path)

        compiled = {
            rule["rule_id"]: rule["compiled_pattern"]
            for rule in compile_rules(loaded)
        }
        self.assertEqual([rule["rule_id"] for rule in loaded], [
            "TEST_SECRET",
            "TEST_MARK",
        ])
        self.assertIsNotNone(compiled["TEST_SECRET"].search("绝 密"))
        self.assertIsNotNone(compiled["TEST_SECRET"].search("绝-密"))
        self.assertIsNotNone(compiled["TEST_MARK"].search("机密 文件"))

    def test_invalid_rule_file_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_path = Path(temp_dir) / "rules.json"
            rules_path.write_text("{invalid", encoding="utf-8")
            loaded = load_rules(rules_path)

        self.assertTrue(loaded)
        self.assertIn("CONF_KEYWORD_SENSITIVE", {
            rule["rule_id"] for rule in loaded
        })


class FileSmokeTests(unittest.TestCase):
    def test_repository_sample_files(self):
        summary = FileScanner(max_workers=1).scan_path(
            str(PROJECT_ROOT / "sample_data" / "files")
        )

        self.assertEqual(summary.total_scanned, 3)
        self.assertEqual(summary.scanned_details, {".txt": 3})
        self.assertEqual(summary.total_secrets, 4)
        self.assertEqual(
            {result.rule_id for result in summary.results},
            {
                "CONF_KEYWORD_TOP_SECRET",
                "CONF_REGEX_CLASSIFICATION_MARK",
                "CONF_KEYWORD_SENSITIVE",
                "CONF_KEYWORD_PROTECT",
            },
        )
        self.assertFalse(any(
            result.source_path.endswith("normal.txt")
            for result in summary.results
        ))

    def test_parser_failure_is_recorded_with_source_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            broken = Path(temp_dir) / "broken.docx"
            broken.write_bytes(b"synthetic broken document")

            def fail_parser(_path, password=None):
                raise ValueError("synthetic parser failure")
                yield

            scanner = FileScanner(max_workers=1)
            scanner.parsers[".docx"] = fail_parser
            with patch(
                "core.file_scanner.get_real_extension",
                return_value=".docx",
            ):
                summary = scanner.scan_path(str(broken))

        self.assertEqual(summary.total_scanned, 1)
        self.assertEqual(len(summary.results), 1)
        result = summary.results[0]
        self.assertTrue(result.source_path.endswith("broken.docx"))
        self.assertIn("synthetic parser failure", result.error_msg)

    def test_missing_path_returns_empty_summary(self):
        summary = FileScanner(max_workers=1).scan_path(
            str(PROJECT_ROOT / "missing-synthetic-path")
        )
        self.assertEqual(summary.total_scanned, 0)
        self.assertEqual(summary.results, [])


class _FakeResponse:
    def __init__(self, html):
        self.text = html
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.encoding = "utf-8"
        self.apparent_encoding = "utf-8"

    def raise_for_status(self):
        return None


class WebScannerTests(unittest.TestCase):
    def test_same_domain_bfs_and_depth_limit(self):
        pages = {
            "https://audit.example/": (
                "<html><body>公开首页"
                '<a href="/level1">level1</a>'
                '<a href="https://outside.example/ignored">outside</a>'
                "</body></html>"
            ),
            "https://audit.example/level1": (
                "<html><body>涉密内容"
                '<a href="/level2">level2</a>'
                "</body></html>"
            ),
        }
        requested = []

        def fake_get(url, headers=None, timeout=None):
            requested.append(url)
            if url not in pages:
                raise AssertionError(f"unexpected URL: {url}")
            return _FakeResponse(pages[url])

        with patch("core.web_scanner.requests.get", side_effect=fake_get):
            summary = WebScanner(
                "https://audit.example/", max_depth=1
            ).scan()

        self.assertEqual(requested, [
            "https://audit.example/",
            "https://audit.example/level1",
        ])
        self.assertEqual(summary.total_scanned, 2)
        self.assertTrue(any(
            result.rule_id == "CONF_KEYWORD_SENSITIVE"
            and result.source_path.endswith("/level1")
            for result in summary.results
        ))

    def test_request_failure_is_recorded(self):
        with patch(
            "core.web_scanner.requests.get",
            side_effect=RuntimeError("synthetic network error"),
        ):
            summary = WebScanner(
                "https://audit.example/", max_depth=0
            ).scan()

        self.assertEqual(summary.total_scanned, 1)
        self.assertEqual(len(summary.results), 1)
        self.assertIn("synthetic network error", summary.results[0].error_msg)


class _PagingCursor:
    def __init__(self):
        self.query = ""
        self.params = None
        self.page_calls = []

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        return False

    def execute(self, query, params=None):
        self.query = " ".join(query.split())
        self.params = params
        if " LIMIT %s OFFSET %s" in self.query:
            self.page_calls.append(tuple(params))

    def fetchall(self):
        if self.query == "SHOW TABLES":
            return [{"Tables_in_demo": "documents"}]
        if "information_schema.COLUMNS" in self.query:
            return [{"COLUMN_NAME": "content"}]
        if " LIMIT %s OFFSET %s" in self.query:
            pages = {
                (2, 0): [
                    {"content": "普通公开内容"},
                    {"content": "包含涉密讨论"},
                ],
                (2, 2): [{"content": "密级：绝密★启用前"}],
                (2, 4): [],
            }
            return pages[tuple(self.params)]
        return []

    def fetchone(self):
        if self.query.startswith("SELECT COUNT(*)"):
            return {"count": 3}
        return None


class _PagingConnection:
    def __init__(self):
        self.open = True
        self.cursor_instance = _PagingCursor()

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.open = False


class DatabasePaginationTests(unittest.TestCase):
    def test_text_fields_are_read_in_pages(self):
        connection = _PagingConnection()
        scanner = DBScanner(
            "localhost",
            3306,
            "audit_user",
            "demo_password",
            database="demo",
            batch_size=2,
        )
        with patch.object(scanner, "_connect", return_value=connection):
            summary = scanner.scan()

        self.assertEqual(
            connection.cursor_instance.page_calls,
            [(2, 0), (2, 2), (2, 4)],
        )
        self.assertFalse(connection.open)
        self.assertEqual(summary.total_scanned, 1)
        self.assertEqual(summary.scanned_details, {"demo.documents": 3})
        self.assertTrue(any(
            result.line_number == "第2行 - 字段[content]"
            and result.rule_id == "CONF_KEYWORD_SENSITIVE"
            for result in summary.results
        ))
        self.assertTrue(any(
            result.line_number == "第3行 - 字段[content]"
            and result.rule_id == "CONF_REGEX_CLASSIFICATION_MARK"
            for result in summary.results
        ))


class ReportStructureTests(unittest.TestCase):
    def test_sheet_names_and_headers(self):
        summary = ScanSummary(
            task_name="结构测试",
            total_scanned=2,
            total_secrets=1,
            scanned_details={".txt": 2},
            results=[
                ScanResult(
                    source_type="FILE",
                    source_path="positive.txt",
                    keyword="涉密",
                    line_number="1",
                    context="包含涉密内容",
                    rule_id="CONF_KEYWORD_SENSITIVE",
                    rule_name="涉密关键词",
                    risk_level="high",
                    rule_description="synthetic",
                ),
                ScanResult(
                    source_type="FILE",
                    source_path="broken.docx",
                    keyword="[无法读取]",
                    line_number="-",
                    context="-",
                    error_msg="synthetic parser failure",
                ),
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ReportManager(temp_dir)
            sheets = manager._build_report_sheets(summary)

            self.assertEqual(list(sheets), [
                "summary",
                "high_risk_findings",
                "findings",
                "errors",
            ])
            self.assertEqual(sheets["summary"][0], ["metric", "value"])
            self.assertEqual(sheets["high_risk_findings"][0], [
                "task_name",
                "source_type",
                "source_path",
                "location",
                "risk_level",
                "rule_id",
                "rule_name",
                "keyword",
                "context",
                "error_msg",
                "rule_description",
            ])
            self.assertEqual(sheets["findings"][0], [
                "source_type",
                "source_path",
                "location",
                "rule_id",
                "rule_name",
                "risk_level",
                "keyword",
                "context",
                "rule_description",
            ])
            self.assertEqual(sheets["errors"][0], [
                "source_type",
                "source_path",
                "location",
                "keyword",
                "error_msg",
                "context",
            ])

            with patch.object(
                manager,
                "_write_with_pandas",
                side_effect=ImportError,
            ):
                report_path = manager.generate_excel_report(summary)
            with zipfile.ZipFile(report_path) as archive:
                workbook = archive.read("xl/workbook.xml").decode("utf-8")
                findings_xml = archive.read(
                    "xl/worksheets/sheet3.xml"
                ).decode("utf-8")

        for sheet_name in (
            "summary",
            "high_risk_findings",
            "findings",
            "errors",
        ):
            self.assertIn(f'name="{sheet_name}"', workbook)
        for field in sheets["findings"][0]:
            self.assertIn(field, findings_xml)

    def test_html_summary_contains_key_sections(self):
        summary = ScanSummary(
            task_name="HTML结构测试",
            total_scanned=3,
            total_secrets=2,
            scanned_details={".txt": 3},
            results=[
                ScanResult(
                    source_type="FILE",
                    source_path="critical.txt",
                    keyword="绝密",
                    line_number="1",
                    context="包含绝密内容",
                    rule_id="CONF_KEYWORD_TOP_SECRET",
                    rule_name="绝密关键词",
                    risk_level="critical",
                    rule_description="synthetic",
                ),
                ScanResult(
                    source_type="FILE",
                    source_path="hidden.txt",
                    keyword="[隐藏文件]",
                    line_number="文件属性",
                    context="hidden synthetic",
                    rule_id="SYSTEM_HIDDEN_FILE",
                    rule_name="隐藏文件提示",
                    risk_level="medium",
                    rule_description="synthetic",
                ),
                ScanResult(
                    source_type="WEB",
                    source_path="https://audit.example/missing",
                    keyword="[无法访问]",
                    line_number="-",
                    context="-",
                    error_msg="synthetic network error",
                ),
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ReportManager(temp_dir)
            excel_path = str(Path(temp_dir) / "synthetic.xlsx")
            html_path = manager.generate_html_report(summary, excel_path)
            html = Path(html_path).read_text(encoding="utf-8")

        for text in [
            "HTML结构测试摘要报告",
            "分模块统计",
            "风险等级分布",
            "规则命中 Top 20",
            "高风险明细（前 100 条）",
            "异常摘要（前 100 条）",
            "完整明细见同目录 Excel 文件",
            "SYSTEM_HIDDEN_FILE",
            "synthetic network error",
        ]:
            self.assertIn(text, html)

    def test_combined_report_has_high_risk_sheet(self):
        summaries = [
            ScanSummary(
                task_name="本地文件深度检查",
                total_scanned=1,
                total_secrets=1,
                results=[
                    ScanResult(
                        source_type="FILE",
                        source_path="secret.txt",
                        keyword="绝密",
                        line_number="1",
                        context="绝密内容",
                        rule_id="CONF_KEYWORD_TOP_SECRET",
                        rule_name="绝密关键词",
                        risk_level="critical",
                        rule_description="synthetic",
                    )
                ],
            )
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            sheets = ReportManager(temp_dir)._build_combined_report_sheets(summaries)
        self.assertEqual(list(sheets)[:4], [
            "overall_summary",
            "high_risk_findings",
            "all_findings",
            "all_errors",
        ])
        self.assertEqual(sheets["high_risk_findings"][1][0], "本地文件深度检查")


class OptionalDependencyBoundaryTests(unittest.TestCase):
    def test_image_scanner_module_imports_without_paddleocr(self):
        import core.image_scanner as image_scanner

        self.assertTrue(hasattr(image_scanner, "ImageScanner"))

    def test_image_scanner_reports_missing_optional_dependency(self):
        import core.image_scanner as image_scanner

        real_import = builtins.__import__

        def blocked_import(name, *args, **kwargs):
            if name == "paddleocr":
                raise ImportError("synthetic missing PaddleOCR")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=blocked_import):
            with self.assertRaisesRegex(
                RuntimeError, "OCR 依赖未安装"
            ):
                image_scanner.ImageScanner()


if __name__ == "__main__":
    unittest.main()
