import os
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class OptionalIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.getenv("DLP_TEST_OCR_IMAGE"),
        "set DLP_TEST_OCR_IMAGE to run the PaddleOCR integration test",
    )
    def test_paddleocr_image(self):
        from core.image_scanner import ImageScanner

        image_path = Path(os.environ["DLP_TEST_OCR_IMAGE"])
        self.assertTrue(image_path.is_file())
        summary = ImageScanner().scan_path(str(image_path))
        self.assertEqual(summary.total_scanned, 1)

    @unittest.skipUnless(
        all(os.getenv(name) for name in (
            "DLP_TEST_MYSQL_HOST",
            "DLP_TEST_MYSQL_USER",
            "DLP_TEST_MYSQL_DATABASE",
        )),
        "set DLP_TEST_MYSQL_* variables to run the MySQL integration test",
    )
    def test_mysql_text_field_scan(self):
        from core.db_scanner import DBScanner

        scanner = DBScanner(
            os.environ["DLP_TEST_MYSQL_HOST"],
            int(os.getenv("DLP_TEST_MYSQL_PORT", "3306")),
            os.environ["DLP_TEST_MYSQL_USER"],
            os.getenv("DLP_TEST_MYSQL_PASSWORD", ""),
            database=os.environ["DLP_TEST_MYSQL_DATABASE"],
            batch_size=50,
        )
        summary = scanner.scan()
        self.assertGreaterEqual(summary.total_scanned, 0)

    @unittest.skipUnless(
        os.name == "nt" and os.getenv("DLP_TEST_LEGACY_OFFICE"),
        "set DLP_TEST_LEGACY_OFFICE on Windows with Office installed",
    )
    def test_windows_com_legacy_office(self):
        from utils.doc_parsers import parse_doc, parse_ppt

        office_path = Path(os.environ["DLP_TEST_LEGACY_OFFICE"])
        self.assertTrue(office_path.is_file())
        parser = {
            ".doc": parse_doc,
            ".ppt": parse_ppt,
        }.get(office_path.suffix.lower())
        self.assertIsNotNone(
            parser,
            "DLP_TEST_LEGACY_OFFICE must point to a .doc or .ppt file",
        )
        list(parser(str(office_path)))


if __name__ == "__main__":
    unittest.main()
