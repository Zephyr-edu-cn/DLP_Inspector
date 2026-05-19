import argparse
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_file_smoke(target: Path, output_dir: Path, export_report: bool) -> int:
    from core.file_scanner import FileScanner

    scanner = FileScanner()
    summary = scanner.scan_path(str(target))

    print(f"task_name={summary.task_name}")
    print(f"total_scanned={summary.total_scanned}")
    print(f"total_findings={summary.total_secrets}")

    for result in summary.results[:10]:
        if result.error_msg:
            print(f"ERROR {result.source_path} :: {result.error_msg}")
            continue
        print(
            f"FINDING {result.risk_level or 'unknown'} "
            f"{result.rule_id or '-'} :: {result.keyword} :: {result.source_path}"
        )

    if export_report:
        from report.report_manager import ReportManager

        report_path = ReportManager(output_dir=str(output_dir)).generate_excel_report(summary)
        if not report_path:
            print("report_export=failed")
            return 2
        print(f"report_export={report_path}")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a reproducible local DLP smoke scan.")
    parser.add_argument("--mode", choices=["file"], default="file")
    parser.add_argument(
        "--target",
        default=str(PROJECT_ROOT / "sample_data" / "files"),
        help="File or directory to scan. Defaults to sample_data/files.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "audit_reports"),
        help="Directory for generated smoke reports.",
    )
    parser.add_argument("--no-report", action="store_true", help="Skip Excel report export.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    os.chdir(PROJECT_ROOT)

    target = Path(args.target)
    if not target.is_absolute():
        target = PROJECT_ROOT / target

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    if args.mode == "file":
        return run_file_smoke(target, output_dir, export_report=not args.no_report)

    print(f"Unsupported smoke mode: {args.mode}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
