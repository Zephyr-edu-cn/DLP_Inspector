import argparse
import json
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def load_snapshot_file(snapshot_path: Path) -> list[dict[str, object]]:
    data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshots = data.get("snapshots", data) if isinstance(data, dict) else data
    if not isinstance(snapshots, list):
        raise ValueError("snapshot file must contain a list or a snapshots list")
    return [item for item in snapshots if isinstance(item, dict) and item.get("url")]


def run_review(snapshot_path: Path, output_dir: Path, export_report: bool) -> int:
    from core.web_scanner import WebScanner

    snapshots = load_snapshot_file(snapshot_path)
    if not snapshots:
        print("snapshot_count=0")
        return 2

    start_url = str(snapshots[0]["url"])
    summary = WebScanner(start_url=start_url, max_depth=0).verify_snapshots(snapshots)

    print(f"task_name={summary.task_name}")
    print(f"total_reviewed={summary.total_scanned}")
    print(f"changed_pages={summary.scanned_details.get('内容变化页面数', 0)}")
    print(f"error_pages={summary.scanned_details.get('访问异常页面数', 0)}")

    for result in summary.results[:10]:
        if result.error_msg:
            print(f"ERROR {result.source_path} :: {result.error_msg}")
        else:
            print(f"DIFF {result.rule_id or '-'} :: {result.source_path} :: {result.context}")

    if export_report:
        from report.report_manager import ReportManager

        manager = ReportManager(output_dir=str(output_dir))
        excel_path = manager.generate_excel_report(summary)
        if not excel_path:
            print("excel_report=failed")
            return 2
        html_path = manager.generate_html_report(summary, excel_path)
        print(f"excel_report={excel_path}")
        if html_path:
            print(f"html_report={html_path}")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review a DLP web snapshot JSON file and report changed static HTML pages."
    )
    parser.add_argument("snapshot", help="Path to *_web_snapshots.json exported by the GUI/report manager.")
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "audit_reports"),
        help="Directory for generated review reports.",
    )
    parser.add_argument("--no-report", action="store_true", help="Skip Excel/HTML report export.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    os.chdir(PROJECT_ROOT)

    snapshot_path = Path(args.snapshot)
    if not snapshot_path.is_absolute():
        snapshot_path = PROJECT_ROOT / snapshot_path

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    return run_review(snapshot_path, output_dir, export_report=not args.no_report)


if __name__ == "__main__":
    raise SystemExit(main())
