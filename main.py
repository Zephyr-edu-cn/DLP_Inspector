# main.py
import os
from core.file_scanner import FileScanner
from core.db_scanner import DBScanner
from core.web_scanner import WebScanner
from core.image_scanner import ImageScanner
from report.report_manager import ReportManager

def print_banner():
    """打印控制台主菜单"""
    print("=" * 60)
    print("数据防泄漏 (DLP) 涉密检查系统 - 核心控制台")
    print("=" * 60)
    print(" [1] 本地文件检查 (支持伪装识别与文档解析)")
    print(" [2] 数据库检查 (MySQL/MariaDB 深度扫描)")
    print(" [3] 网页检查 (动态爬虫)")
    print(" [4] 图片涉密检查 (本地离线 AI OCR)")
    print(" [0] 退出系统")
    print("=" * 60)

def prompt_export(summary):
    """通用的报告导出交互逻辑"""
    if summary.total_secrets == 0:
        print("\n本次检查未发现涉密信息，无需导出明细报告。")
        return

    choice = input("\n是否将本次扫描结果导出为 Excel 审计报告？(Y/N): ").strip().upper()
    if choice == 'Y':
        print("正在生成审计报告...")
        reporter = ReportManager()  # 默认会输出到根目录的 audit_reports 文件夹
        report_path = reporter.generate_excel_report(summary)
        if report_path:
            print(f"报告已成功生成！请前往查看：\n{report_path}")

def handle_file_scan():
    """处理文件扫描逻辑"""
    target_path = input("\n[文件扫描] 请输入要扫描的路径 (支持文件夹或单个文件): ").strip().strip(' "\'').strip()
    if not target_path:
        return

    print(f"\n开始深度扫描: {target_path}")
    
    scanner = FileScanner()
    # 返回 ScanSummary 对象
    summary = scanner.scan_path(target_path)
    
    print("\n" + "=" * 60)
    print(f"扫描任务: {summary.task_name}")
    print(f"共扫描文件: {summary.total_scanned} 个")
    print(f"文件类型分布: {summary.scanned_details}")
    print(f"发现涉密告警: {summary.total_secrets} 条")
    print("=" * 60)

    # 结果展示限制
    limit = 20
    for i, res in enumerate(summary.results[:limit], start=1):
        if res.error_msg:
            print(f"[警告] {res.source_path} -> {res.error_msg}")
        else:
            print(f"[{i}] 涉密文件: {res.source_path}")
            print(f"    -> 命中位置: {res.line_number}")
            print(f"    -> 关键字: [{res.keyword}]")
            print(f"    -> 上下文证据: ...{res.context}...")
        print("-" * 60)
        
    if summary.total_secrets > limit:
        print(f"\n... (由于结果过多，屏幕仅展示前 {limit} 条) ...")

    # 调用报告导出
    prompt_export(summary)

def handle_db_scan():
    """处理数据库扫描逻辑"""
    print("\n[数据库扫描] 请输入连接信息 (直接回车将使用默认值)")
    host = input("主机地址 (默认 localhost): ").strip() or "localhost"
    port = input("端口号 (默认 3306): ").strip() or "3306"
    user = input("用户名 (默认 root): ").strip() or "root"
    password = input("密码 (默认为空): ").strip() or ""
    database = input("数据库名 (必填): ").strip()

    if not database:
        print("\n错误：数据库名称不能为空！")
        return

    print(f"\n开始连接并扫描数据库: {database} ...")
    try:
        scanner = DBScanner(host, port, user, password, database)
        # 统一适配：现在返回的是 ScanSummary 对象
        summary = scanner.scan()
        
        print("\n" + "=" * 60)
        print(f"任务名称: {summary.task_name}")
        print(f"共扫描数据表: {summary.total_scanned} 个")
        print("各表数据量分布 (行数):")
        for tbl, count in summary.scanned_details.items():
            print(f"  * 表 [{tbl}]: {count} 行")
        
        print(f"\n涉密检查结果：共发现 {summary.total_secrets} 条记录。")
        print("=" * 60)
        
        limit = 20
        for i, res in enumerate(summary.results[:limit], start=1):
            print(f"[{i}] 发现涉密数据表: {res.source_path}")
            print(f"    -> 所在位置: {res.line_number}")
            print(f"    -> 命中关键字: [{res.keyword}]")
            print(f"    -> 上下文证据: ...{res.context}...")
            print("-" * 60)

        if summary.total_secrets > limit:
            print(f"\n... (仅展示前 {limit} 条明细) ...")

        # 调用报告导出
        prompt_export(summary)

    except Exception as e:
        print(f"\n数据库扫描失败: {e}")

def handle_web_scan():
    """处理网页爬虫扫描逻辑"""
    url = input("\n[网页扫描] 入口网址: ").strip()
    if not url:
        return
        
    depth_input = input("爬取深度 (默认 2，输入 0 只扫首页): ").strip()
    depth = int(depth_input) if depth_input.isdigit() else 2

    print(f"\n开始部署网络爬虫: {url} (深度: {depth}) ...")
    
    scanner = WebScanner(start_url=url, max_depth=depth)
    summary = scanner.scan()
    
    print("\n" + "=" * 60)
    print(f"任务名称: {summary.task_name}")
    print(f"共检查网页: {summary.total_scanned} 页")
    print(f"共发现涉密信息: {summary.total_secrets} 条")
    print("=" * 60)
    
    limit = 20
    for i, res in enumerate(summary.results[:limit], start=1):
        print(f"[{i}] 发现涉密网页: {res.source_path}")
        print(f"    -> 命中位置: {res.line_number}")
        print(f"    -> 命中关键字: [{res.keyword}]")
        print(f"    -> 上下文证据: ...{res.context}...")
        print("-" * 60)

    if summary.total_secrets > limit:
        print(f"\n... (仅展示前 {limit} 条明细) ...")

    # 调用报告导出
    prompt_export(summary)

def handle_image_scan():
    """处理图片 OCR 扫描逻辑"""
    target_path = input("\n[图片扫描] 请输入图片路径或文件夹: ").strip().strip(' "\'').strip()
    if not target_path:
        return
    
    print(f"\n开始分析图像数据: {target_path}")

    scanner = ImageScanner()
    summary = scanner.scan_path(target_path)

    print("\n" + "=" * 60)
    print(f"任务名称: {summary.task_name}")
    print(f"共扫描图片: {summary.total_scanned} 张")
    print(f"图片格式统计: {summary.scanned_details}")
    print(f"共发现涉密信息: {summary.total_secrets} 条")
    print("=" * 60)

    limit = 20
    for i, res in enumerate(summary.results[:limit], start=1):
        print(f"[{i}] 涉密图片: {res.source_path}")
        print(f"    -> 命中位置: {res.line_number}")
        print(f"    -> 关键字: [{res.keyword}]")
        print(f"    -> 上下文: ...{res.context}...")
        print("-" * 60)

    if summary.total_secrets > limit:
        print(f"\n... (仅展示前 {limit} 条明细) ...")

    # 调用报告导出
    prompt_export(summary)

def main():
    while True:
        print_banner()
        choice = input("请输入功能序号: ").strip()
        
        if choice == '1':
            handle_file_scan()
        elif choice == '2':
            handle_db_scan()
        elif choice == '3':
            handle_web_scan()
        elif choice == '4':
            handle_image_scan()
        elif choice == '0':
            print("退出系统，再见！")
            break
        else:
            print("无效的输入，请重新选择。")
        
        input("\n按回车键返回主菜单...")

if __name__ == "__main__":
    main()