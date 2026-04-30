# main.py
import os
from core.file_scanner import FileScanner
from core.db_scanner import DBScanner
from core.web_scanner import WebScanner
from core.image_scanner import ImageScanner

def print_banner():
    print("=" * 60)
    print("数据防泄漏 (DLP) 涉密检查系统 - 核心控制台")
    print("=" * 60)
    print(" [1] 本地文件检查 (支持伪装识别与文档解析)")
    print(" [2] 数据库检查 (MySQL/MariaDB 深度扫描)")
    print(" [3] 网页检查 (动态爬虫)")
    print(" [4] 图片涉密检查 (本地离线 AI OCR)")
    print(" [0] 退出系统")
    print("=" * 60)

def handle_file_scan():
    target_path = input("\n[文件扫描] 请输入要扫描的路径 (支持文件夹或单个文件): ").strip().strip(' "\'').strip()
    if not os.path.exists(target_path):
        print(f"\n错误：路径 '{target_path}' 不存在，请检查！")
        return

    print(f"\n开始深度扫描: {target_path}")
    scanner = FileScanner()
    results = scanner.scan_path(target_path)
    
    print("\n" + "=" * 60)
    print(f"扫描完成！共发现 {len(results)} 条疑似涉密/异常信息。")
    print("=" * 60)
    
    for i, res in enumerate(results, start=1):
        if res.error_msg:
            print(f"[{i}] 异常跳过: {res.source_path}\n    -> 原因: {res.error_msg}")
        else:
            print(f"[{i}] 发现涉密文件: {res.source_path}")
            print(f"    -> 位置: {res.line_number}")
            print(f"    -> 关键字: [{res.keyword}]")
            print(f"    -> 上下文: ...{res.context}...")
        print("-" * 60)

def handle_db_scan():
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
        results, stats = scanner.scan()
        
        # 打印题目要求的统计报告
        print("\n" + "=" * 60)
        print("数据库扫描统计报告")
        print("=" * 60)
        print(f"  - 共扫描数据表: {stats['table_count']} 个")
        print(f"  - 共扫描总行数: {stats['total_rows_scanned']} 行")
        print("  - 各表数据量:")
        for tbl, count in stats['table_details'].items():
            print(f"    * 表 [{tbl}]: {count} 行")
        
        print("\n" + "=" * 60)
        print(f"涉密检查结果：共发现 {len(results)} 条涉密记录。")
        print("=" * 60)
        
        for i, res in enumerate(results, start=1):
            print(f"[{i}] 发现涉密数据表: {res.source_path}")
            print(f"    -> 所在位置: {res.line_number}")
            print(f"    -> 命中关键字: [{res.keyword}]")
            print(f"    -> 上下文证据: ...{res.context}...")
            print("-" * 60)
            
    except Exception as e:
        print(f"\n数据库扫描发生致命错误: {e}")

def handle_web_scan():
    print("\n[网页扫描] 请输入要检查的入口网址")
    url = input("入口网址 (例如 https://bm.yangyq.net/): ").strip()
    if not url:
        return
        
    depth_input = input("爬取深度 (默认 2，输入 0 只扫首页): ").strip()
    depth = int(depth_input) if depth_input.isdigit() else 2

    print(f"\n开始部署网络爬虫: {url} (深度: {depth}) ...")
    print("正在抓取和解析网页，这可能需要几十秒钟，请稍候...")
    
    scanner = WebScanner(start_url=url, max_depth=depth)
    results = scanner.scan()
    
    print("\n" + "=" * 60)
    print(f"爬虫任务结束！共爬取了 {len(scanner.visited)} 个网页。")
    print(f"共发现 {len(results)} 条疑似涉密信息。")
    print("=" * 60)
    
    for i, res in enumerate(results, start=1):
        print(f"[{i}] 发现涉密网页: {res.source_path}")
        print(f"    -> 命中位置: {res.line_number}")
        print(f"    -> 命中关键字: [{res.keyword}]")
        print(f"    -> 上下文证据: ...{res.context}...")
        print("-" * 60)

def handle_image_scan():
    target_path = input("\n[图片扫描] 请输入要扫描的路径 (支持文件夹或单个图片文件): ").strip().strip(' "\'').strip()
    if not target_path:
        return
    
    print(f"\n开始部署图像分析引擎，扫描: {target_path}")

    scanner = ImageScanner()
    results = scanner.scan_path(target_path)

    print("\n" + "=" * 60)
    print(f"✅ 图像分析完毕！共发现 {len(results)} 条涉密信息。")
    print("=" * 60)

    for i, res in enumerate(results, start=1):
        print(f"[{i}] 涉密图片: {res.source_path}")
        print(f"    -> 命中位置: {res.line_number}")
        print(f"    -> 关键字: [{res.keyword}]")
        print(f"    -> 上下文: ...{res.context}...")
        print("-" * 60)

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