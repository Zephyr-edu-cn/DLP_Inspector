# 项目主入口
# main.py
import os
from core.file_scanner import FileScanner

def main():
    print("=" * 50)
    print("🛡️  数据防泄漏 (DLP) 涉密检查系统 - 雏形测试版")
    print("=" * 50)
    
    # 交互式获取测试目录
    test_dir = input("\n请输入要扫描的路径 (支持文件夹或单个文件): ").strip(' "\'')# 去除用户输入中的多余空格和引号
    
    if not os.path.exists(test_dir):
        print(f"\n❌ 错误：路径 '{test_dir}' 不存在，请检查！")
        return

    print(f"\n🚀 开始深度扫描目录: {test_dir}")
    
    # 初始化扫描器并执行扫描
    scanner = FileScanner()
    results = scanner.scan_path(test_dir)

    # 打印测试报告
    print("\n" + "=" * 50)
    print(f"✅ 扫描完成！共发现 {len(results)} 条疑似涉密/异常信息。")
    print("=" * 50)

    for i, res in enumerate(results, start=1):
        # 如果是异常文件（如加密）
        if res.error_msg:
            print(f"[{i}] ⚠️ 异常跳过: {res.source_path}")
            print(f"    -> 原因: {res.error_msg}")
        # 如果是正常涉密发现
        else:
            print(f"[{i}] 📄 发现涉密文件: {res.source_path}")
            print(f"    -> 位置: 第 {res.line_number} 行")
            print(f"    -> 命中关键字: [{res.keyword}]")
            print(f"    -> 上下文证据: ...{res.context}...")
        print("-" * 50)

if __name__ == "__main__":
    main()