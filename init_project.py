import os

def create_project_structure():
    # 定义需要的文件夹路径
    directories = [
        "config",
        "core",
        "utils",
        "models",
        "report/templates",
        "ui"
    ]

    for directory in directories:
        # 创建文件夹
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")
        
        # 在除了 templates 之外的每个包目录下创建 __init__.py
        if "templates" not in directory:
            init_file = os.path.join(directory, "__init__.py")
            if not os.path.exists(init_file):
                with open(init_file, "w", encoding="utf-8") as f:
                    pass
                print(f"Created file: {init_file}")
                
    # 创建主入口文件
    main_file = "main.py"
    if not os.path.exists(main_file):
        with open(main_file, "w", encoding="utf-8") as f:
            f.write("# 项目主入口\n")
        print(f"📄 Created file: {main_file}")

if __name__ == "__main__":
    print("开始构建项目结构...")
    create_project_structure()
    print("项目基础结构构建完成。")