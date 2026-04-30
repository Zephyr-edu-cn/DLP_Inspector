# ui/main_window.py
import os
import sys
import re  # [新增] 引入正则库，用于清洗 Excel 非法字符

# 获取当前文件 (main_window.py) 的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取项目的根目录 (即 ui 的上一级)
root_dir = os.path.dirname(current_dir)

# 将根目录动态加入 Python 的搜索路径中
if root_dir not in sys.path:
    sys.path.append(root_dir)

import time
import threading
import customtkinter as ctk
from tkinter import messagebox

# 导入底层引擎
from core.file_scanner import FileScanner
from core.db_scanner import DBScanner
from core.web_scanner import WebScanner
from core.image_scanner import ImageScanner
from report.report_manager import ReportManager

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class DLPScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DLP Inspector - 安全审计终端")
        self.geometry("1050x700")
        self.minsize(800, 500)
        
        self.current_mode = "FILE" # 默认模式
        self.current_summary = None # 保存最近一次扫描的结果用于导出

        # ==================== 左侧导航栏 ====================
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="DLP INSPECTOR", 
                                       font=ctk.CTkFont(size=18, weight="bold"), text_color="#00FF41")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        self.btn_file = ctk.CTkButton(self.sidebar_frame, text="文件深度检查", command=lambda: self.switch_mode("FILE"))
        self.btn_file.grid(row=1, column=0, padx=20, pady=10)

        self.btn_db = ctk.CTkButton(self.sidebar_frame, text="数据库穿透扫描", command=lambda: self.switch_mode("DB"))
        self.btn_db.grid(row=2, column=0, padx=20, pady=10)

        self.btn_web = ctk.CTkButton(self.sidebar_frame, text="网页动态爬虫", command=lambda: self.switch_mode("WEB"))
        self.btn_web.grid(row=3, column=0, padx=20, pady=10)

        self.btn_img = ctk.CTkButton(self.sidebar_frame, text="AI 图像涉密识别", command=lambda: self.switch_mode("IMAGE"))
        self.btn_img.grid(row=4, column=0, padx=20, pady=10)

        # 记录所有导航按钮，方便扫描时统一管理状态
        self.nav_buttons = [self.btn_file, self.btn_db, self.btn_web, self.btn_img]

        # ==================== 右侧主工作区 ====================
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.grid_columnconfigure(1, weight=1)

        # 1. 顶部操作区
        self.top_action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.top_action_frame.pack(fill="x", pady=(0, 20))

        # --- 1.1 标准单行输入框 (用于文件、网页、图片) ---
        self.path_entry = ctk.CTkEntry(self.top_action_frame, placeholder_text="请输入待检查的文件夹路径...", height=40)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # --- 1.2 数据库专用动态表单区 (默认隐藏) ---
        self.db_input_frame = ctk.CTkFrame(self.top_action_frame, fg_color="transparent", height=40)
        self.db_host = ctk.CTkEntry(self.db_input_frame, placeholder_text="主机 IP (例: localhost)", height=40)
        self.db_host.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.db_port = ctk.CTkEntry(self.db_input_frame, placeholder_text="端口", width=60, height=40)
        self.db_port.pack(side="left", padx=5)
        self.db_user = ctk.CTkEntry(self.db_input_frame, placeholder_text="用户名", width=90, height=40)
        self.db_user.pack(side="left", padx=5)
        self.db_pass = ctk.CTkEntry(self.db_input_frame, placeholder_text="密码", show="*", width=90, height=40)
        self.db_pass.pack(side="left", padx=5)
        self.db_name = ctk.CTkEntry(self.db_input_frame, placeholder_text="数据库名", width=100, height=40)
        self.db_name.pack(side="left", padx=(5, 10))
        # 保存为一个列表方便后续一键禁用
        self.db_entries = [self.db_host, self.db_port, self.db_user, self.db_pass, self.db_name]

        self.scan_btn = ctk.CTkButton(self.top_action_frame, text="▶ 启动核查引擎", 
                                      fg_color="#8B0000", hover_color="#600000", 
                                      height=40, font=ctk.CTkFont(weight="bold"), command=self.start_scan)
        self.scan_btn.pack(side="right")

        # 2. 极客风实时监控终端
        self.terminal_label = ctk.CTkLabel(self.main_frame, text="[ 实时监控终端 / LIVE MONITOR ]", anchor="w", text_color="#777777")
        self.terminal_label.pack(fill="x")

        self.console_box = ctk.CTkTextbox(self.main_frame, fg_color="#0a0a0a", text_color="#00FF41", 
                                          font=ctk.CTkFont(family="Consolas", size=13))
        self.console_box.pack(fill="both", expand=True, pady=(5, 0))
        
        # 预先配置颜色标签
        self.console_box.tag_config("danger", foreground="#FF4500")
        self.console_box.tag_config("warning", foreground="#FFD700")
        self.console_box.tag_config("info", foreground="#00FF41")

        self.console_box.insert("0.0", ">> 系统初始化完成。引擎就绪。\n", "info")
        self.console_box.configure(state="disabled")

        # 3. 底部隐藏的导出按钮
        self.export_btn = ctk.CTkButton(self.main_frame, text="导出审计报告", 
                                        fg_color="#28a745", hover_color="#218838", height=40, command=self.export_report)

    def switch_mode(self, mode):
        self.current_mode = mode
        self.export_btn.pack_forget() # 切换模式时隐藏导出按钮
        
        # 动态切换输入界面
        if mode == "DB":
            self.path_entry.pack_forget()
            self.db_input_frame.pack(side="left", fill="x", expand=True)
            for entry in self.db_entries:
                entry.delete(0, 'end')
        else:
            self.db_input_frame.pack_forget()
            self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
            self.path_entry.delete(0, 'end')
            
            tips = {
                "FILE": "请输入待检查的文件或文件夹路径...",
                "WEB": "请输入入口网址 (例如 https://example.net/)",
                "IMAGE": "请输入待检查的图片或图片所在文件夹路径..."
            }
            self.path_entry.configure(placeholder_text=tips[mode])

        self.log_to_terminal(f"已切换至 [{mode}] 引擎模式。等待接入目标参数...")

    def log_to_terminal(self, message, is_warning=False, is_danger=False):
        """线程安全的终端日志输出"""
        def update_ui():
            self.console_box.configure(state="normal")
            if is_danger:
                color_tag = "danger"
                prefix = "[!!!]"
            elif is_warning:
                color_tag = "warning"
                prefix = "[!]"
            else:
                color_tag = "info"
                prefix = ">>"
            
            # 插入文本并附加预定义好的颜色标签
            self.console_box.insert("end", f"{prefix} {message}\n", color_tag)
            self.console_box.see("end") 
            self.console_box.configure(state="disabled")
            
        self.after(0, update_ui)

    def start_scan(self):
        target_payload = None
        display_target = ""

        # 1. 收集与校验输入参数
        if self.current_mode == "DB":
            host = self.db_host.get().strip() or "localhost"
            port = self.db_port.get().strip() or "3306"
            user = self.db_user.get().strip()
            pwd = self.db_pass.get().strip()
            db = self.db_name.get().strip()

            if not all([user, pwd, db]):
                self.log_to_terminal("访问拒绝：数据库账号、密码及库名不能为空！", is_warning=True)
                return
            
            # 使用字典传递，避免密码内包含逗号导致解析崩溃
            target_payload = {"host": host, "port": port, "user": user, "pwd": pwd, "db": db}
            display_target = f"{user}:***@{host}:{port}/{db}" # 日志脱敏显示
            
            # 锁定 UI
            for entry in self.db_entries:
                entry.configure(state="disabled")
        else:
            path_val = self.path_entry.get().strip().strip(' "\'').strip()
            if not path_val:
                self.log_to_terminal("访问拒绝：未输入目标参数！", is_warning=True)
                return
                
            if self.current_mode in ["FILE", "IMAGE"]:
                path_val = os.path.normpath(path_val)
                
            target_payload = path_val
            display_target = path_val
            
            # 锁定 UI
            self.path_entry.configure(state="disabled")

        # 2. 锁定通用 UI 组件
        self.scan_btn.configure(state="disabled", text="引擎运转中...")
        for btn in self.nav_buttons:
            btn.configure(state="disabled")
        self.export_btn.pack_forget() 
        
        # 清屏
        self.console_box.configure(state="normal")
        self.console_box.delete("1.0", "end") 
        self.console_box.configure(state="disabled")
        
        self.log_to_terminal(f"正在建立安全连接，挂载目标: {display_target} ...")
        
        # 3. 启动后台工作线程
        threading.Thread(target=self._run_engine_thread, args=(target_payload,), daemon=True).start()

    def _run_engine_thread(self, target_payload):
        """在后台线程调用真正的核心扫描引擎"""
        try:
            summary = None
            if self.current_mode == "FILE":
                scanner = FileScanner()
                summary = scanner.scan_path(target_payload)
                
            elif self.current_mode == "DB":
                # 解包字典传参
                scanner = DBScanner(target_payload["host"], target_payload["port"], 
                                    target_payload["user"], target_payload["pwd"], 
                                    target_payload["db"])
                summary = scanner.scan()
                
            elif self.current_mode == "WEB":
                scanner = WebScanner(start_url=target_payload, max_depth=2)
                summary = scanner.scan()
                
            elif self.current_mode == "IMAGE":
                scanner = ImageScanner()
                summary = scanner.scan_path(target_payload)

            if summary:
                self.current_summary = summary
                self._display_results(summary)

        except Exception as e:
            self.log_to_terminal(f"引擎发生致命异常: {e}", is_danger=True)
            
        finally:
            # 扫描结束，在主线程恢复所有 UI 状态
            def restore_ui():
                self.scan_btn.configure(state="normal", text="▶ 启动核查引擎")
                self.path_entry.configure(state="normal")
                for entry in self.db_entries:
                    entry.configure(state="normal")
                for btn in self.nav_buttons:
                    btn.configure(state="normal")
            self.after(0, restore_ui)

    def _display_results(self, summary):
        """优化后的矩阵显示逻辑，增强条目区分度"""
        self.log_to_terminal("\n" + "="*55)
        self.log_to_terminal(f"审计任务: {summary.task_name}")
        self.log_to_terminal(f"扫描穿透总数: {summary.total_scanned}")
        self.log_to_terminal(f"捕获涉密/异常告警: {summary.total_secrets} 条", is_danger=(summary.total_secrets > 0))
        self.log_to_terminal("="*55 + "\n")

        if summary.total_secrets == 0:
            self.log_to_terminal("安全区：未检测到任何涉密违规特征。")
            return

        limit = 30 # 适当增加显示上限
        for i, res in enumerate(summary.results[:limit], start=1):
            if res.error_msg:
                continue # 终端仅展示有效告警，减少杂音
            
            # 条目头部：带序号和来源
            is_high_risk = any(k in res.keyword for k in ["加密", "异常", "状态"])
            
            self.log_to_terminal(f"[{i:02d}] ------------------------------------------", is_danger=is_high_risk)
            self.log_to_terminal(f"来源: {res.source_path}")
            self.log_to_terminal(f"位置: {res.line_number} | 特征: {res.keyword}", is_warning=True)
            self.log_to_terminal(f"证据: {res.context[:100]}...")
            self.log_to_terminal("") 
            
            time.sleep(0.01) 
            
        if summary.total_secrets > limit:
            self.log_to_terminal(f"--- 数据流过载，剩余 {summary.total_secrets - limit} 条明细请查看完整导出报告 ---", is_warning=True)

        # 每次展示新结果时，重置并显示导出按钮
        def show_export_btn():
            self.export_btn.configure(state="normal", text="导出审计报告")
            self.export_btn.pack(side="right", pady=10, padx=20)
            
        self.after(0, show_export_btn)

    def export_report(self):
        if not self.current_summary:
            return
            
        self.log_to_terminal("\n正在启动 ReportManager 编制结构化审计报告...", is_warning=True)
        
        # =========================================================================
        # [修复BUG] 过滤 Excel 无法解析的非法 ASCII 控制字符，防止 openpyxl 崩溃
        # =========================================================================
        ILLEGAL_CHARACTERS_RE = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')
        for res in self.current_summary.results:
            if isinstance(res.context, str):
                res.context = ILLEGAL_CHARACTERS_RE.sub('', res.context)
            if isinstance(res.keyword, str):
                res.keyword = ILLEGAL_CHARACTERS_RE.sub('', res.keyword)
            if isinstance(res.source_path, str):
                res.source_path = ILLEGAL_CHARACTERS_RE.sub('', res.source_path)

        # 提交给核心引擎进行报告生成
        reporter = ReportManager()
        try:
            report_path = reporter.generate_excel_report(self.current_summary)
            if report_path:
                self.log_to_terminal("审计报告已成功封存入库！")
                self.log_to_terminal(f"物理地址: {report_path}")
                self.export_btn.configure(text="报告已导出", state="disabled")
                
                # 延迟 2 秒后恢复按钮状态，允许在当前窗口继续对同一次结果重复导出
                def reset_export_btn():
                    self.export_btn.configure(text="导出审计报告", state="normal")
                self.after(2000, reset_export_btn)
        except Exception as e:
            self.log_to_terminal(f"导出失败: {e}", is_danger=True)


if __name__ == "__main__":
    app = DLPScannerApp()
    app.mainloop()