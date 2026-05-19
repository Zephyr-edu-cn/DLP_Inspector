# ui/main_window.py
import os
import sys

# 获取当前文件所在目录与项目根目录
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)

# 强制将工作目录挂载至项目根目录
# 确保底层核心引擎 (Scanner) 能够通过相对路径正确加载 rules.txt 等敏感词字典
os.chdir(root_dir)

# 将根目录动态注入 Python 环境变量，保障跨目录模块调用的稳定性
if root_dir not in sys.path:
    sys.path.append(root_dir)

import time
import threading
import customtkinter as ctk
from tkinter import messagebox

# 导入安全审计底层引擎
from core.file_scanner import FileScanner
from core.db_scanner import DBScanner
from core.web_scanner import WebScanner
from core.image_scanner import ImageScanner
from report.report_manager import ReportManager

# 设定 UI 全局主题：深色极客风终端
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class DLPScannerApp(ctk.CTk):
    """DLP 数据防泄漏涉密检查系统 - 图形化主终端"""
    
    def __init__(self):
        super().__init__()

        self.title("DLP Inspector - 安全审计终端")
        self.geometry("1050x700")
        self.minsize(800, 500)
        
        # 系统状态指针
        self.current_mode = "FILE" 
        self.current_summary = None 

        # ==================== 左侧导航系统 ====================
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="DLP INSPECTOR", 
                                       font=ctk.CTkFont(size=18, weight="bold"), text_color="#00FF41")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        # 引擎切换开关
        self.btn_file = ctk.CTkButton(self.sidebar_frame, text="文件深度检查", command=lambda: self.switch_mode("FILE"))
        self.btn_file.grid(row=1, column=0, padx=20, pady=10)

        self.btn_db = ctk.CTkButton(self.sidebar_frame, text="数据库文本字段审计", command=lambda: self.switch_mode("DB"))
        self.btn_db.grid(row=2, column=0, padx=20, pady=10)

        self.btn_web = ctk.CTkButton(self.sidebar_frame, text="Web 静态页面扫描", command=lambda: self.switch_mode("WEB"))
        self.btn_web.grid(row=3, column=0, padx=20, pady=10)

        self.btn_img = ctk.CTkButton(self.sidebar_frame, text="图片 OCR 敏感信息扫描", command=lambda: self.switch_mode("IMAGE"))
        self.btn_img.grid(row=4, column=0, padx=20, pady=10)

        # 构建导航按钮组，便于在执行扫描任务时统一进行并发锁定
        self.nav_buttons = [self.btn_file, self.btn_db, self.btn_web, self.btn_img]

        # ==================== 右侧主工作矩阵 ====================
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.grid_columnconfigure(1, weight=1)

        # 1. 顶部目标参数下发区
        self.top_action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.top_action_frame.pack(fill="x", pady=(0, 20))

        # --- 1.1 标准单行输入通道 (支持：文件、网页、图片) ---
        self.path_entry = ctk.CTkEntry(self.top_action_frame, placeholder_text="请输入待检查的文件夹路径...", height=40)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # --- 1.2 数据库专用动态参数面板 (初始状态隐藏) ---
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
        
        self.db_entries = [self.db_host, self.db_port, self.db_user, self.db_pass, self.db_name]

        # 引擎点火按钮
        self.scan_btn = ctk.CTkButton(self.top_action_frame, text="▶ 启动核查引擎", 
                                      fg_color="#8B0000", hover_color="#600000", 
                                      height=40, font=ctk.CTkFont(weight="bold"), command=self.start_scan)
        self.scan_btn.pack(side="right")

        # 2. 实时审计监控终端
        self.terminal_label = ctk.CTkLabel(self.main_frame, text="[ 实时监控终端 / LIVE MONITOR ]", anchor="w", text_color="#777777")
        self.terminal_label.pack(fill="x")

        self.console_box = ctk.CTkTextbox(self.main_frame, fg_color="#0a0a0a", text_color="#00FF41", 
                                          font=ctk.CTkFont(family="Consolas", size=13))
        self.console_box.pack(fill="both", expand=True, pady=(5, 0))
        
        # 预注册终端日志分级颜色渲染字典
        self.console_box.tag_config("danger", foreground="#FF4500")
        self.console_box.tag_config("warning", foreground="#FFD700")
        self.console_box.tag_config("info", foreground="#00FF41")

        self.console_box.insert("0.0", ">> 系统初始化完成。引擎就绪。\n", "info")
        self.console_box.configure(state="disabled")

        # 3. 数据防泄漏导出控制器 (默认挂起隐藏)
        self.export_btn = ctk.CTkButton(self.main_frame, text="导出审计报告", 
                                        fg_color="#28a745", hover_color="#218838", height=40, command=self.export_report)

    def switch_mode(self, mode):
        """核心模块调度器：响应左侧导航栏的引擎切换指令"""
        self.current_mode = mode
        self.export_btn.pack_forget() 
        
        # UI 面板流转机制
        if mode == "DB":
            self.path_entry.pack_forget()
            self.db_input_frame.pack(side="left", fill="x", expand=True)
            for entry in self.db_entries:
                entry.delete(0, 'end')
        else:
            self.db_input_frame.pack_forget()
            self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
            self.path_entry.delete(0, 'end')
            
            # 根据模块自适应占位提示
            tips = {
                "FILE": "请输入待检查的文件或文件夹路径...",
                "WEB": "请输入入口网址 (例如 https://example.net/)",
                "IMAGE": "请输入待检查的图片或图片所在文件夹路径..."
            }
            self.path_entry.configure(placeholder_text=tips[mode])

        self.log_to_terminal(f"已切换至 [{mode}] 引擎模式。等待接入目标参数...")

    def log_to_terminal(self, message, is_warning=False, is_danger=False):
        """线程安全的日志输出管道：将核心引擎的扫描状态投影至界面 UI"""
        def update_ui():
            self.console_box.configure(state="normal")
            
            # 威胁等级着色器
            if is_danger:
                color_tag = "danger"
                prefix = "[!!!]"
            elif is_warning:
                color_tag = "warning"
                prefix = "[!]"
            else:
                color_tag = "info"
                prefix = ">>"
            
            self.console_box.insert("end", f"{prefix} {message}\n", color_tag)
            self.console_box.see("end") # 自动滚动追尾
            self.console_box.configure(state="disabled")
            
        # 将 UI 渲染任务推入 Tkinter 的主事件循环
        self.after(0, update_ui)

    def start_scan(self):
        """扫描流程控制器：负责数据收集、校验、系统锁定与线程派发"""
        target_payload = None
        display_target = ""

        # 阶段一：目标参数解包与数据清洗
        if self.current_mode == "DB":
            host = self.db_host.get().strip() or "localhost"
            port = self.db_port.get().strip() or "3306"
            user = self.db_user.get().strip()
            pwd = self.db_pass.get().strip()
            db = self.db_name.get().strip()

            if not all([user, db]):
                self.log_to_terminal("访问拒绝：数据库账号与库名不能为空！", is_warning=True)
                return
            
            # 采用字典封装传输，防止密码特殊字符引发解析异常
            target_payload = {"host": host, "port": port, "user": user, "pwd": pwd, "db": db}
            display_target = f"{user}:***@{host}:{port}/{db}" # 日志脱敏处理
            
            for entry in self.db_entries:
                entry.configure(state="disabled")
        else:
            path_val = self.path_entry.get().strip().strip(' "\'').strip()
            if not path_val:
                self.log_to_terminal("访问拒绝：未输入目标参数！", is_warning=True)
                return
                
            # 仅对物理存储介质路径进行反斜杠归一化
            if self.current_mode in ["FILE", "IMAGE"]:
                path_val = os.path.normpath(path_val)
                
            target_payload = path_val
            display_target = path_val
            self.path_entry.configure(state="disabled")

        # 阶段二：接管并锁定全局界面，防止并发指令冲突
        self.scan_btn.configure(state="disabled", text="引擎运转中...")
        for btn in self.nav_buttons:
            btn.configure(state="disabled")
        self.export_btn.pack_forget() 
        
        self.console_box.configure(state="normal")
        self.console_box.delete("1.0", "end") 
        self.console_box.configure(state="disabled")
        
        self.log_to_terminal(f"正在建立安全连接，挂载目标: {display_target} ...")
        
        # 阶段三：切分工作流，启动异步守护线程进行重量级计算
        threading.Thread(target=self._run_engine_thread, args=(target_payload,), daemon=True).start()

    def _run_engine_thread(self, target_payload):
        """核心后台执行器：调度底层 Scanner 进行静默检查"""
        try:
            summary = None
            if self.current_mode == "FILE":
                scanner = FileScanner()
                summary = scanner.scan_path(target_payload)
                
            elif self.current_mode == "DB":
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
            # 生命周期终止，释放系统锁并归还界面控制权
            def restore_ui():
                self.scan_btn.configure(state="normal", text="▶ 启动核查引擎")
                self.path_entry.configure(state="normal")
                for entry in self.db_entries:
                    entry.configure(state="normal")
                for btn in self.nav_buttons:
                    btn.configure(state="normal")
            self.after(0, restore_ui)

    def _display_results(self, summary):
        """审计数据可视化映射器：对 ScanSummary 进行终端矩阵化展示"""
        self.log_to_terminal("\n" + "="*55)
        self.log_to_terminal(f"审计任务: {summary.task_name}")
        self.log_to_terminal(f"扫描对象总数: {summary.total_scanned}")
        self.log_to_terminal(f"捕获涉密/异常告警: {summary.total_secrets} 条", is_danger=(summary.total_secrets > 0))
        self.log_to_terminal("="*55 + "\n")

        if summary.total_secrets == 0:
            self.log_to_terminal("安全区：未检测到任何涉密违规特征。")
            return

        limit = 30 # 设定控制台缓冲阈值，防止 UI 渲染过载
        for i, res in enumerate(summary.results[:limit], start=1):
            
            # 捕获并渲染底层引擎发出的异常告警（如OCR解析失败、文件加密损坏等）
            if res.error_msg:
                self.log_to_terminal(f"[{i:02d}] ------------------------------------------", is_warning=True)
                self.log_to_terminal(f"[引擎警告]: {res.source_path}", is_warning=True)
                self.log_to_terminal(f"异常原因: {res.error_msg}", is_warning=True)
                self.log_to_terminal("") 
                continue 
            
            # 渲染正常命中的涉密违规明细
            is_high_risk = any(k in res.keyword for k in ["加密", "异常", "状态"])
            
            self.log_to_terminal(f"[{i:02d}] ------------------------------------------", is_danger=is_high_risk)
            self.log_to_terminal(f"来源: {res.source_path}")
            self.log_to_terminal(f"位置: {res.line_number} | 特征: {res.keyword}", is_warning=True)
            self.log_to_terminal(f"证据: {res.context[:100]}...")
            self.log_to_terminal("") 
            
            time.sleep(0.01) # 增加微小阻断，增强极客风格的打字机流式输出感
            
        if summary.total_secrets > limit:
            self.log_to_terminal(f"--- 数据流过载，剩余 {summary.total_secrets - limit} 条明细请查看完整导出报告 ---", is_warning=True)

        # 结果推流完毕，唤醒底层报表导出器
        self.after(0, lambda: self.export_btn.pack(side="right", pady=10, padx=20))

    def export_report(self):
        """编排并调用 ReportManager 生成 Excel 结构化审计物料"""
        if not self.current_summary:
            return
            
        self.log_to_terminal("\n正在启动 ReportManager 编制结构化审计报告...", is_warning=True)
        reporter = ReportManager()
        report_path = reporter.generate_excel_report(self.current_summary)
        
        if report_path:
            self.log_to_terminal("审计报告已成功封存入库！")
            self.log_to_terminal(f"物理地址: {report_path}")
            self.export_btn.configure(text="报告已导出", state="disabled")


if __name__ == "__main__":
    app = DLPScannerApp()
    app.mainloop()
