# ui/main_window.py
import os
import sys
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import customtkinter as ctk
from tkinter import messagebox, simpledialog

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

from core.file_scanner import FileScanner
from core.db_scanner import DBScanTarget, DBScanner
from core.web_scanner import WebScanner
from core.image_scanner import ImageScanner
from models.data_models import ScanResult, ScanSummary
from report.report_manager import ReportManager
from utils.regex_utils import DEFAULT_KEYWORDS_TEXT, configure_runtime_rules

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ALL_DATABASES_LABEL = "全部用户库"


class DLPScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DLP Inspector - 审计自查工具")
        self.geometry("1240x800")
        self.minsize(1020, 650)

        self.current_mode = "FILE"
        self.current_summary: ScanSummary | None = None
        self.current_summaries: list[ScanSummary] | None = None
        self.password_prompt_lock = threading.Lock()

        # ==================== 左侧导航栏 ====================
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="DLP INSPECTOR",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#00FF41"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 25))

        self.btn_all = ctk.CTkButton(self.sidebar_frame, text="综合一键检查", command=lambda: self.switch_mode("ALL"))
        self.btn_all.grid(row=1, column=0, padx=20, pady=8)
        self.btn_file = ctk.CTkButton(self.sidebar_frame, text="文件深度检查", command=lambda: self.switch_mode("FILE"))
        self.btn_file.grid(row=2, column=0, padx=20, pady=8)
        self.btn_db = ctk.CTkButton(self.sidebar_frame, text="数据库文本字段审计", command=lambda: self.switch_mode("DB"))
        self.btn_db.grid(row=3, column=0, padx=20, pady=8)
        self.btn_web = ctk.CTkButton(self.sidebar_frame, text="Web 静态页面扫描", command=lambda: self.switch_mode("WEB"))
        self.btn_web.grid(row=4, column=0, padx=20, pady=8)
        self.btn_img = ctk.CTkButton(self.sidebar_frame, text="图片 OCR 敏感信息扫描", command=lambda: self.switch_mode("IMAGE"))
        self.btn_img.grid(row=5, column=0, padx=20, pady=8)
        self.nav_buttons = [self.btn_all, self.btn_file, self.btn_db, self.btn_web, self.btn_img]

        # ==================== 右侧主工作区 ====================
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.grid_columnconfigure(1, weight=1)

        self.top_action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.top_action_frame.pack(fill="x", pady=(0, 12))

        # 标准单目标输入框：文件/网页/图片共用
        self.path_entry = ctk.CTkEntry(self.top_action_frame, placeholder_text="请输入待检查的文件夹路径...", height=40)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # 数据库输入区：支持“全部用户库”或选择某一个库
        self.db_input_frame = ctk.CTkFrame(self.top_action_frame, fg_color="transparent", height=40)
        self.db_host = ctk.CTkEntry(self.db_input_frame, placeholder_text="主机 IP", height=40)
        self.db_host.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.db_port = ctk.CTkEntry(self.db_input_frame, placeholder_text="端口", width=60, height=40)
        self.db_port.pack(side="left", padx=5)
        self.db_user = ctk.CTkEntry(self.db_input_frame, placeholder_text="用户名", width=90, height=40)
        self.db_user.pack(side="left", padx=5)
        self.db_pass = ctk.CTkEntry(self.db_input_frame, placeholder_text="密码", show="*", width=90, height=40)
        self.db_pass.pack(side="left", padx=5)
        self.db_name = ctk.CTkComboBox(self.db_input_frame, values=[ALL_DATABASES_LABEL], width=180, height=40)
        self.db_name.set(ALL_DATABASES_LABEL)
        self.db_name.pack(side="left", padx=5)
        self.db_fetch_btn = ctk.CTkButton(self.db_input_frame, text="获取库名", width=80, height=40, command=self.fetch_databases)
        self.db_fetch_btn.pack(side="left", padx=(5, 10))
        self.db_entries = [self.db_host, self.db_port, self.db_user, self.db_pass, self.db_name]

        # 综合检查输入区：四类任务可一次填写，后台并发调度
        self.all_input_frame = ctk.CTkFrame(self.top_action_frame, fg_color="transparent")
        self.all_web = ctk.CTkEntry(self.all_input_frame, placeholder_text="网页入口 URL", height=34)
        self.all_file = ctk.CTkEntry(self.all_input_frame, placeholder_text="文件目录路径", height=34)
        self.all_image = ctk.CTkEntry(self.all_input_frame, placeholder_text="图片目录路径", height=34)
        self.all_web.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=3)
        self.all_file.grid(row=1, column=0, sticky="ew", padx=4, pady=3)
        self.all_image.grid(row=1, column=1, sticky="ew", padx=4, pady=3)
        self.all_db_host = ctk.CTkEntry(self.all_input_frame, placeholder_text="DB Host", height=34)
        self.all_db_port = ctk.CTkEntry(self.all_input_frame, placeholder_text="Port", width=65, height=34)
        self.all_db_user = ctk.CTkEntry(self.all_input_frame, placeholder_text="User", width=90, height=34)
        self.all_db_pass = ctk.CTkEntry(self.all_input_frame, placeholder_text="Password", show="*", width=105, height=34)
        self.all_db_name = ctk.CTkComboBox(self.all_input_frame, values=[ALL_DATABASES_LABEL], width=180, height=34)
        self.all_db_name.set(ALL_DATABASES_LABEL)
        self.all_db_fetch_btn = ctk.CTkButton(self.all_input_frame, text="获取库名", width=80, height=34, command=self.fetch_databases_for_all)
        self.all_db_host.grid(row=2, column=0, sticky="ew", padx=4, pady=3)
        self.all_db_port.grid(row=2, column=1, sticky="ew", padx=4, pady=3)
        self.all_db_user.grid(row=3, column=0, sticky="ew", padx=4, pady=3)
        self.all_db_pass.grid(row=3, column=1, sticky="ew", padx=4, pady=3)
        self.all_db_name.grid(row=4, column=0, sticky="ew", padx=4, pady=3)
        self.all_db_fetch_btn.grid(row=4, column=1, sticky="ew", padx=4, pady=3)
        self.all_input_frame.grid_columnconfigure(0, weight=1)
        self.all_input_frame.grid_columnconfigure(1, weight=1)
        self.all_entries = [self.all_web, self.all_file, self.all_image, self.all_db_host, self.all_db_port,
                            self.all_db_user, self.all_db_pass, self.all_db_name]

        self.scan_btn = ctk.CTkButton(
            self.top_action_frame,
            text="▶ 启动核查引擎",
            fg_color="#8B0000",
            hover_color="#600000",
            height=40,
            font=ctk.CTkFont(weight="bold"),
            command=self.start_scan
        )
        self.scan_btn.pack(side="right")

        # 用户侧规则配置：默认就是课程要求的六个关键词，可直接编辑
        self.rule_frame = ctk.CTkFrame(self.main_frame, fg_color="#111111")
        self.rule_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(self.rule_frame, text="检测关键词（可编辑）", text_color="#CCCCCC").pack(side="left", padx=(8, 6))
        self.keyword_entry = ctk.CTkEntry(self.rule_frame, height=34)
        self.keyword_entry.insert(0, DEFAULT_KEYWORDS_TEXT)
        self.keyword_entry.pack(side="left", fill="x", expand=True, padx=5, pady=6)
        self.reset_keyword_btn = ctk.CTkButton(self.rule_frame, text="恢复默认", width=75, height=34, command=self.reset_keywords)
        self.reset_keyword_btn.pack(side="left", padx=5, pady=6)
        self.regex_entry = ctk.CTkEntry(self.rule_frame, placeholder_text="高级正则（可选，逗号/分号/换行分隔）", height=34)
        self.regex_entry.pack(side="left", fill="x", expand=True, padx=5, pady=6)

        # 终端输出
        self.terminal_label = ctk.CTkLabel(self.main_frame, text="[ 实时监控终端 / LIVE MONITOR ]", anchor="w", text_color="#777777")
        self.terminal_label.pack(fill="x")
        self.console_box = ctk.CTkTextbox(self.main_frame, fg_color="#0a0a0a", text_color="#00FF41",
                                          font=ctk.CTkFont(family="Consolas", size=13))
        self.console_box.pack(fill="both", expand=True, pady=(5, 0))
        self.console_box.tag_config("danger", foreground="#FF4500")
        self.console_box.tag_config("warning", foreground="#FFD700")
        self.console_box.tag_config("info", foreground="#00FF41")
        self.console_box.insert("0.0", ">> 系统初始化完成。引擎就绪。\n", "info")
        self.console_box.configure(state="disabled")

        self.export_btn = ctk.CTkButton(self.main_frame, text="导出审计报告",
                                        fg_color="#28a745", hover_color="#218838", height=40, command=self.export_report)
        self.switch_mode("FILE")

    def reset_keywords(self):
        self.keyword_entry.delete(0, "end")
        self.keyword_entry.insert(0, DEFAULT_KEYWORDS_TEXT)

    def switch_mode(self, mode):
        self.current_mode = mode
        self.current_summary = None
        self.current_summaries = None
        self.export_btn.pack_forget()
        self.path_entry.pack_forget()
        self.db_input_frame.pack_forget()
        self.all_input_frame.pack_forget()

        if mode == "DB":
            self.db_input_frame.pack(side="left", fill="x", expand=True)
            if not self.db_port.get().strip():
                self.db_port.insert(0, "3306")
        elif mode == "ALL":
            self.all_input_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))
            if not self.all_db_port.get().strip():
                self.all_db_port.insert(0, "3306")
        else:
            self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
            tips = {
                "FILE": "请输入待检查的文件或文件夹路径...",
                "WEB": "请输入入口网址 (例如 https://example.net/)",
                "IMAGE": "请输入待检查的图片或图片所在文件夹路径...",
            }
            self.path_entry.configure(placeholder_text=tips[mode])

        self.log_to_terminal(f"已切换至 [{mode}] 引擎模式。等待接入目标参数...")

    def log_to_terminal(self, message, is_warning=False, is_danger=False):
        def update_ui():
            self.console_box.configure(state="normal")
            if is_danger:
                color_tag, prefix = "danger", "[!!!]"
            elif is_warning:
                color_tag, prefix = "warning", "[!]"
            else:
                color_tag, prefix = "info", ">>"
            self.console_box.insert("end", f"{prefix} {message}\n", color_tag)
            self.console_box.see("end")
            self.console_box.configure(state="disabled")
        self.after(0, update_ui)

    def _db_selection_to_database(self, selection: str) -> str:
        value = (selection or "").strip()
        if not value or value == ALL_DATABASES_LABEL:
            return ""
        return value

    def _get_db_payload(self, prefix="single") -> dict:
        if prefix == "all":
            host = self.all_db_host.get().strip() or "localhost"
            port = self.all_db_port.get().strip() or "3306"
            user = self.all_db_user.get().strip()
            pwd = self.all_db_pass.get().strip()
            db = self._db_selection_to_database(self.all_db_name.get())
        else:
            host = self.db_host.get().strip() or "localhost"
            port = self.db_port.get().strip() or "3306"
            user = self.db_user.get().strip()
            pwd = self.db_pass.get().strip()
            db = self._db_selection_to_database(self.db_name.get())
        return {"host": host, "port": port, "user": user, "pwd": pwd, "db": db}

    def _build_db_targets(self, payload: dict) -> list[DBScanTarget]:
        host_items = [part.strip() for part in re.split(r"[,;\n]+", payload.get("host", "")) if part.strip()]
        if not host_items:
            host_items = ["localhost"]

        targets: list[DBScanTarget] = []
        for index, host_item in enumerate(host_items, start=1):
            host_part, _, db_override = host_item.partition("/")
            host_name, port = self._split_host_port(host_part, payload.get("port", "3306"))
            targets.append(DBScanTarget(
                host=host_name or "localhost",
                port=int(port or 3306),
                user=payload.get("user", ""),
                password=payload.get("pwd", ""),
                database=(db_override or payload.get("db", "")).strip(),
                label=f"DB{index}:{host_name or 'localhost'}:{int(port or 3306)}",
            ))
        return targets

    def _split_host_port(self, host_text: str, default_port: str) -> tuple[str, int]:
        value = host_text.strip()
        if ":" in value and value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.strip().isdigit():
                return host.strip(), int(port.strip())
        return value, int(default_port or 3306)

    def _scan_db_payload(self, payload: dict) -> ScanSummary:
        targets = self._build_db_targets(payload)
        if len(targets) == 1:
            target = targets[0]
            return DBScanner(
                target.host,
                target.port,
                target.user,
                target.password,
                target.database,
                target_label=target.label,
            ).scan()
        self.log_to_terminal(f"DB batch audit targets: {len(targets)}; submitting text-field scans concurrently.")
        return DBScanner.scan_targets(targets, max_workers=min(4, len(targets)))

    def fetch_databases(self):
        payload = self._get_db_payload("single")
        self._fetch_databases_to_widget(payload, self.db_name)

    def fetch_databases_for_all(self):
        payload = self._get_db_payload("all")
        self._fetch_databases_to_widget(payload, self.all_db_name)

    def _fetch_databases_to_widget(self, payload: dict, target_widget):
        if not payload["user"] or not payload["pwd"]:
            self.log_to_terminal("需要先填写数据库用户名和密码。", is_warning=True)
            return

        def worker():
            try:
                first_target = self._build_db_targets(payload)[0]
                dbs = DBScanner.list_databases(first_target.host, first_target.port, payload["user"], payload["pwd"])

                def apply_result():
                    values = [ALL_DATABASES_LABEL] + dbs
                    target_widget.configure(values=values)
                    target_widget.set(ALL_DATABASES_LABEL)
                    if dbs:
                        self.log_to_terminal(f"已获取可访问数据库：{', '.join(dbs)}；可选择单库或保留 [{ALL_DATABASES_LABEL}]。")
                    else:
                        self.log_to_terminal("未发现可访问的非系统数据库。", is_warning=True)
                self.after(0, apply_result)
            except Exception as e:
                self.log_to_terminal(f"获取库名失败: {e}", is_danger=True)
        threading.Thread(target=worker, daemon=True).start()

    def _apply_runtime_rules(self):
        keyword_text = self.keyword_entry.get().strip()
        regex_text = self.regex_entry.get().strip()
        rule_count = configure_runtime_rules(keyword_text, regex_text, include_default_regex=True)
        self.log_to_terminal(f"已启用当前检测关键词/正则规则，共 {rule_count} 条有效规则。")

    def start_scan(self):
        mode = self.current_mode
        target_payload = None
        display_target = ""
        self._apply_runtime_rules()

        if mode == "DB":
            payload = self._get_db_payload("single")
            if not payload["user"] or not payload["pwd"]:
                self.log_to_terminal("访问拒绝：数据库账号和密码不能为空。", is_warning=True)
                return
            target_payload = payload
            display_target = f"{payload['user']}:***@{payload['host']}:{payload['port']}/{payload['db'] or ALL_DATABASES_LABEL}"
        elif mode == "ALL":
            payload = {
                "web": self.all_web.get().strip().strip(' "\''),
                "file": os.path.normpath(self.all_file.get().strip().strip(' "\'')) if self.all_file.get().strip() else "",
                "image": os.path.normpath(self.all_image.get().strip().strip(' "\'')) if self.all_image.get().strip() else "",
                "db": self._get_db_payload("all"),
            }
            has_db = bool(payload["db"]["user"] and payload["db"]["pwd"])
            if not any([payload["web"], payload["file"], payload["image"], has_db]):
                self.log_to_terminal("综合检查至少需要填写一个任务参数。", is_warning=True)
                return
            target_payload = payload
            display_target = "综合任务"
        else:
            path_val = self.path_entry.get().strip().strip(' "\'').strip()
            if not path_val:
                self.log_to_terminal("访问拒绝：未输入目标参数！", is_warning=True)
                return
            if mode in ["FILE", "IMAGE"]:
                path_val = os.path.normpath(path_val)
            target_payload = path_val
            display_target = path_val

        self._lock_ui()
        self.export_btn.pack_forget()
        self.current_summary = None
        self.current_summaries = None
        self.console_box.configure(state="normal")
        self.console_box.delete("1.0", "end")
        self.console_box.configure(state="disabled")
        self.log_to_terminal(f"正在建立安全连接，挂载目标: {display_target} ...")
        threading.Thread(target=self._run_engine_thread, args=(mode, target_payload), daemon=True).start()

    def _lock_ui(self):
        self.scan_btn.configure(state="disabled", text="引擎运转中...")
        for widget in [self.path_entry, self.db_fetch_btn, self.all_db_fetch_btn, self.reset_keyword_btn]:
            widget.configure(state="disabled")
        for entry in self.db_entries + self.all_entries + [self.keyword_entry, self.regex_entry]:
            entry.configure(state="disabled")
        for btn in self.nav_buttons:
            btn.configure(state="disabled")

    def _unlock_ui(self):
        self.scan_btn.configure(state="normal", text="▶ 启动核查引擎")
        for widget in [self.path_entry, self.db_fetch_btn, self.all_db_fetch_btn, self.reset_keyword_btn]:
            widget.configure(state="normal")
        for entry in self.db_entries + self.all_entries + [self.keyword_entry, self.regex_entry]:
            entry.configure(state="normal")
        for btn in self.nav_buttons:
            btn.configure(state="normal")

    def _ask_password_for_file(self, file_path: str) -> str | None:
        """从后台扫描线程请求主线程弹出密码输入框，并串行化多个加密文件的密码提示。"""
        with self.password_prompt_lock:
            event = threading.Event()
            holder: dict[str, str | None] = {"password": None}

            def ask():
                holder["password"] = simpledialog.askstring(
                    title="加密文件需要密码",
                    prompt=f"检测到加密或受保护文件：\n{file_path}\n\n请输入密码继续扫描；取消则记录为加密风险。",
                    show="*",
                    parent=self
                )
                event.set()

            self.after(0, ask)
            event.wait()
            return holder["password"]

    def _run_engine_thread(self, mode, target_payload):
        try:
            if mode == "FILE":
                summary = FileScanner(max_workers=4, password_provider=self._ask_password_for_file).scan_path(target_payload)
                self.current_summary = summary
                self._display_results(summary)
            elif mode == "DB":
                summary = self._scan_db_payload(target_payload)
                self.current_summary = summary
                self._display_results(summary)
            elif mode == "WEB":
                summary = WebScanner(start_url=target_payload, max_depth=2).scan()
                self.current_summary = summary
                self._display_results(summary)
            elif mode == "IMAGE":
                summary = ImageScanner().scan_path(target_payload)
                self.current_summary = summary
                self._display_results(summary)
            elif mode == "ALL":
                summaries = self._run_integrated_tasks(target_payload)
                self.current_summaries = summaries
                merged = self._merge_summaries(summaries)
                self.current_summary = merged
                self._display_results(merged)
        except Exception as e:
            self.log_to_terminal(f"引擎发生致命异常: {e}", is_danger=True)
        finally:
            self.after(0, self._unlock_ui)

    def _run_integrated_tasks(self, payload: dict) -> list[ScanSummary]:
        """综合模式：四类任务可同时启动，失败任务也以 error summary 进入总报告。"""
        tasks = []
        if payload.get("web"):
            tasks.append(("Web 静态页面扫描", lambda: WebScanner(start_url=payload["web"], max_depth=2).scan()))

        db_payload = payload.get("db", {})
        if db_payload.get("user") and db_payload.get("pwd"):
            tasks.append((
                "数据库文本字段审计",
                lambda: self._scan_db_payload(db_payload)
            ))

        if payload.get("file"):
            tasks.append((
                "本地文件深度检查",
                lambda: FileScanner(max_workers=4, password_provider=self._ask_password_for_file).scan_path(payload["file"])
            ))

        if payload.get("image"):
            tasks.append(("图片 OCR 敏感信息扫描", lambda: ImageScanner().scan_path(payload["image"])))

        if not tasks:
            return []

        summaries: list[ScanSummary] = []
        max_workers = min(4, len(tasks))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            for task_name, task_func in tasks:
                self.log_to_terminal(f"[综合] 已提交任务：{task_name}")
                future_map[executor.submit(task_func)] = task_name

            for future in as_completed(future_map):
                task_name = future_map[future]
                try:
                    summary = future.result()
                    self.log_to_terminal(f"[综合] 完成任务：{task_name}，扫描 {summary.total_scanned}，命中 {summary.total_secrets}")
                except Exception as e:
                    summary = self._task_error_summary(task_name, str(e))
                    self.log_to_terminal(f"[综合] 任务失败：{task_name}：{e}", is_danger=True)
                summaries.append(summary)

        return summaries

    def _task_error_summary(self, task_name: str, message: str) -> ScanSummary:
        return ScanSummary(
            task_name=task_name,
            total_scanned=0,
            total_secrets=0,
            scanned_details={},
            results=[ScanResult(
                source_type="TASK",
                source_path=task_name,
                keyword="[任务失败]",
                line_number="-",
                context="-",
                error_msg=message
            )]
        )

    def _merge_summaries(self, summaries: list[ScanSummary]) -> ScanSummary:
        details = {}
        results = []
        for summary in summaries:
            details[f"{summary.task_name} - scanned"] = summary.total_scanned
            details[f"{summary.task_name} - findings"] = len([r for r in summary.results if not r.error_msg])
            details[f"{summary.task_name} - errors"] = len([r for r in summary.results if r.error_msg])
            results.extend(summary.results)
        return ScanSummary(
            task_name="综合涉密信息检查",
            total_scanned=sum(summary.total_scanned for summary in summaries),
            total_secrets=len([r for r in results if not r.error_msg]),
            scanned_details=details,
            results=results
        )

    def _display_results(self, summary):
        self.log_to_terminal("\n" + "=" * 55)
        self.log_to_terminal(f"审计任务: {summary.task_name}")
        error_count = len([res for res in summary.results if res.error_msg])
        self.log_to_terminal(f"扫描对象总数: {summary.total_scanned}")
        self.log_to_terminal(f"捕获涉密/异常告警: {summary.total_secrets} 条", is_danger=(summary.total_secrets > 0))
        self.log_to_terminal(f"解析/访问异常: {error_count} 条", is_warning=(error_count > 0))
        self.log_to_terminal("=" * 55 + "\n")

        if summary.total_secrets == 0:
            if error_count > 0:
                self.log_to_terminal("未检测到涉密违规特征，但存在解析/访问异常，建议导出报告后人工复核。", is_warning=True)
            else:
                self.log_to_terminal("安全区：未检测到任何涉密违规特征。")

        limit = 30
        displayed = 0
        for res in summary.results:
            if res.error_msg:
                continue
            displayed += 1
            if displayed > limit:
                break
            is_high_risk = any(k in res.keyword for k in ["加密", "异常", "状态", "隐藏", "后缀"])
            self.log_to_terminal(f"[{displayed:02d}] ------------------------------------------", is_danger=is_high_risk)
            self.log_to_terminal(f"来源: {res.source_path}")
            self.log_to_terminal(f"位置: {res.line_number} | 特征: {res.keyword}", is_warning=True)
            self.log_to_terminal(f"证据: {res.context[:100]}...")
            self.log_to_terminal("")
            time.sleep(0.005)

        if summary.total_secrets > limit:
            self.log_to_terminal(f"--- 数据流过载，剩余 {summary.total_secrets - limit} 条明细请查看完整导出报告 ---", is_warning=True)

        def show_export_btn():
            self.export_btn.configure(state="normal", text="导出审计报告")
            self.export_btn.pack(side="right", pady=10, padx=20)
        self.after(0, show_export_btn)

    def export_report(self):
        if not self.current_summary and not self.current_summaries:
            return
        self.export_btn.configure(state="disabled", text="报告导出中...")
        illegal_characters_re = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')
        summaries = self.current_summaries or [self.current_summary]
        is_combined = bool(self.current_summaries)
        self.log_to_terminal("\n正在后台生成 Excel 明细报告和 HTML 摘要报告...", is_warning=True)

        def worker():
            try:
                for summary in summaries:
                    for res in summary.results:
                        for field in ("context", "keyword", "source_path", "line_number", "error_msg"):
                            value = getattr(res, field, None)
                            if isinstance(value, str):
                                setattr(res, field, illegal_characters_re.sub('', value))

                reporter = ReportManager()
                if is_combined:
                    report_path = reporter.generate_combined_excel_report(summaries)
                    html_path = reporter.generate_combined_html_report(summaries, report_path) if report_path else ""
                else:
                    report_path = reporter.generate_excel_report(summaries[0])
                    html_path = reporter.generate_html_report(summaries[0], report_path) if report_path else ""

                def finish_success():
                    if report_path:
                        self.log_to_terminal("审计报告已成功封存入库！")
                        self.log_to_terminal(f"Excel 明细报告: {report_path}")
                        if html_path:
                            self.log_to_terminal(f"HTML 摘要报告: {html_path}")
                        self.export_btn.configure(text="报告已导出", state="disabled")
                        self.after(2000, lambda: self.export_btn.configure(text="导出审计报告", state="normal"))
                    else:
                        self.log_to_terminal("导出失败：ReportManager 未返回有效报告路径。", is_danger=True)
                        self.export_btn.configure(text="导出审计报告", state="normal")

                self.after(0, finish_success)
            except Exception as e:
                error_message = str(e)

                def finish_error():
                    self.log_to_terminal(f"导出失败: {error_message}", is_danger=True)
                    self.export_btn.configure(text="导出审计报告", state="normal")

                self.after(0, finish_error)

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = DLPScannerApp()
    app.mainloop()
