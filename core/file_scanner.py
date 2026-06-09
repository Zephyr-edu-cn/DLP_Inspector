# core/file_scanner.py
import os
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from models.data_models import ScanResult, ScanSummary
from utils.regex_utils import extract_secrets_from_text
from utils.doc_parsers import parse_txt, parse_docx, parse_xlsx, parse_pptx, parse_pdf, parse_xls, parse_doc, parse_ppt
from utils.file_utils import get_real_extension


PasswordProvider = Callable[[str], str | None]


def is_file_hidden(filepath: str) -> bool:
    """
    跨平台检查文件是否具有隐藏属性。
    兼容 Windows 底层属性以及 Linux/Mac 的点号前缀规则。
    """
    name = os.path.basename(filepath)
    if name.startswith('.'):
        return True
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
        return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
    except AttributeError:
        return False


class FileScanner:
    def __init__(self, max_workers: int = 4, password_provider: PasswordProvider | None = None):
        # 注册所有支持的文件后缀与对应的解析策略
        self.parsers = {
            '.txt': parse_txt,
            '.docx': parse_docx,
            '.xlsx': parse_xlsx,
            '.pptx': parse_pptx,
            '.pdf': parse_pdf,
            '.xls': parse_xls,
            '.doc': parse_doc,
            '.ppt': parse_ppt
        }
        # 普通文件可并发扫描；旧版 Office COM 文件保守串行处理，避免 Word/PowerPoint COM 多线程不稳定
        self.max_workers = max(1, int(max_workers or 1))
        self.password_provider = password_provider

    def scan_path(self, target_path: str) -> ScanSummary:
        """
        智能扫描入口：自动判断是单个文件还是文件夹，并展开遍历。
        先收集任务文件，再对普通文件并发扫描；旧版 COM 文档保守串行扫描。
        """
        file_paths = self._collect_files(target_path)
        all_results: list[ScanResult] = []
        ext_counts: dict[str, int] = {}

        serial_files: list[str] = []
        parallel_files: list[str] = []
        for file_path in file_paths:
            # Use real file type, not declared suffix, so disguised .doc/.ppt files still avoid COM multithreading.
            real_ext_for_schedule = get_real_extension(file_path)
            if real_ext_for_schedule in {'.doc', '.ppt'}:
                serial_files.append(file_path)
            else:
                parallel_files.append(file_path)

        # 并发扫描普通文件，提升大量文件时的吞吐；每个文件仍然独立封装结果
        if self.max_workers > 1 and len(parallel_files) > 1:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_map = {executor.submit(self._process_file, fp): fp for fp in parallel_files}
                for future in as_completed(future_map):
                    real_ext, file_results = future.result()
                    ext_counts[real_ext] = ext_counts.get(real_ext, 0) + 1
                    all_results.extend(file_results)
        else:
            for file_path in parallel_files:
                real_ext, file_results = self._process_file(file_path)
                ext_counts[real_ext] = ext_counts.get(real_ext, 0) + 1
                all_results.extend(file_results)

        # 旧版 Office COM 文件串行处理，避免后台 Office 自动化对象线程冲突
        for file_path in serial_files:
            real_ext, file_results = self._process_file(file_path)
            ext_counts[real_ext] = ext_counts.get(real_ext, 0) + 1
            all_results.extend(file_results)

        return ScanSummary(
            task_name="本地文件深度检查",
            total_scanned=len(file_paths),
            total_secrets=len([r for r in all_results if not r.error_msg]),
            scanned_details=ext_counts,
            results=all_results
        )

    def _collect_files(self, target_path: str) -> list[str]:
        """Collect all files first so the scan can be parallelized safely."""
        if os.path.isfile(target_path):
            return [target_path]
        if os.path.isdir(target_path):
            collected = []
            for root, _, files in os.walk(target_path):
                for file_name in files:
                    collected.append(os.path.join(root, file_name))
            return collected
        return []

    def _process_file(self, file_path: str) -> tuple[str, list[ScanResult]]:
        """处理单个文件，返回真实类型和该文件产生的结果列表。"""
        real_ext = get_real_extension(file_path)
        declared_ext = os.path.splitext(file_path)[1].lower()
        hidden_status = is_file_hidden(file_path)
        display_path = f"[被隐藏的文件] {file_path}" if hidden_status else file_path

        file_results: list[ScanResult] = []

        # 隐藏文件作为独立审计线索记录，即使命中文本规则也保留隐藏属性提示
        if hidden_status:
            file_results.append(ScanResult(
                source_type="FILE",
                source_path=display_path,
                keyword="[隐藏文件]",
                line_number="文件属性",
                context="系统底层检测到该文件具有隐藏属性，可能存在规避检查的嫌疑，建议人工核查。",
                rule_id="SYSTEM_HIDDEN_FILE",
                rule_name="隐藏文件提示",
                risk_level="medium",
                rule_description="隐藏文件属性提示，需人工确认是否存在规避检查行为。"
            ))

        # 后缀伪装/文件类型不匹配提示：声明后缀与真实类型不一致时单独记录
        if declared_ext and real_ext and declared_ext != real_ext:
            file_results.append(ScanResult(
                source_type="FILE",
                source_path=display_path,
                keyword="[后缀伪装]",
                line_number="文件类型",
                context=f"文件扩展名为 {declared_ext}，真实类型识别为 {real_ext}，建议人工复核是否存在规避检查行为。",
                rule_id="SYSTEM_EXTENSION_MISMATCH",
                rule_name="文件后缀与真实类型不一致",
                risk_level="medium",
                rule_description="文件扩展名与内容识别结果不一致，可能存在规避检查风险。"
            ))

        file_results.extend(self._dispatch_file(file_path, display_path, real_ext))
        return real_ext or declared_ext or "unknown", file_results

    def _dispatch_file(self, file_path: str, display_path: str, real_ext: str | None = None) -> list[ScanResult]:
        """根据真实文件类型选择对应解析器。"""
        real_ext = real_ext or get_real_extension(file_path)
        if real_ext in self.parsers:
            parser_func = self.parsers[real_ext]
            return self._scan_single_file(file_path, display_path, parser_func, real_ext)
        return []

    def _iter_parsed_text(self, parser_func, file_path: str, real_ext: str, password: str | None = None):
        """统一调用解析器；PDF / Office 加密文档支持额外 password 参数。"""
        if real_ext in {'.pdf', '.docx', '.xlsx', '.pptx', '.xls', '.doc', '.ppt'}:
            yield from parser_func(file_path, password=password)
        else:
            yield from parser_func(file_path)

    def _scan_single_file(self, file_path: str, display_path: str, parser_func, real_ext: str) -> list[ScanResult]:
        """解析文本并进行涉密匹配；PDF 加密时可请求密码后重试。"""
        try:
            return self._scan_with_parser(file_path, display_path, parser_func, real_ext)
        except Exception as e:
            error_msg_lower = str(e).lower()
            encrypt_keywords = ['password', 'encrypt', 'protected', 'pwd', 'decryption', '加密', '密码']
            is_encrypted_error = any(k in error_msg_lower for k in encrypt_keywords)

            # 加密文件：如果 UI 提供密码回调，则请求用户输入密码并重试解析。
            # PDF 和新版 Office 可较稳定支持；旧版 Office 由 COM 尽力尝试，失败后仍进入风险记录。
            if is_encrypted_error and real_ext in {'.pdf', '.docx', '.xlsx', '.pptx', '.xls', '.doc', '.ppt'} and self.password_provider:
                password = self.password_provider(file_path)
                if password:
                    try:
                        return self._scan_with_parser(file_path, display_path, parser_func, real_ext, password=password)
                    except Exception as retry_error:
                        return [self._encrypted_result(display_path, f"已输入密码但仍无法解密或解析: {retry_error}")]

            if is_encrypted_error:
                return [self._encrypted_result(display_path, "检测到加密或受保护文档，当前未提供可用密码，需人工复核。")]

            return [ScanResult(
                source_type="FILE",
                source_path=display_path,
                keyword="[无法读取]",
                line_number="-",
                context="-",
                error_msg=f"解析跳过: {str(e)}"
            )]

    def _scan_with_parser(self, file_path: str, display_path: str, parser_func, real_ext: str,
                          password: str | None = None) -> list[ScanResult]:
        results: list[ScanResult] = []
        for line_num, text in self._iter_parsed_text(parser_func, file_path, real_ext, password=password):
            secrets_found = extract_secrets_from_text(text, line_num)
            for secret in secrets_found:
                results.append(ScanResult(
                    source_type="FILE",
                    source_path=display_path,
                    keyword=secret['keyword'],
                    line_number=str(secret['line_number']),
                    context=secret['context'],
                    rule_id=secret.get('rule_id', ''),
                    rule_name=secret.get('rule_name', ''),
                    risk_level=secret.get('risk_level', ''),
                    rule_description=secret.get('rule_description', '')
                ))
        return results

    def _encrypted_result(self, display_path: str, message: str) -> ScanResult:
        return ScanResult(
            source_type="FILE",
            source_path=display_path,
            keyword="[加密文档]",
            line_number="文档受保护",
            context=f"【高危告警】{message}",
            rule_id="SYSTEM_ENCRYPTED_FILE",
            rule_name="加密文档提示",
            risk_level="high",
            rule_description="加密或受保护文档无法直接读取，需要人工复核或输入密码继续扫描。",
            is_encrypted=True
        )
