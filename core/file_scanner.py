# core/file_scanner.py
import os
import ctypes
from models.data_models import ScanResult
from models.data_models import ScanSummary
from utils.regex_utils import extract_secrets_from_text
from utils.doc_parsers import parse_txt, parse_docx, parse_xlsx, parse_pptx, parse_pdf, parse_xls, parse_doc, parse_ppt
from utils.file_utils import get_real_extension

def is_file_hidden(filepath: str) -> bool:
    """
    跨平台检查文件是否具有隐藏属性。
    兼容 Windows 底层属性以及 Linux/Mac 的点号前缀规则。
    """
    name = os.path.basename(filepath)
    if name.startswith('.'):
        return True
    try:
        # 调用 Windows API 检查 FILE_ATTRIBUTE_HIDDEN (0x02)
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
        return bool(attrs & 2)
    except AttributeError:
        return False

class FileScanner:
    def __init__(self):
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
        
    def scan_path(self, target_path: str) -> ScanSummary:
        """
        智能扫描入口：自动判断是单个文件还是文件夹，并展开遍历。
        包含对隐藏文件的深度挖掘机制。
        """
        all_results = []
        total_files = 0
        ext_counts = {}
        
        # 内部函数：用于处理单个文件并更新计数器
        def process_file(file_path):
            nonlocal total_files # 使用外层变量
            total_files += 1
            real_ext = get_real_extension(file_path)
            # 记录文件类型统计 (即使它不在支持的 parser 里也统计一下，方便报告展示)
            ext_counts[real_ext] = ext_counts.get(real_ext, 0) + 1
            
            # 检查文件隐藏状态，并在展示路径中进行高亮标注
            hidden_status = is_file_hidden(file_path)
            display_path = f"[被隐藏的文件] {file_path}" if hidden_status else file_path
            
            # 分发解析
            file_results = self._dispatch_file(file_path, display_path)
            
            # 若文件被隐藏但未发现文本层面的涉密内容，仍作为异常行为上报
            if hidden_status and not file_results:
                all_results.append(ScanResult(
                    source_type="FILE",
                    source_path=display_path,
                    keyword="[状态异常]",
                    line_number="文件属性",
                    context="系统底层检测到该文件被用户刻意隐藏，可能存在规避检查的嫌疑，建议人工核查。"
                ))
            else:
                all_results.extend(file_results)

        # 1. 扫描单个文件
        if os.path.isfile(target_path):
            process_file(target_path)
            
        # 2. 遍历整个文件夹
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file_name in files:
                    # 确保无死角扫描，移除跳过特定文件名的逻辑
                    file_path = os.path.join(root, file_name)
                    process_file(file_path)
                    
        # 3. 组装并返回终极统计对象
        return ScanSummary(
            task_name="本地文件深度检查",
            total_scanned=total_files,
            total_secrets=len([r for r in all_results if not r.error_msg]), # 只统计真正涉密的，不算报错的
            scanned_details=ext_counts,
            results=all_results
        )

    def _dispatch_file(self, file_path: str, display_path: str) -> list[ScanResult]:
        """
        核心调度逻辑：完全依赖强大的底层透视眼，精准路由。
        """
        real_ext = get_real_extension(file_path)
        
        # 只要透视眼看准了类型，直接分发给对应的解析器
        if real_ext in self.parsers:
            parser_func = self.parsers[real_ext]
            return self._scan_single_file(file_path, display_path, parser_func)
            
        return []

    def _scan_single_file(self, file_path: str, display_path: str, parser_func) -> list[ScanResult]:
        """
        具体的解析和涉密匹配逻辑。
        包含对加密文档的智能拦截与分类。
        """
        results = []
        try:
            for line_num, text in parser_func(file_path):
                # 传入每一行文本，调用正则引擎提取涉密词与上下文
                secrets_found = extract_secrets_from_text(text, line_num)
                
                for secret in secrets_found:
                    result = ScanResult(
                        source_type="FILE",
                        source_path=display_path,
                        keyword=secret['keyword'],
                        line_number=str(secret['line_number']),
                        context=secret['context']
                    )
                    results.append(result)
        except Exception as e:
            error_msg_lower = str(e).lower()
            encrypt_keywords = ['password', 'encrypt', 'protected', 'pwd', 'decryption', '加密']
            
            # 优雅接管异常：区分是文件损坏还是加密保护
            if any(k in error_msg_lower for k in encrypt_keywords):
                # 识别为加密文件，作为有效告警上报（不设置 error_msg）
                results.append(ScanResult(
                    source_type="FILE",
                    source_path=display_path,
                    keyword="[加密文档]",
                    line_number="文档受保护",
                    context="【高危告警】检测到该文件使用了密码加密，系统无法穿透读取内容。建议重点关注并索要密码核查。",
                    is_encrypted=True
                ))
            else:
                # 普通损坏或不支持的异常，设置 error_msg 静默处理
                error_result = ScanResult(
                    source_type="FILE",
                    source_path=display_path,
                    keyword="[无法读取]",
                    line_number="-",
                    context="-",
                    error_msg=f"解析跳过: {str(e)}"
                )
                results.append(error_result)
            
        return results