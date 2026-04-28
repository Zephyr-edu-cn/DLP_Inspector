# core/file_scanner.py
import os
from models.data_models import ScanResult
from utils.regex_utils import extract_secrets_from_text
from utils.doc_parsers import parse_txt, parse_docx, parse_xlsx, parse_pptx, parse_pdf, parse_xls, parse_doc, parse_ppt
from utils.file_utils import get_real_extension

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
        
    def scan_path(self, target_path: str) -> list[ScanResult]:
        """
        智能扫描入口：自动判断是单个文件还是文件夹，并展开遍历。
        """
        all_results = []
        
        # 1. 扫描单个文件
        if os.path.isfile(target_path):
            return self._dispatch_file(target_path)
            
        # 2. 遍历整个文件夹
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file_name in files:
                    # 过滤隐藏文件
                    if file_name.startswith('.'):
                        continue
                    file_path = os.path.join(root, file_name)
                    all_results.extend(self._dispatch_file(file_path))
                    
        return all_results

    def _dispatch_file(self, file_path: str) -> list[ScanResult]:
        """
        核心调度逻辑：完全依赖强大的底层透视眼，精准路由。
        """
        real_ext = get_real_extension(file_path)
        
        # 只要透视眼看准了类型，直接分发给对应的解析器
        if real_ext in self.parsers:
            parser_func = self.parsers[real_ext]
            return self._scan_single_file(file_path, parser_func)
            
        return []

    def _scan_single_file(self, file_path: str, parser_func) -> list[ScanResult]:
        """
        具体的解析和涉密匹配逻辑。
        """
        results = []
        try:
            for line_num, text in parser_func(file_path):
                # 传入每一行文本，调用正则引擎提取涉密词与上下文
                secrets_found = extract_secrets_from_text(text, line_num)
                
                for secret in secrets_found:
                    result = ScanResult(
                        source_type="FILE",
                        source_path=file_path,
                        keyword=secret['keyword'],
                        line_number=secret['line_number'],
                        context=secret['context']
                    )
                    results.append(result)
        except Exception as e:
            # 优雅接管加密、损坏等异常
            error_result = ScanResult(
                source_type="FILE",
                source_path=file_path,
                keyword="[无法读取]",
                line_number="-",
                context="-",
                error_msg=f"解析跳过: {str(e)}"
            )
            results.append(error_result)
            
        return results