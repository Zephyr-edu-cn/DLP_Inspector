# core/image_scanner.py
import os
import logging
from paddleocr import PaddleOCR
from models.data_models import ScanResult
from models.data_models import ScanSummary
from utils.regex_utils import extract_secrets_from_text

logging.disable(logging.DEBUG)  # 禁止PaddleOCR的调试日志输出

class ImageScanner:
    def __init__(self):
        """初始化OCR模型"""
        print("正在初始化AI视觉识别模型 (PaddleOCR)，请稍候...")
        self.ocr = PaddleOCR(use_angle_cls=True, lang='ch', show_log=False, use_gpu=False)  # 只加载中文模型，禁用日志
        self.supported_exts = ('.png', '.jpg', '.jpeg', '.bmp', '.tiff')

    def scan_path(self, target_path) -> ScanSummary:
        results = []
        files_to_scan = []

        if not os.path.exists(target_path):
            print(f"错误：路径 '{target_path}' 不存在！")
            return []
        
        if os.path.isfile(target_path):
            ext = os.path.splitext(target_path)[1].lower()
            if ext in self.supported_exts:
                files_to_scan.append(target_path)
            else:
                print(f"警告：文件 '{target_path}' 不是支持的图片格式，已跳过。")
                return []
        
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    if os.path.splitext(file)[1].lower() in self.supported_exts:
                        files_to_scan.append(os.path.join(root, file))
            
            if not files_to_scan:
                print(f"\n警告: 文件夹中未找到支持的图片。")
                return []
        
        for file_path in files_to_scan:
            try:
                ocr_result = self.ocr.ocr(file_path, cls=True)

                if not ocr_result or not ocr_result[0]:
                    continue

                for idx, line_info in enumerate(ocr_result[0], start=1):
                    text = line_info[1][0]
                    confidence = line_info[1][1]

                    if confidence > 0.8:  # 只处理置信度较高的文本
                        secrets_found = extract_secrets_from_text(text, idx)
                        for secret in secrets_found:
                            results.append(ScanResult(
                                source_type="IMAGE",
                                source_path=file_path,
                                keyword=secret['keyword'],
                                line_number=f"图片文本块 [{idx}]",
                                context=secret['context']
                            ))
            except Exception as e:
                print(f"图片 [{os.path.basename(file_path)}] 解析失败: {e}")
        
        # 统计图片类型分布
        ext_counts = {}
        for f in files_to_scan:
            ext = os.path.splitext(f)[1].lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

        return ScanSummary(
            task_name="图片离线 OCR 检查",
            total_scanned=len(files_to_scan),
            total_secrets=len(results),
            scanned_details=ext_counts,
            results=results
        )
