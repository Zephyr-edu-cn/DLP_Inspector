# core/image_scanner.py
import os
import logging
from models.data_models import ScanResult, ScanSummary
from utils.regex_utils import extract_secrets_from_text

logging.disable(logging.DEBUG)  # 禁止PaddleOCR的调试日志输出


class ImageScanner:
    def __init__(self):
        """初始化OCR模型"""
        try:
            from paddleocr import PaddleOCR
        except ImportError as e:
            raise RuntimeError(
                "OCR 依赖未安装。请安装 requirements.txt，"
                "或在已有基础环境中安装 requirements-ocr.txt 和对应 PaddlePaddle 运行时。"
            ) from e

        print("正在初始化 OCR 识别模型 (PaddleOCR)，请稍候...")
        self.ocr = PaddleOCR(use_angle_cls=True, lang='ch', show_log=False, use_gpu=False)  # 只加载中文模型，禁用日志
        self.supported_exts = ('.png', '.jpg', '.jpeg', '.bmp', '.tiff')

    def _build_error_summary(self, target_path: str, message: str) -> ScanSummary:
        """Return a normal ScanSummary even when the image task cannot run."""
        return ScanSummary(
            task_name="图片 OCR 敏感信息扫描",
            total_scanned=0,
            total_secrets=0,
            scanned_details={},
            results=[
                ScanResult(
                    source_type="IMAGE",
                    source_path=target_path,
                    keyword="[OCR任务跳过]",
                    line_number="-",
                    context="-",
                    error_msg=message
                )
            ]
        )

    def scan_path(self, target_path) -> ScanSummary:
        results = []
        files_to_scan = []

        if not os.path.exists(target_path):
            message = f"路径不存在: {target_path}"
            print(f"错误：{message}")
            return self._build_error_summary(target_path, message)

        if os.path.isfile(target_path):
            ext = os.path.splitext(target_path)[1].lower()
            if ext in self.supported_exts:
                files_to_scan.append(target_path)
            else:
                message = f"不是支持的图片格式，已跳过: {target_path}"
                print(f"警告：{message}")
                return self._build_error_summary(target_path, message)

        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    if os.path.splitext(file)[1].lower() in self.supported_exts:
                        files_to_scan.append(os.path.join(root, file))

            if not files_to_scan:
                message = f"文件夹中未找到支持的图片: {target_path}"
                print(f"\n警告: {message}")
                return self._build_error_summary(target_path, message)

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
                                context=secret['context'],
                                rule_id=secret.get('rule_id', ''),
                                rule_name=secret.get('rule_name', ''),
                                risk_level=secret.get('risk_level', ''),
                                rule_description=secret.get('rule_description', '')
                            ))
            except Exception as e:
                error_msg = f"图片解析失败: {e}"
                print(f"图片 [{os.path.basename(file_path)}] 解析失败: {e}")
                results.append(ScanResult(
                    source_type="IMAGE",
                    source_path=file_path,
                    keyword="[OCR失败]",
                    line_number="-",
                    context="-",
                    error_msg=error_msg
                ))

        # 统计图片类型分布
        ext_counts = {}
        for f in files_to_scan:
            ext = os.path.splitext(f)[1].lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

        return ScanSummary(
            task_name="图片 OCR 敏感信息扫描",
            total_scanned=len(files_to_scan),
            total_secrets=len([r for r in results if not r.error_msg]),
            scanned_details=ext_counts,
            results=results
        )
