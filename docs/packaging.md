# Packaging

本文档记录 DLP Inspector 的运行依赖、OCR 包选择、PyInstaller 打包注意事项和打包后 smoke test。打包前请先确认项目口径：本项目是轻量级审计自查工具原型，不是企业级实时 DLP 网关。

## 推荐环境

建议使用 Windows + Python 3.10 或 3.11 创建虚拟环境。PaddleOCR、PaddlePaddle、OpenCV、PyMuPDF、pywin32 等依赖在过新的 Python 版本上可能存在兼容性问题。

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` 默认安装通用依赖和 CPU 版 PaddlePaddle。若只检查非 OCR 模块，可先安装 `requirements-base.txt`，但完整 GUI 启动仍需要 OCR 相关依赖可导入。

## CPU / GPU 依赖选择

默认建议使用 CPU 依赖：

```bash
pip install -r requirements.txt
```

具备匹配 CUDA、cuDNN、显卡驱动和 PaddlePaddle GPU 轮子的开发环境时，才考虑安装 GPU 依赖：

```bash
pip install -r requirements-gpu.txt
```

注意：如果打包目标是普通演示或答辩环境，优先使用 CPU 包，避免 GPU 运行时、驱动和动态库带来的额外不确定性。打包产物中不应混入与实际口径不一致的 GPU 依赖。

## PyInstaller 打包

项目可以使用 PyInstaller 生成目录式构建产物。由于 PaddleOCR 依赖较重，通常需要显式收集相关包和元数据：

```bash
pyinstaller -D --name "DLP_Inspector" ^
  --collect-all paddle ^
  --collect-all paddleocr ^
  --collect-all customtkinter ^
  --collect-all skimage ^
  --collect-all imgaug ^
  --collect-all lmdb ^
  --hidden-import pyclipper ^
  --hidden-import shapely ^
  --copy-metadata imageio ^
  --copy-metadata imgaug ^
  run.py
```

不同环境下隐藏依赖可能略有差异。若打包后启动失败，应根据异常补充 `--hidden-import` 或 `--collect-all`，并重新验证。

## 模型与缓存

PaddleOCR 可能在首次运行时下载或生成模型缓存。模型缓存位置受 PaddleOCR 配置和用户目录影响。源码仓库不应提交模型缓存、打包缓存或临时运行产物。

交付独立可执行版本时，应在目标环境确认：

- OCR 模型是否已经随包携带或可在首次运行时获得。
- 无网络环境下 OCR 是否能正常初始化。
- 打包产物是否只包含实际需要的 CPU 或 GPU 运行时。

## 源码仓库清理

以下内容属于本地构建或运行产物，不应提交到源码仓库：

- `dist/`
- `build/`
- `*.spec`
- `__pycache__/`
- `.pytest_cache/`
- `audit_reports/*.xlsx`
- PaddleOCR 模型缓存
- 临时扫描输出和历史 exe 产物

如果当前仓库没有生成好的 exe，就不要在 README 中写“直接双击 exe”。应写成“可通过 PyInstaller 打包生成独立运行目录，并在目标环境完成 smoke test 后交付”。

## 打包后 smoke test

打包完成后至少验证以下步骤：

1. 启动 `dist/DLP_Inspector/DLP_Inspector.exe`，确认 GUI 能打开。
2. 使用小型文本样例执行文件扫描，确认能发现预期关键词。
3. 导出 Excel 报告，确认 `检查概述` 和 `涉密明细清单` 两个工作表可打开。
4. 若启用 Web 扫描，使用静态 HTML 测试页面验证 `requests + BeautifulSoup` 路径。
5. 若启用 OCR，使用一张清晰图片验证 PaddleOCR 能初始化并返回文本。

在开发机上，若依赖未完整安装，至少可以执行最小导入检查：

```bash
python -c "from utils.regex_utils import extract_secrets_from_text; print(extract_secrets_from_text('这里有绝 密资料', 1))"
```

仓库还提供了一个文件扫描 smoke demo：

```bash
python scripts/smoke_scan.py
```

该脚本默认扫描 `sample_data/files/`，并将报告输出到本地 `audit_reports/`。`audit_reports/` 和外部提供的 `inputs/` 测试数据都不应提交到源码仓库。

完整核心模块导入需要安装 `requirements.txt`，OCR 相关依赖过重时可单独记录为环境要求，不强行在轻量 smoke 中覆盖。
