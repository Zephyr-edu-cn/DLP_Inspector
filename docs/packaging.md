# Packaging

本文档记录 DLP Inspector 的运行依赖、OCR 包选择、PyInstaller 打包注意事项和打包后基础验证流程。本项目是轻量级审计自查工具原型，不是企业级实时 DLP 网关。

## 推荐环境

建议使用 Windows + Python 3.10 或 3.11 创建虚拟环境。PaddleOCR、PaddlePaddle、OpenCV、PyMuPDF、pywin32 等依赖在过新的 Python 版本上可能存在兼容性问题。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

依赖分层如下：

- `requirements-base.txt`：文件、数据库、Web、报告、GUI 和打包基础依赖，不包含 PaddleOCR / PaddlePaddle。
- `requirements-ocr.txt`：CPU/GPU 共用的 PaddleOCR 前端。
- `requirements.txt`：基础依赖 + OCR 前端 + CPU 版 PaddlePaddle。
- `requirements-gpu.txt`：基础依赖 + OCR 前端 + GPU 版 PaddlePaddle。
- `requirements-test.txt`：GitHub Actions 使用的轻量测试依赖，不包含 OCR、GUI、Pandas 和 Windows COM。

OCR 模块采用延迟导入。只安装 `requirements-base.txt` 时，可导入并运行非 OCR 模块；实际创建 `ImageScanner` 时会明确提示安装 OCR 依赖。

## CPU / GPU 依赖选择

默认建议使用 CPU 依赖：

```bash
pip install -r requirements.txt
```

具备匹配 CUDA、cuDNN、显卡驱动和 PaddlePaddle GPU 轮子的开发环境时，才考虑安装 GPU 依赖：

```bash
pip install -r requirements-gpu.txt
```

已存在基础环境时，也可以单独安装 OCR 前端和匹配的运行时：

```bash
pip install -r requirements-ocr.txt
pip install paddlepaddle==2.6.1
```

注意：如果打包目标是普通展示或测试环境，优先使用 CPU 包，避免 GPU 运行时、驱动和动态库带来的额外不确定性。打包产物中不应混入与实际运行方式不一致的 GPU 依赖。

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

当前源码仓库不随附 exe。独立运行版本应通过 PyInstaller 生成，并在目标环境完成基础验证后再交付。

## 打包后基础验证

打包完成后至少验证以下步骤：

1. 启动 `dist/DLP_Inspector/DLP_Inspector.exe`，确认 GUI 能打开。
2. 使用小型文本样例执行文件扫描，确认能发现预期关键词。
3. 导出 Excel 报告，确认 `summary`、`findings`、`errors` 三个工作表可打开。
4. 若启用 Web 扫描，使用静态 HTML 测试页面验证 `requests + BeautifulSoup` 路径。
5. 若启用 OCR，使用一张清晰图片验证 PaddleOCR 能初始化并返回文本。

在开发机上，若依赖未完整安装，可以先执行最小导入检查：

```bash
python -c "from utils.regex_utils import extract_secrets_from_text; print(extract_secrets_from_text('这里有绝 密资料', 1))"
```

仓库还提供了一个文件扫描验证脚本：

```bash
python scripts/smoke_scan.py
```

该脚本默认扫描 `sample_data/files/`，并将报告输出到本地 `audit_reports/`。

完整 OCR 运行需要安装 `requirements.txt` 或等价的 OCR 前端与 PaddlePaddle 运行时；非 OCR 模块可只安装基础依赖。

轻量自动测试与可选集成测试见 [testing.md](testing.md)。GitHub Actions 不执行 PyInstaller、OCR 模型推理、真实 MySQL 扫描或 Windows COM 测试。
