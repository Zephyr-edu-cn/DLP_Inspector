# DLP Inspector

> Lightweight confidentiality audit and sensitive-information inspection prototype

DLP Inspector 是一个轻量级保密审计自查工具原型，用于在本地文件、MySQL 文本字段、Web 静态页面和图片 OCR 结果中发现潜在敏感信息，并将命中结果归档为 Excel 审计报告。

本项目不是企业级实时阻断 DLP 网关，不提供内核级拦截、网络流量监控、外发阻断、策略下发或终端管控能力；也不是数据库漏洞扫描器或动态 JS 爬虫平台。它的目标是支持文档共享、内部检查或答辩演示前的轻量级预检查，回答“风险线索在哪里、能否形成可复核记录”的问题。

## 功能范围

### 1. 本地文件敏感信息扫描

- 支持 `.txt`、`.docx`、`.xlsx`、`.pptx`、`.pdf` 以及部分旧版 Office 格式的文本提取与敏感词检测。
- 通过文件真实类型识别降低后缀伪装造成的漏检风险。
- 在 Windows 环境下识别隐藏文件属性，并对隐藏文件或加密/受保护文档给出审计告警。

### 2. 数据库文本字段敏感内容审计

- 支持使用标准凭证连接 MySQL。
- 遍历库内数据表，仅提取文本类型字段进行敏感内容审计。
- 记录命中特征、表名、字段名、行位置和上下文片段。
- 不执行弱口令、注入、越权、配置缺陷等数据库漏洞检测。

### 3. Web 静态页面扫描

- 基于 `requests` 和 `BeautifulSoup` 抓取与解析静态 HTML。
- 使用同域 BFS 遍历策略，并通过最大深度限制控制扫描范围。
- 提取页面可见文本并进行敏感词匹配。
- 不渲染 JavaScript，不执行浏览器自动化，也不承诺覆盖前端动态加载内容。

### 4. 图片 OCR 敏感信息扫描

- 依赖 `PaddleOCR` 提取图片文本，当前实现默认使用 CPU 推理。
- 支持 `.png`、`.jpg`、`.jpeg`、`.bmp`、`.tiff` 等常见图片格式。
- 对 OCR 结果进行置信度过滤后再做敏感词匹配。
- OCR 效果受图片质量、字体、排版、模型文件和运行环境影响；本项目不包含自研 OCR 模型。

### 5. GUI 与报告归档

- 基于 `CustomTkinter` 提供桌面 GUI，支持文件、数据库、Web、图片四类扫描入口。
- 扫描任务运行在后台线程中，避免 I/O 密集型任务阻塞界面。
- 导出 `summary`、`findings`、`errors` 三个工作表，便于人工复核和归档。

### 6. 规则配置化

- 敏感信息规则存放在 `config/rules.json`。
- 规则字段包括 `rule_id`、`name`、`pattern`、`type`、`risk_level`、`description`。
- 支持 `keyword` 和 `regex` 两类规则，扫描结果会保留命中的规则 ID 和风险等级。

## 技术栈

- **语言**：Python 3.10+
- **GUI**：CustomTkinter
- **文件解析**：python-docx、python-pptx、openpyxl、xlrd、PyMuPDF、pywin32、olefile、python-magic-bin
- **数据库连接**：PyMySQL
- **Web 静态页面解析**：requests、BeautifulSoup
- **OCR**：PaddleOCR / PaddlePaddle，默认 CPU 推理
- **报告导出**：Pandas / OpenPyXL
- **打包工具**：PyInstaller

## 目录结构

```text
DLP_Inspector/
├── assets/                # README 截图素材
├── config/                # 规则配置，例如 rules.json
├── core/                  # 文件、数据库、Web、OCR 扫描模块
├── docs/                  # 交付边界与打包说明
├── models/                # ScanResult / ScanSummary 数据模型
├── report/                # Excel 报告导出模块
├── sample_data/           # 可复现 smoke demo 样例
├── scripts/               # smoke_scan.py 等本地验证脚本
├── ui/                    # CustomTkinter GUI
├── utils/                 # 文件类型、文档解析、正则匹配工具
├── main.py                # GUI 主程序副本
├── run.py                 # 推荐启动入口
├── requirements.txt       # 默认 CPU 运行依赖
├── requirements-base.txt  # 通用依赖
├── requirements-gpu.txt   # 可选 GPU 开发依赖
└── README.md
```

`dist/`、`build/`、`__pycache__/` 和 `audit_reports/` 属于本地构建或运行产物，不应作为源码仓库内容提交。

## 安装与运行

建议使用 Python 3.10 或 3.11 创建虚拟环境。OCR 与部分科学计算依赖在过新的 Python 版本上可能存在兼容性问题。

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

如只需要检查非 OCR 代码结构，可先安装 `requirements-base.txt`，但启动完整 GUI 时仍需要满足全部运行依赖。

## 打包说明

PyInstaller 打包涉及 PaddleOCR、PaddlePaddle、OpenCV、CustomTkinter 等较重依赖，容易受到 Python 版本、CPU/GPU 包选择和模型缓存位置影响。详细说明见 [docs/packaging.md](docs/packaging.md)。

如果当前仓库没有可执行文件，请不要把交付方式描述成“直接双击 exe”。应先在目标环境完成打包并验证生成的 `dist/` 目录后，再提供独立可执行版本。

## 报告输出

报告由 `report/report_manager.py` 生成，默认输出到本地 `audit_reports/` 目录。Excel 报告包含：

- **summary**：任务名称、扫描对象数量、命中数量、异常数量、类型分布。
- **findings**：来源类型、路径/URL/表名、位置、规则 ID、规则名称、风险等级、命中特征、上下文证据。
- **errors**：解析失败、权限异常、依赖缺失等需要人工复核的问题。

## 可复现 smoke demo

仓库提供了小型样例数据和本地 smoke 脚本，用于验证文件扫描、规则命中和报告导出闭环：

```bash
python scripts/smoke_scan.py
```

默认扫描 `sample_data/files/` 并导出 Excel 报告到 `audit_reports/`。`inputs/` 是本地测试材料目录，已加入 `.gitignore`，不应提交到 GitHub。

## 界面预览

### 本地文件敏感信息扫描

![File Scan](assets/ui_file_scan.png)

### 数据库文本字段敏感内容审计

![Database Scan](assets/ui_db_scan.png)

### Web 静态页面扫描

![Web Scan](assets/ui_web_scan.png)

### 图片 OCR 敏感信息扫描

![Image OCR Scan](assets/ui_image_scan.png)

### Excel 审计报告导出

![Report Preview](assets/report_preview.png)

## 已知限制

本项目以规则匹配和 OCR 文本提取为主，适合作为轻量级保密审计自查与教学演示原型。关于误报/漏报、Web 静态扫描边界、数据库审计边界、OCR 环境依赖和 Office 解析限制，见 [docs/limitations.md](docs/limitations.md)。

## 合规声明

1. 本工具仅限于对已获得合法授权的资产进行安全审查、合规自查和教学演示。
2. 严禁将本工具用于未经授权的数据访问、渗透测试、数据窃取或任何违反法律法规的数据处理行为。
3. 软件运行产生的合规责任由具体使用者承担。

---

Generated for DLP Inspector - Lightweight DLP Inspection Prototype.
