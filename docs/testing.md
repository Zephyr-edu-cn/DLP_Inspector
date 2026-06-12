# Testing

DLP Inspector 的自动化验证分为轻量测试和可选集成测试。轻量测试不安装 PaddleOCR、PaddlePaddle、GUI、Pandas 或 Windows COM 依赖，可直接在 GitHub Actions 中运行。

## 轻量测试

安装测试依赖：

```bash
pip install -r requirements-test.txt
```

运行：

```bash
python -B -m pytest -q
python -B scripts/smoke_scan.py --no-report
```

当前覆盖：

- `config/rules.json` 风格规则的加载、无效配置回退和关键词模糊正则编译。
- 仓库内三个文本样例的文件 smoke。
- 文件不存在、解析器异常及异常来源路径留痕。
- Web 静态页面的同域 BFS、深度限制和请求异常留痕。
- MySQL 文本字段扫描的 `LIMIT / OFFSET` 分页调用与跨页行号。
- `summary`、`findings`、`errors` 三个 sheet 及字段结构。
- 不安装 PaddleOCR 时，`core.image_scanner` 模块仍可导入。

轻量测试验证的是确定性流程和数据结构，不代表真实数据上的 precision、recall、F1，也不验证 PaddleOCR 模型精度、真实 MySQL 性能或 Windows Office 自动化兼容性。

## 可选集成测试

下列测试默认跳过，仅在准备好对应环境后通过环境变量启用。

### OCR

安装 CPU 或 GPU OCR 依赖后设置一张测试图片：

```powershell
$env:DLP_TEST_OCR_IMAGE="D:\path\to\sample.png"
python -B -m pytest tests/test_optional_integrations.py -q
```

### MySQL / MariaDB

请只使用授权的测试数据库和只读账号：

```powershell
$env:DLP_TEST_MYSQL_HOST="127.0.0.1"
$env:DLP_TEST_MYSQL_PORT="3306"
$env:DLP_TEST_MYSQL_USER="audit_reader"
$env:DLP_TEST_MYSQL_PASSWORD="..."
$env:DLP_TEST_MYSQL_DATABASE="demo"
python -B -m pytest tests/test_optional_integrations.py -q
```

### Windows COM

该测试仅适用于 Windows、本机已安装 Microsoft Office，并准备了 `.doc` 或 `.ppt` 测试文件的环境：

```powershell
$env:DLP_TEST_LEGACY_OFFICE="D:\path\to\legacy.doc"
python -B -m pytest tests/test_optional_integrations.py -q
```

这些环境变量不应写入仓库或 GitHub Actions。
