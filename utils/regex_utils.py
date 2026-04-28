# utils/regex_utils.py
import re

# 题目要求检测的基准关键字
SECRET_KEYWORDS = ["涉密", "秘密", "机密", "绝密", "保密", "泄密"]

def build_fuzzy_pattern(keywords: list[str]) -> re.Pattern:
    """
    将基准关键字转换为支持模糊匹配的正则表达式。
    原理：在每个汉字之间插入 [\s\W_]* ，代表允许有任意多个空格、标点符号或特殊字符。
    例如: '绝密' -> '绝[\s\W_]*密'
    """
    patterns = []
    for kw in keywords:
        # list(kw) 会把 "绝密" 变成 ['绝', '密']
        # join 后变成 "绝[\s\W_]*密"
        fuzzy_kw = r"[\s\W_]*".join(list(kw))
        patterns.append(fuzzy_kw)

    # 用 | (或) 将所有关键字正则拼接起来，加上括号作为一个整体捕获组
    combined_pattern = f"({'|'.join(patterns)})"
    
    # 预编译为正则对象，极大提升海量文本匹配时的效率
    return re.compile(combined_pattern)

# 全局单例的正则匹配引擎，只在模块导入时编译一次
SECRET_PATTERN = build_fuzzy_pattern(SECRET_KEYWORDS)

def extract_secrets_from_text(text: str, line_num: str | int) -> list[dict]:
    """
    扫描传入的一段文本，提取所有涉密信息及其上下文。
    返回一个字典列表，方便直接用于实例化 ScanResult。
    """
    results = []
    # 如果传入的文本为空，直接返回
    if not text:
        return results

    # finditer 可以在全文中查找所有匹配项，并保留它们在字符串中的索引位置
    for match in SECRET_PATTERN.finditer(text):
        found_word = match.group()
        start_idx = match.start()
        end_idx = match.end()

        # 截取上下文（前后各保留 15 个字符作为证据），并注意边界防止越界
        context_start = max(0, start_idx - 15)
        context_end = min(len(text), end_idx + 15)
        # 将上下文中的换行符替换为空格，保持报告格式整洁
        context = text[context_start:context_end].replace('\n', ' ').strip()

        results.append({
            "keyword": found_word,
            "line_number": str(line_num),
            "context": context
        })
        
    return results