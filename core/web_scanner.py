# core/web_scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from models.data_models import ScanResult
from utils.regex_utils import extract_secrets_from_text

class WebScanner:
    def __init__(self, start_url: str, max_depth: int = 2):
        """
        初始化爬虫引擎
        :param start_url: 目标入口网址
        :param max_depth: 最大爬取深度 (0代表只扫首页，1代表扫首页及首页上的链接，以此类推)
        """
        # 确保网址有 http/https 前缀
        if not start_url.startswith('http'):
            start_url = 'http://' + start_url
            
        self.start_url = start_url
        self.max_depth = max_depth
        self.visited = set() # 记录已访问的URL，防止死循环
        
        # 提取目标主域名 (例如 bm.yangyq.net)，用于同源策略限制
        self.base_domain = urlparse(self.start_url).netloc

    def scan(self) -> list[ScanResult]:
        results = []
        # 使用队列实现 BFS (广度优先搜索)
        # 队列中存放元组: (当前URL, 当前深度)
        queue = deque([(self.start_url, 0)])

        while queue:
            current_url, depth = queue.popleft()

            # 去重：如果已经爬过，直接跳过
            if current_url in self.visited:
                continue
            self.visited.add(current_url)

            try:
                # 伪装成真实的浏览器，防止被反爬虫拦截
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                # 设置 5 秒超时，防止网站卡死导致程序一直等
                response = requests.get(current_url, headers=headers, timeout=5)
                response.raise_for_status()

                # 只处理 HTML 网页，跳过图片、压缩包等非文本链接
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type:
                    continue

                # 智能识别网页编码，防止中文乱码
                response.encoding = response.apparent_encoding
                
                # 使用 BeautifulSoup 剥离 HTML 标签
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 提取纯文本，按换行符分割
                text_content = soup.get_text(separator='\n', strip=True)
                
                # 逐行进行涉密匹配
                for line_num, line in enumerate(text_content.splitlines(), start=1):
                    if not line.strip():
                        continue
                        
                    secrets_found = extract_secrets_from_text(line, line_num)
                    for secret in secrets_found:
                        results.append(ScanResult(
                            source_type="WEB",
                            source_path=current_url, # 来源直接写出问题的网址
                            keyword=secret['keyword'],
                            line_number=f"网页第{line_num}行",
                            context=secret['context']
                        ))

                # 如果还没达到最大深度，就继续挖当前页面的超链接
                if depth < self.max_depth:
                    for a_tag in soup.find_all('a', href=True):
                        raw_link = a_tag['href']
                        # 处理相对路径，拼接成完整的绝对路径
                        next_url = urljoin(current_url, raw_link)
                        # 去掉 URL 里的锚点 (#)，因为它们指向的是同一个页面
                        next_url = next_url.split('#')[0]

                        # 【核心安全策略】：只爬同一个域名下的网页，且没被访问过
                        if urlparse(next_url).netloc == self.base_domain and next_url not in self.visited:
                            queue.append((next_url, depth + 1))

            except Exception as e:
                # 网页打不开很正常，打印警告但不让程序崩溃
                print(f"⚠️ 无法访问 {current_url}: {e}")

        return results