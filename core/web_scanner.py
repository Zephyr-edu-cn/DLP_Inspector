# core/web_scanner.py
from __future__ import annotations

import hashlib
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from models.data_models import ScanResult, ScanSummary
from utils.regex_utils import extract_secrets_from_text


class WebScanner:
    def __init__(self, start_url: str, max_depth: int = 2):
        """
        Static same-domain HTML scanner.

        This scanner intentionally uses requests + BeautifulSoup only. It does
        not render JavaScript or automate a browser.
        """
        if not start_url.startswith('http'):
            start_url = 'http://' + start_url

        self.start_url = start_url
        self.max_depth = max_depth
        self.visited = set()
        self.base_domain = urlparse(self.start_url).netloc

    def scan(self) -> ScanSummary:
        results: list[ScanResult] = []
        snapshots: list[dict[str, object]] = []
        queue = deque([(self.start_url, 0)])

        while queue:
            current_url, depth = queue.popleft()
            if current_url in self.visited:
                continue
            self.visited.add(current_url)

            try:
                response, soup, text_content = self._fetch_static_html(current_url)
                snapshots.append(self._build_snapshot(
                    current_url,
                    depth,
                    response,
                    soup,
                    text_content,
                ))

                for line_num, line in enumerate(text_content.splitlines(), start=1):
                    if not line.strip():
                        continue

                    secrets_found = extract_secrets_from_text(line, line_num)
                    for secret in secrets_found:
                        results.append(ScanResult(
                            source_type="WEB",
                            source_path=current_url,
                            keyword=secret['keyword'],
                            line_number=f"网页第{line_num}行",
                            context=secret['context'],
                            rule_id=secret.get('rule_id', ''),
                            rule_name=secret.get('rule_name', ''),
                            risk_level=secret.get('risk_level', ''),
                            rule_description=secret.get('rule_description', '')
                        ))

                if depth < self.max_depth:
                    for a_tag in soup.find_all('a', href=True):
                        raw_link = a_tag['href']
                        next_url = urljoin(current_url, raw_link).split('#')[0]
                        if urlparse(next_url).netloc == self.base_domain and next_url not in self.visited:
                            queue.append((next_url, depth + 1))

            except Exception as e:
                error_msg = f"无法访问网页: {e}"
                print(f"[WARN] 无法访问 {current_url}: {e}")
                snapshots.append(self._build_error_snapshot(current_url, depth, error_msg))
                results.append(ScanResult(
                    source_type="WEB",
                    source_path=current_url,
                    keyword="[无法访问]",
                    line_number="-",
                    context="-",
                    error_msg=error_msg
                ))

        return ScanSummary(
            task_name="Web 静态页面扫描",
            total_scanned=len(self.visited),
            total_secrets=len([r for r in results if not r.error_msg]),
            scanned_details={
                "抓取页面数": len(self.visited),
                "最大深度": self.max_depth,
            },
            results=results,
            metadata={
                "web_scan": {
                    "start_url": self.start_url,
                    "base_domain": self.base_domain,
                    "max_depth": self.max_depth,
                    "scanner": "requests + BeautifulSoup static HTML",
                },
                "web_snapshots": snapshots,
            },
        )

    def verify_snapshots(self, snapshots: list[dict[str, object]]) -> ScanSummary:
        """
        Re-fetch previously scanned pages and compare extracted-text SHA-256.

        This answers the point-in-time consistency question without pretending
        to solve real-time page monitoring.
        """
        results: list[ScanResult] = []
        refreshed_snapshots: list[dict[str, object]] = []
        changed_count = 0
        error_count = 0

        for snapshot in snapshots:
            url = str(snapshot.get("url", "")).strip()
            if not url:
                continue
            try:
                response, soup, text_content = self._fetch_static_html(url)
                current_snapshot = self._build_snapshot(
                    url,
                    int(snapshot.get("depth", 0) or 0),
                    response,
                    soup,
                    text_content,
                )
                refreshed_snapshots.append(current_snapshot)
                old_hash = str(snapshot.get("text_sha256", ""))
                new_hash = str(current_snapshot.get("text_sha256", ""))
                if old_hash and new_hash and old_hash != new_hash:
                    changed_count += 1
                    results.append(ScanResult(
                        source_type="WEB",
                        source_path=url,
                        keyword="[页面内容变更]",
                        line_number="-",
                        context=f"old_sha256={old_hash}; new_sha256={new_hash}",
                        rule_id="SYSTEM_WEB_CONTENT_CHANGED",
                        rule_name="页面快照变更",
                        risk_level="medium",
                        rule_description="复核时静态页面文本哈希与首次扫描不一致，建议重新审计该页面。",
                    ))
            except Exception as e:
                error_count += 1
                message = f"页面快照复核失败: {e}"
                refreshed_snapshots.append(self._build_error_snapshot(url, int(snapshot.get("depth", 0) or 0), message))
                results.append(ScanResult(
                    source_type="WEB",
                    source_path=url,
                    keyword="[页面复核异常]",
                    line_number="-",
                    context="-",
                    error_msg=message,
                ))

        return ScanSummary(
            task_name="Web 页面快照复核",
            total_scanned=len(refreshed_snapshots),
            total_secrets=changed_count,
            scanned_details={
                "复核页面数": len(refreshed_snapshots),
                "内容变化页面数": changed_count,
                "访问异常页面数": error_count,
            },
            results=results,
            metadata={
                "web_snapshot_verification": {
                    "changed_pages": changed_count,
                    "error_pages": error_count,
                },
                "web_snapshots": refreshed_snapshots,
            },
        )

    def _fetch_static_html(self, url: str):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            raise ValueError(f"非 HTML 内容类型: {content_type or 'unknown'}")

        response.encoding = response.apparent_encoding
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text(separator='\n', strip=True)
        return response, soup, text_content

    def _build_snapshot(self, url: str, depth: int, response, soup: BeautifulSoup,
                        text_content: str) -> dict[str, object]:
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        return {
            "url": url,
            "depth": depth,
            "status_code": getattr(response, "status_code", 200),
            "content_type": response.headers.get('Content-Type', ''),
            "title": title,
            "text_sha256": hashlib.sha256(text_content.encode("utf-8")).hexdigest(),
            "text_chars": len(text_content),
            "fetched_at": datetime.now().isoformat(timespec="seconds"),
            "error_msg": "",
        }

    def _build_error_snapshot(self, url: str, depth: int, error_msg: str) -> dict[str, object]:
        return {
            "url": url,
            "depth": depth,
            "status_code": "",
            "content_type": "",
            "title": "",
            "text_sha256": "",
            "text_chars": 0,
            "fetched_at": datetime.now().isoformat(timespec="seconds"),
            "error_msg": error_msg,
        }
