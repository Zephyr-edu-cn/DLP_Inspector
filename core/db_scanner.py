# core/db_scanner.py
from __future__ import annotations

import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pymysql

from models.data_models import ScanResult, ScanSummary
from utils.regex_utils import extract_secrets_from_text


SYSTEM_DATABASES = {'information_schema', 'mysql', 'performance_schema', 'sys'}
TEXT_COLUMN_TYPES = ('varchar', 'text', 'char', 'longtext', 'mediumtext', 'tinytext')


@dataclass(frozen=True)
class DBScanTarget:
    """A single authorized MySQL/MariaDB audit target."""
    host: str
    port: int
    user: str
    password: str
    database: str = ""
    label: str = ""

    @property
    def display_name(self) -> str:
        base = self.label.strip() if self.label else f"{self.host}:{int(self.port)}"
        db = self.database.strip() or "*"
        return f"{base}/{db}"

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "host": self.host,
            "port": int(self.port),
            "database": self.database or "*",
            "user": self.user,
        }


class DBScanner:
    def __init__(
        self,
        host,
        port,
        user,
        password,
        database: str | None = None,
        batch_size: int = 500,
        include_target_in_path: bool = False,
        target_label: str = "",
        connect_timeout: int = 5,
        read_timeout: int = 30,
        write_timeout: int = 30,
    ):
        """Initialize one authorized MySQL/MariaDB text-field audit target."""
        self.host = str(host).strip() or "localhost"
        self.port = int(port)
        self.user = user
        self.password = password
        self.database = (database or '').strip()
        self.batch_size = max(1, int(batch_size or 500))
        self.include_target_in_path = include_target_in_path
        self.target_label = target_label.strip()
        self.connect_timeout = max(1, int(connect_timeout or 5))
        self.read_timeout = max(1, int(read_timeout or 30))
        self.write_timeout = max(1, int(write_timeout or 30))

    @staticmethod
    def list_databases(host, port, user, password) -> list[str]:
        """List non-system databases visible to the provided account."""
        connection = pymysql.connect(
            host=host,
            port=int(port),
            user=user,
            password=password,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
            read_timeout=30,
            write_timeout=30,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute("SHOW DATABASES")
                dbs = [list(row.values())[0] for row in cursor.fetchall()]
                return [db for db in dbs if db not in SYSTEM_DATABASES]
        finally:
            if connection.open:
                connection.close()

    @classmethod
    def scan_targets(
        cls,
        targets: list[DBScanTarget | dict[str, Any]],
        batch_size: int = 500,
        max_workers: int = 4,
    ) -> ScanSummary:
        """Scan multiple authorized DB targets concurrently and merge their audit results."""
        normalized_targets = [cls._normalize_target(target) for target in targets]
        normalized_targets = [target for target in normalized_targets if target.host and target.user]
        if not normalized_targets:
            raise ValueError("未提供可扫描的数据库目标。")

        all_results: list[ScanResult] = []
        scanned_details: dict[str, int] = {}
        target_metadata: list[dict[str, Any]] = []
        workers = max(1, min(int(max_workers or 1), len(normalized_targets)))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {}
            for target in normalized_targets:
                scanner = cls(
                    target.host,
                    target.port,
                    target.user,
                    target.password,
                    database=target.database,
                    batch_size=batch_size,
                    include_target_in_path=True,
                    target_label=target.label or f"{target.host}:{target.port}",
                )
                future_map[executor.submit(scanner.scan)] = target

            for future in as_completed(future_map):
                target = future_map[future]
                safe_target = target.to_safe_dict()
                try:
                    summary = future.result()
                    all_results.extend(summary.results)
                    scanned_details.update(summary.scanned_details)
                    target_metadata.append({
                        **safe_target,
                        "status": "ok",
                        "total_scanned": summary.total_scanned,
                        "total_findings": len([r for r in summary.results if not r.error_msg]),
                        "total_errors": len([r for r in summary.results if r.error_msg]),
                    })
                except Exception as exc:
                    message = f"数据库目标扫描失败: {exc}"
                    all_results.append(ScanResult(
                        source_type="DB",
                        source_path=target.display_name,
                        keyword="[数据库目标异常]",
                        line_number="-",
                        context="-",
                        error_msg=message,
                    ))
                    target_metadata.append({
                        **safe_target,
                        "status": "error",
                        "total_scanned": 0,
                        "total_findings": 0,
                        "total_errors": 1,
                        "error_msg": str(exc),
                    })

        findings = [result for result in all_results if not result.error_msg]
        return ScanSummary(
            task_name="数据库文本字段并发审计",
            total_scanned=sum(item.get("total_scanned", 0) for item in target_metadata),
            total_secrets=len(findings),
            scanned_details=scanned_details,
            results=all_results,
            metadata={
                "db_targets": target_metadata,
                "db_parallel_workers": workers,
                "db_batch_size": int(batch_size or 500),
            },
        )

    @classmethod
    def load_targets_from_file(
        cls,
        target_file: str | Path,
        default_user: str = "",
        default_password: str = "",
        default_port: int = 3306,
    ) -> list[DBScanTarget]:
        """Load authorized DB audit targets from JSON or CSV.

        JSON accepts either a list or {"targets": [...]}.
        CSV should contain host, port, user, password, database/db and label columns.
        A password_env column can be used to avoid storing passwords in the file.
        """
        path = Path(target_file)
        if not path.is_file():
            raise ValueError(f"数据库目标文件不存在: {path}")

        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            items = data.get("targets", data) if isinstance(data, dict) else data
        elif path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                items = list(csv.DictReader(f))
        else:
            raise ValueError("数据库目标文件仅支持 .json 或 .csv")

        if not isinstance(items, list):
            raise ValueError("数据库目标文件格式错误：targets 必须是列表")

        targets = [
            cls._target_from_mapping(item, default_user, default_password, default_port)
            for item in items
            if isinstance(item, dict)
        ]
        targets = [target for target in targets if target.host and target.user]
        if not targets:
            raise ValueError("数据库目标文件中没有可用目标。")
        return targets

    @staticmethod
    def _target_from_mapping(
        mapping: dict[str, Any],
        default_user: str = "",
        default_password: str = "",
        default_port: int = 3306,
    ) -> DBScanTarget:
        password_env = str(mapping.get("password_env", "") or "").strip()
        password = str(mapping.get("password", mapping.get("pwd", "")) or "")
        if not password and password_env:
            password = os.getenv(password_env, "")
        return DBScanTarget(
            host=str(mapping.get("host", "localhost") or "localhost").strip(),
            port=int(mapping.get("port", default_port) or default_port),
            user=str(mapping.get("user", default_user) or default_user),
            password=password if password else default_password,
            database=str(mapping.get("database", mapping.get("db", "")) or "").strip(),
            label=str(mapping.get("label", "") or "").strip(),
        )

    @classmethod
    def _normalize_target(cls, target: DBScanTarget | dict[str, Any]) -> DBScanTarget:
        if isinstance(target, DBScanTarget):
            return target
        return cls._target_from_mapping(target)

    def _connect(self, database: str | None = None):
        config = {
            'host': self.host,
            'port': self.port,
            'user': self.user,
            'password': self.password,
            'charset': 'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor,
            'connect_timeout': self.connect_timeout,
            'read_timeout': self.read_timeout,
            'write_timeout': self.write_timeout,
        }
        if database:
            config['database'] = database
        return pymysql.connect(**config)

    def _quote_identifier(self, value: str) -> str:
        """Quote MySQL identifiers. Names come from metadata, but still escape backticks defensively."""
        return "`" + value.replace("`", "``") + "`"

    def scan(self) -> ScanSummary:
        """Scan one target; if database is empty, scan all non-system databases."""
        databases = [self.database] if self.database else self.list_databases(self.host, self.port, self.user, self.password)
        if not databases:
            raise ValueError("未发现可扫描的用户数据库。")

        all_results: list[ScanResult] = []
        table_details: dict[str, int] = {}
        total_table_count = 0

        try:
            for db_name in databases:
                db_results, db_table_details = self._scan_database(db_name)
                all_results.extend(db_results)
                table_details.update(db_table_details)
                total_table_count += len(db_table_details)
        except pymysql.MySQLError as e:
            raise ValueError(f"数据库连接或查询失败: {e}")

        return ScanSummary(
            task_name="数据库文本字段审计",
            total_scanned=total_table_count,
            total_secrets=len(all_results),
            scanned_details=table_details,
            results=all_results,
            metadata={
                "db_targets": [{
                    "label": self.target_label,
                    "host": self.host,
                    "port": self.port,
                    "database": self.database or "*",
                    "user": self.user,
                    "status": "ok",
                    "total_scanned": total_table_count,
                    "total_findings": len([r for r in all_results if not r.error_msg]),
                    "total_errors": len([r for r in all_results if r.error_msg]),
                }],
                "db_batch_size": self.batch_size,
            },
        )

    def _scan_database(self, db_name: str) -> tuple[list[ScanResult], dict[str, int]]:
        results: list[ScanResult] = []
        table_details: dict[str, int] = {}
        connection = self._connect(db_name)
        try:
            with connection.cursor() as cursor:
                cursor.execute("SHOW TABLES")
                tables = [list(row.values())[0] for row in cursor.fetchall()]

                for table in tables:
                    table_key = self._table_key(db_name, table)
                    text_columns = self._get_text_columns(cursor, db_name, table)

                    cursor.execute(f"SELECT COUNT(*) AS count FROM {self._quote_identifier(table)}")
                    row_count = cursor.fetchone()['count']
                    table_details[table_key] = row_count

                    if not text_columns or row_count == 0:
                        continue

                    primary_keys = self._get_primary_key_columns(cursor, db_name, table)
                    if len(primary_keys) == 1:
                        self._scan_table_keyset(cursor, table, table_key, text_columns, primary_keys[0], results)
                    else:
                        self._scan_table_offset(cursor, table, table_key, text_columns, results)
        finally:
            if connection.open:
                connection.close()

        return results, table_details

    def _scan_table_offset(self, cursor, table: str, table_key: str,
                           text_columns: list[str], results: list[ScanResult]) -> None:
        cols_str = ", ".join([self._quote_identifier(col) for col in text_columns])
        offset = 0
        while True:
            cursor.execute(
                f"SELECT {cols_str} FROM {self._quote_identifier(table)} LIMIT %s OFFSET %s",
                (self.batch_size, offset),
            )
            rows = cursor.fetchall()
            if not rows:
                break

            for batch_row_idx, row_data in enumerate(rows, start=1):
                row_idx = offset + batch_row_idx
                for col_name in text_columns:
                    self._append_text_findings(
                        row_data.get(col_name),
                        col_name,
                        f"第{row_idx}行 - 字段[{col_name}]",
                        table_key,
                        results,
                    )
            offset += self.batch_size

    def _scan_table_keyset(self, cursor, table: str, table_key: str,
                           text_columns: list[str], pk_col: str,
                           results: list[ScanResult]) -> None:
        pk_expr = f"{self._quote_identifier(pk_col)} AS __dlp_pk"
        cols_str = ", ".join([pk_expr] + [self._quote_identifier(col) for col in text_columns])
        last_pk = None

        while True:
            where_clause = ""
            params: tuple[object, ...] = (self.batch_size,)
            if last_pk is not None:
                where_clause = f" WHERE {self._quote_identifier(pk_col)} > %s"
                params = (last_pk, self.batch_size)

            cursor.execute(
                f"SELECT {cols_str} FROM {self._quote_identifier(table)}"
                f"{where_clause} ORDER BY {self._quote_identifier(pk_col)} ASC LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
            if not rows:
                break

            for row_data in rows:
                pk_value = row_data.get("__dlp_pk")
                for col_name in text_columns:
                    self._append_text_findings(
                        row_data.get(col_name),
                        col_name,
                        f"主键[{pk_col}={pk_value}] - 字段[{col_name}]",
                        table_key,
                        results,
                    )
            last_pk = rows[-1].get("__dlp_pk")
            if last_pk is None:
                break

    def _append_text_findings(self, text_value, col_name: str, location: str,
                              table_key: str, results: list[ScanResult]) -> None:
        if text_value is None or str(text_value).strip() == "":
            return

        secrets_found = extract_secrets_from_text(str(text_value), col_name)
        for secret in secrets_found:
            results.append(ScanResult(
                source_type="DB",
                source_path=table_key,
                keyword=secret['keyword'],
                line_number=location,
                context=secret['context'],
                rule_id=secret.get('rule_id', ''),
                rule_name=secret.get('rule_name', ''),
                risk_level=secret.get('risk_level', ''),
                rule_description=secret.get('rule_description', ''),
            ))

    def _table_key(self, db_name: str, table_name: str) -> str:
        table_key = f"{db_name}.{table_name}"
        if not self.include_target_in_path:
            return table_key
        target = self.target_label or f"{self.host}:{self.port}"
        return f"{target}/{table_key}"

    def _get_text_columns(self, cursor, db_name, table_name) -> list[str]:
        """Read metadata and return text-like columns only."""
        query = """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = %s
              AND DATA_TYPE IN ('varchar', 'text', 'char', 'longtext', 'mediumtext', 'tinytext')
        """
        cursor.execute(query, (db_name, table_name))
        return [row['COLUMN_NAME'] for row in cursor.fetchall()]

    def _get_primary_key_columns(self, cursor, db_name, table_name) -> list[str]:
        """Return primary key columns in ordinal order for keyset pagination."""
        query = """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = %s
              AND COLUMN_KEY = 'PRI'
            ORDER BY ORDINAL_POSITION
        """
        cursor.execute(query, (db_name, table_name))
        return [row['COLUMN_NAME'] for row in cursor.fetchall()]
