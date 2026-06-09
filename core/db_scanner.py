# core/db_scanner.py
import pymysql
from models.data_models import ScanResult, ScanSummary
from utils.regex_utils import extract_secrets_from_text


SYSTEM_DATABASES = {'information_schema', 'mysql', 'performance_schema', 'sys'}


class DBScanner:
    def __init__(self, host, port, user, password, database: str | None = None, batch_size: int = 500):
        """初始化数据库连接配置。database 可为空；为空时自动扫描所有非系统库。"""
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.database = (database or '').strip()
        self.batch_size = max(1, int(batch_size or 500))

    @staticmethod
    def list_databases(host, port, user, password) -> list[str]:
        """自动获取当前账号可访问的非系统数据库名。"""
        connection = pymysql.connect(
            host=host,
            port=int(port),
            user=user,
            password=password,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute("SHOW DATABASES")
                dbs = [list(row.values())[0] for row in cursor.fetchall()]
                return [db for db in dbs if db not in SYSTEM_DATABASES]
        finally:
            if connection.open:
                connection.close()

    def _connect(self, database: str | None = None):
        config = {
            'host': self.host,
            'port': self.port,
            'user': self.user,
            'password': self.password,
            'charset': 'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor,
        }
        if database:
            config['database'] = database
        return pymysql.connect(**config)

    def _quote_identifier(self, value: str) -> str:
        """Quote MySQL identifiers. Names come from metadata, but still escape backticks defensively."""
        return "`" + value.replace("`", "``") + "`"

    def scan(self) -> ScanSummary:
        """执行数据库扫描；若未指定 database，则扫描所有非系统库。"""
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
            results=all_results
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
                    table_key = f"{db_name}.{table}"
                    text_columns = self._get_text_columns(cursor, db_name, table)

                    cursor.execute(f"SELECT COUNT(*) AS count FROM {self._quote_identifier(table)}")
                    row_count = cursor.fetchone()['count']
                    table_details[table_key] = row_count

                    if not text_columns or row_count == 0:
                        continue

                    cols_str = ", ".join([self._quote_identifier(col) for col in text_columns])
                    offset = 0
                    while True:
                        cursor.execute(
                            f"SELECT {cols_str} FROM {self._quote_identifier(table)} LIMIT %s OFFSET %s",
                            (self.batch_size, offset)
                        )
                        rows = cursor.fetchall()
                        if not rows:
                            break

                        for batch_row_idx, row_data in enumerate(rows, start=1):
                            row_idx = offset + batch_row_idx
                            for col_name, text_value in row_data.items():
                                if text_value is None or str(text_value).strip() == "":
                                    continue

                                secrets_found = extract_secrets_from_text(str(text_value), col_name)
                                for secret in secrets_found:
                                    results.append(ScanResult(
                                        source_type="DB",
                                        source_path=table_key,
                                        keyword=secret['keyword'],
                                        line_number=f"第{row_idx}行 - 字段[{col_name}]",
                                        context=secret['context'],
                                        rule_id=secret.get('rule_id', ''),
                                        rule_name=secret.get('rule_name', ''),
                                        risk_level=secret.get('risk_level', ''),
                                        rule_description=secret.get('rule_description', '')
                                    ))

                        offset += self.batch_size
        finally:
            if connection.open:
                connection.close()

        return results, table_details

    def _get_text_columns(self, cursor, db_name, table_name) -> list[str]:
        """查字典表，仅提取可能包含涉密文字的文本类字段。"""
        query = """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = %s
              AND DATA_TYPE IN ('varchar', 'text', 'char', 'longtext', 'mediumtext', 'tinytext')
        """
        cursor.execute(query, (db_name, table_name))
        return [row['COLUMN_NAME'] for row in cursor.fetchall()]
