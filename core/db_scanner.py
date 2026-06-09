# core/db_scanner.py
import pymysql
from models.data_models import ScanResult, ScanSummary
from utils.regex_utils import extract_secrets_from_text

class DBScanner:
    def __init__(self, host, port, user, password, database, batch_size: int = 500):
        """初始化数据库连接配置"""
        self.batch_size = batch_size
        self.db_config = {
            'host': host,
            'port': int(port),
            'user': user,
            'password': password,
            'database': database,
            'charset': 'utf8mb4',
            # 使用字典游标，方便通过字段名获取数据
            'cursorclass': pymysql.cursors.DictCursor 
        }

    def scan(self) -> ScanSummary:
        """
        执行全库扫描。
        返回: ScanSummary 对象
        """
        results = []
        stats = {
            "table_count": 0,
            "total_rows_scanned": 0,
            "table_details": {} # 记录每张表的行数
        }

        try:
            # 建立数据库连接
            connection = pymysql.connect(**self.db_config)
            with connection.cursor() as cursor:
                # 1. 获取库中所有的表名
                cursor.execute("SHOW TABLES")
                tables = [list(row.values())[0] for row in cursor.fetchall()]
                stats["table_count"] = len(tables)

                # 2. 遍历每一张表
                for table in tables:
                    # 动态获取该表中所有【文本类型】的字段，极大提升效率
                    text_columns = self._get_text_columns(cursor, self.db_config['database'], table)
                    
                    # 统计该表的总行数 (满足题目要求的报告细节)
                    cursor.execute(f"SELECT COUNT(*) as count FROM `{table}`")
                    row_count = cursor.fetchone()['count']
                    stats["table_details"][table] = row_count
                    stats["total_rows_scanned"] += row_count

                    # 如果这张表没有文本字段，或者没有数据，直接跳过
                    if not text_columns or row_count == 0:
                        continue

                    # 3. 分批提取文本字段进行扫描，避免大表一次性 fetchall 造成内存压力
                    cols_str = ", ".join([f"`{col}`" for col in text_columns])
                    offset = 0

                    while True:
                        cursor.execute(
                            f"SELECT {cols_str} FROM `{table}` LIMIT %s OFFSET %s",
                            (self.batch_size, offset)
                        )
                        rows = cursor.fetchall()
                        if not rows:
                            break

                        for batch_row_idx, row_data in enumerate(rows, start=1):
                            row_idx = offset + batch_row_idx
                            for col_name, text_value in row_data.items():
                                if text_value: # 忽略 NULL 或空字符串
                                    # 调用通用的正则匹配引擎
                                    secrets_found = extract_secrets_from_text(str(text_value), col_name)

                                    for secret in secrets_found:
                                        res = ScanResult(
                                            source_type="DB",
                                            source_path=table, # 来源路径记为表名
                                            keyword=secret['keyword'],
                                            line_number=f"第{row_idx}行 - 字段[{col_name}]", # 位置记为行号和字段名
                                            context=secret['context'],
                                            rule_id=secret.get('rule_id', ''),
                                            rule_name=secret.get('rule_name', ''),
                                            risk_level=secret.get('risk_level', ''),
                                            rule_description=secret.get('rule_description', '')
                                        )
                                        results.append(res)

                        offset += self.batch_size
        except pymysql.MySQLError as e:
            raise ValueError(f"数据库连接或查询失败: {e}")
        finally:
            if 'connection' in locals() and connection.open:
                connection.close()

        return ScanSummary(
            task_name="数据库文本字段审计",
            total_scanned=stats["table_count"],
            total_secrets=len(results),
            scanned_details=stats["table_details"],
            results=results
        )

    def _get_text_columns(self, cursor, db_name, table_name) -> list[str]:
        """内部方法：查字典表，仅提取可能包含涉密文字的文本类字段"""
        query = """
            SELECT COLUMN_NAME 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = %s 
              AND DATA_TYPE IN ('varchar', 'text', 'char', 'longtext', 'mediumtext', 'tinytext')
        """
        cursor.execute(query, (db_name, table_name))
        return [row['COLUMN_NAME'] for row in cursor.fetchall()]
