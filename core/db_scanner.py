# core/db_scanner.py
import pymysql
from models.data_models import ScanResult
from utils.regex_utils import extract_secrets_from_text

class DBScanner:
    def __init__(self, host, port, user, password, database):
        """初始化数据库连接配置"""
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

    def scan(self) -> tuple[list[ScanResult], dict]:
        """
        执行全库扫描。
        返回: (涉密结果列表, 扫描统计信息字典)
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

                    # 3. 提取所有文本字段的数据进行扫描
                    cols_str = ", ".join([f"`{col}`" for col in text_columns])
                    # 使用流式获取(fetchall在数据极大时可改为fetchmany，但本项目100条规模直接fetchall即可)
                    cursor.execute(f"SELECT {cols_str} FROM `{table}`")
                    rows = cursor.fetchall()

                    for row_idx, row_data in enumerate(rows, start=1):
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
                                        context=secret['context']
                                    )
                                    results.append(res)
        except pymysql.MySQLError as e:
            raise ValueError(f"数据库连接或查询失败: {e}")
        finally:
            if 'connection' in locals() and connection.open:
                connection.close()

        return results, stats

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