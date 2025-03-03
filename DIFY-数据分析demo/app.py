from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Union, Set
import pymysql
import uvicorn
from contextlib import contextmanager
import sqlparse
from datetime import datetime, timedelta
import jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi import Security, Depends
import logging

app = FastAPI()

class SQLQuery(BaseModel):
    sql_query: str

@contextmanager
def get_db_connection(config):
    """数据库连接的上下文管理器"""
    conn = None
    try:
        conn = pymysql.connect(**config)
        yield conn
    finally:
        if conn:
            conn.close()

# 添加允许的 SQL 操作类型
ALLOWED_SQL_OPERATIONS = {'SELECT'}
# 添加禁止的关键词
FORBIDDEN_KEYWORDS = {
    'DROP', 'DELETE', 'UPDATE', 'INSERT', 'TRUNCATE', 
    'CREATE', 'ALTER', 'GRANT', 'EXECUTE', 'MERGE'
}

# 添加用户角色和权限控制
ROLE_PERMISSIONS = {
    'admin': {'all_tables'},
    'analyst': {'employees', 'departments', 'salaries'},
    'viewer': {'employees'}
}

# 添加 JWT 配置
JWT_SECRET = "your-secret-key"  # 建议使用环境变量
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class AuthError(Exception):
    pass

def validate_sql_query(sql_query: str) -> bool:
    """验证 SQL 查询的安全性"""
    # 解析 SQL 语句
    parsed = sqlparse.parse(sql_query.strip())
    if not parsed:
        raise HTTPException(status_code=400, detail="无效的 SQL 查询")
    
    statement = parsed[0]
    # 获取查询类型
    query_type = statement.get_type().upper()
    
    # 检查是否是允许的操作类型
    if query_type not in ALLOWED_SQL_OPERATIONS:
        raise HTTPException(
            status_code=403, 
            detail=f"不允许的操作类型: {query_type}。仅允许 SELECT 操作"
        )
    
    # 检查是否包含禁止的关键词
    sql_upper = sql_query.upper()
    for keyword in FORBIDDEN_KEYWORDS:
        if keyword in sql_upper:
            raise HTTPException(
                status_code=403,
                detail=f"查询中包含禁止的关键词: {keyword}"
            )
    
    return True

# 配置日志
logging.basicConfig(
    filename='sql_queries.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class QueryLimiter:
    def __init__(self):
        self.queries = {}
        self.max_queries_per_minute = 60
        self.max_rows_per_query = 1000

    def check_rate_limit(self, api_key: str):
        """检查查询频率限制"""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # 清理旧的查询记录
        self.queries = {
            k: v for k, v in self.queries.items() 
            if v['timestamp'] > minute_ago
        }
        
        # 检查频率限制
        if (
            api_key in self.queries and 
            self.queries[api_key]['count'] >= self.max_queries_per_minute
        ):
            raise HTTPException(
                status_code=429,
                detail="超过每分钟查询限制"
            )
        
        # 更新查询计数
        if api_key not in self.queries:
            self.queries[api_key] = {'count': 1, 'timestamp': now}
        else:
            self.queries[api_key]['count'] += 1

query_limiter = QueryLimiter()

@app.post("/execute_query")
async def execute_query(
    query: SQLQuery,
    api_key: str = Depends(verify_api_key),
    user_role: str = Header(..., alias="X-User-Role")
):
    """处理POST请求以执行SQL查询"""
    try:
        # 检查频率限制
        query_limiter.check_rate_limit(api_key)
        
        sql_queries = query.sql_query.strip()
        if not sql_queries:
            raise HTTPException(status_code=400, detail="缺少 sql_query 参数")

        for sql_query in sql_queries.split(';'):
            if sql_query.strip():
                # 验证 SQL 查询
                validate_sql_query(sql_query)
                # 验证表访问权限
                verify_table_access(sql_query, user_role)

        # 记录查询
        logging.info(f"User Role: {user_role}, Query: {sql_queries}")

        with get_db_connection(app.db_config) as conn:
            results = []
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                for sql_query in sql_queries.split(';'):
                    if sql_query.strip():
                        cursor.execute(sql_query)
                        result = cursor.fetchall()
                        
                        # 检查结果集大小限制
                        if len(result) > query_limiter.max_rows_per_query:
                            raise HTTPException(
                                status_code=400,
                                detail=f"查询结果超过最大行数限制 ({query_limiter.max_rows_per_query})"
                            )
                            
                        if result:
                            results.extend(result)
                conn.commit()
            
        return results

    except pymysql.Error as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"数据库错误: {str(e)}")
    except Exception as e:
        logging.error(f"Server error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"服务器错误: {str(e)}")

def verify_api_key(
    api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> str:
    """验证 API 密钥并返回用户信息"""
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="缺少 API 密钥"
        )
    
    if api_key != app.api_key:
        raise HTTPException(
            status_code=401,
            detail="无效的 API 密钥"
        )
    
    return api_key

def verify_table_access(sql_query: str, user_role: str):
    """验证用户是否有权限访问查询中的表"""
    # 简单的表名提取（实际应该使用更复杂的 SQL 解析）
    tables = set()
    sql_lower = sql_query.lower()
    
    # 从 FROM 和 JOIN 子句中提取表名
    from_parts = sql_lower.split('from')
    if len(from_parts) > 1:
        table_part = from_parts[1].split('where')[0]
        tables.update(t.strip() for t in table_part.split(','))
    
    # 检查用户是否有权限访问所有涉及的表
    allowed_tables = ROLE_PERMISSIONS.get(user_role, set())
    if not allowed_tables.intersection(tables):
        raise HTTPException(
            status_code=403,
            detail=f"用户角色 {user_role} 没有权限访问请求的表"
        )

if __name__ == '__main__':
    # 数据库配置
    app.db_config = {
        "host": "127.0.0.1",
        "user": "demo",
        "password": "Ohnu5aeX",
        "database": "employees",
        "port": 3306,
        "charset": 'utf8mb4'
    }
    
    # 添加API密钥配置
    app.api_key = "oWoh*thae5"  # 建议使用环境变量存储此密钥
    
    uvicorn.run(app, host='0.0.0.0', port=35003)

