from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Union
import pymysql
import uvicorn
from contextlib import contextmanager

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

@app.post("/execute_query")
async def execute_query(
    query: SQLQuery,
    api_key: Optional[str] = Header(None, alias="X-API-Key")
):
    """处理POST请求以执行SQL查询。"""
    try:
        sql_queries = query.sql_query.strip()

        if not sql_queries:
            raise HTTPException(status_code=400, detail="Missing sql_query parameter")

        with get_db_connection(app.db_config) as conn:
            results = []
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                for sql_query in sql_queries.split(';'):
                    if sql_query.strip():
                        cursor.execute(sql_query)
                        result = cursor.fetchall()
                        if result:
                            results.extend(result)
                conn.commit()
            
        return results

    except pymysql.Error as e:
        raise HTTPException(status_code=500, detail=f"数据库错误: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"服务器错误: {str(e)}")

def verify_api_key(api_key: Optional[str]) -> bool:
    """验证API密钥"""
    return api_key == app.api_key

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

