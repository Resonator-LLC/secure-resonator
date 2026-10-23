import os
from contextlib import contextmanager
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

_pool = None

def pool():
    global _pool
    if _pool is None:
        _pool = ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=8, kwargs={"row_factory": dict_row})
    return _pool

@contextmanager
def conn():
    with pool().connection() as c:
        yield c

def init_schema():
    import pathlib
    sql = (pathlib.Path(__file__).parent / "schema.sql").read_text()
    with conn() as c:
        c.execute(sql)

def q(sql, params=None, one=False):
    with conn() as c:
        cur = c.execute(sql, params)
        if cur.description is None:
            return None
        return cur.fetchone() if one else cur.fetchall()
