from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.core import config

pool = ConnectionPool(config.DATABASE_URL, open=False, min_size=1, max_size=10, kwargs={"row_factory": dict_row})


def get_conn():
    """요청 단위 트랜잭션. 정상 종료 시 커밋, 예외 시 롤백."""
    with pool.connection() as conn:
        yield conn


def set_rls_context(conn, user_id: str | None, role: str) -> None:
    # 트랜잭션 로컬(true) → 풀에서 다른 요청으로 새지 않는다.
    conn.execute(
        "SELECT set_config('app.user_id', %s, true), set_config('app.role', %s, true)",
        (user_id or "", role),
    )
