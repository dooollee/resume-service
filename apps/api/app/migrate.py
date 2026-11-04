"""DB 역할 부트스트랩 + 마이그레이션.

- resume_owner: 테이블 소유자(NOLOGIN). DDL은 이 역할로만.
- resume_app: 애플리케이션 계정. DML만, 슈퍼유저/DDL/BYPASSRLS 없음 → RLS가 항상 적용된다.
관리자(슈퍼유저) URL은 이 스크립트에만 주고 애플리케이션에는 주지 않는다.
"""

from pathlib import Path

import psycopg
from psycopg import sql

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


def bootstrap(admin_url: str, app_password: str) -> None:
    with psycopg.connect(admin_url, autocommit=True) as c:
        for role, login in (("resume_owner", "NOLOGIN"), ("resume_app", "LOGIN")):
            if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                c.execute(sql.SQL("CREATE ROLE {} " + login).format(sql.Identifier(role)))
        c.execute(
            sql.SQL(
                "ALTER ROLE resume_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS "
                "CONNECTION LIMIT 50 PASSWORD {}"
            ).format(sql.Literal(app_password))
        )
        db = sql.Identifier(c.execute("SELECT current_database()").fetchone()[0])
        c.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(db))
        c.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO resume_app").format(db))
        c.execute("ALTER SCHEMA public OWNER TO resume_owner")
        c.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        c.execute("GRANT USAGE ON SCHEMA public TO resume_app")
        c.execute(
            "ALTER DEFAULT PRIVILEGES FOR ROLE resume_owner IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO resume_app"
        )
        c.execute(
            "ALTER DEFAULT PRIVILEGES FOR ROLE resume_owner IN SCHEMA public "
            "GRANT USAGE, SELECT ON SEQUENCES TO resume_app"
        )
        c.execute(
            "ALTER DEFAULT PRIVILEGES FOR ROLE resume_owner IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
        )


def migrate(admin_url: str) -> list[str]:
    applied = []
    with psycopg.connect(admin_url) as c:
        c.execute("SET ROLE resume_owner")
        c.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz DEFAULT now())"
        )
        c.execute("REVOKE ALL ON schema_migrations FROM resume_app")
        c.commit()
        done = {r[0] for r in c.execute("SELECT name FROM schema_migrations")}
        for f in sorted(MIGRATIONS.glob("*.sql")):
            if f.name in done:
                continue
            c.execute(f.read_text(encoding="utf-8"))  # 파라미터 없음 → 다중 문장 허용
            c.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (f.name,))
            c.commit()
            applied.append(f.name)
    return applied
