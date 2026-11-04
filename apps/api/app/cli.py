"""운영 명령. 컨테이너 안에서 `python -m app.cli <명령>`으로 실행한다."""

import argparse
import getpass
import os
import sys

from app import crypto
from app.db import pool, set_rls_context

# (테이블, DEK 컨텍스트 접두사) — 봉투 암호화를 쓰는 테이블
ENVELOPE_TABLES = [("users", "user")]


def cmd_migrate(_):
    from app.migrate import bootstrap, migrate

    bootstrap(os.environ["ADMIN_DATABASE_URL"], os.environ["APP_DB_PASSWORD"])
    print("applied:", migrate(os.environ["ADMIN_DATABASE_URL"]) or "nothing")


def cmd_create_admin(_):
    from app.admin import create_user

    email = input("관리자 이메일: ")
    password = getpass.getpass("초기 비밀번호(12자 이상, 첫 로그인 때 변경 강제): ")
    with pool.connection() as conn:
        create_user(conn, email, "admin", password)
    print("생성됨. 첫 로그인에서 MFA 등록과 비밀번호 변경이 강제됩니다.")


def cmd_rotate_kek(_):
    """모든 DEK를 KEK_CURRENT로 다시 감싼다. 완료 후 이전 KEK를 KEK_KEYS에서 제거할 수 있다."""
    with pool.connection() as conn:
        set_rls_context(conn, None, "system")
        for table, ctx in ENVELOPE_TABLES:
            rows = conn.execute(
                f"SELECT id, dek_wrapped, key_version FROM {table} WHERE key_version <> %s",  # noqa: S608 — 고정 테이블명
                (crypto.KEK_CURRENT,),
            ).fetchall()
            for r in rows:
                wrapped, version = crypto.rewrap(r["dek_wrapped"], r["key_version"], f"{ctx}:{r['id']}")
                conn.execute(f"UPDATE {table} SET dek_wrapped = %s, key_version = %s WHERE id = %s",  # noqa: S608
                             (wrapped, version, r["id"]))
            print(f"{table}: {len(rows)} rewrapped")


COMMANDS = {"migrate": cmd_migrate, "create-admin": cmd_create_admin, "rotate-kek": cmd_rotate_kek}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="app.cli")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args(argv)
    if args.command != "migrate":
        pool.open(wait=True)
    COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
