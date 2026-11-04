"""격리된 파싱 프로세스. 신뢰할 수 없는 파일은 이 프로세스 안에서만 열린다.

부모(worker)가 보장하는 것: 비밀값 없는 최소 환경변수, (Linux) 메모리·CPU·파일쓰기 rlimit, 타임아웃,
stderr 폐기(트레이스백에 개인정보가 섞일 수 있음). 컨테이너는 읽기 전용 + 외부망 없음.
이 프로세스 스스로: 무거운 모듈을 먼저 임포트한 뒤 감사 훅으로 네트워크·프로세스 생성·파일 쓰기를 차단.

프로토콜: stdin = "<mime>\n<파일 바이트>", stdout = JSON 한 줄.
"""

import json
import os
import subprocess  # noqa: S404
import sys
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[2]
TIMEOUT_SECONDS = 60

_BLOCKED_EVENTS = {
    "socket.connect",
    "socket.bind",
    "socket.getaddrinfo",
    "socket.sendto",
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.fork",
    "os.forkpty",
    "ctypes.dlopen",
    "urllib.Request",
    "webbrowser.open",
}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _audit_hook(event: str, args) -> None:
    if event in _BLOCKED_EVENTS:
        raise RuntimeError("blocked in sandbox")
    if event == "open":
        _, mode, flags = args
        if (isinstance(mode, str) and set(mode) & set("wax+")) or (isinstance(flags, int) and flags & _WRITE_FLAGS):
            raise RuntimeError("blocked in sandbox")


def _child_main() -> None:
    sys.dont_write_bytecode = True
    from app.extraction import parse, validate  # 무거운 모듈(pdfminer, docx, PIL)을 훅 설치 전에 로드

    parse.preload()
    raw = sys.stdin.buffer.read()
    sys.addaudithook(_audit_hook)  # 이후로는 제거 불가

    mime, _, content = raw.partition(b"\n")
    try:
        result = parse.extract(mime.decode(), content)
        out = {"ok": True, **result}
    except validate.Rejected as e:
        out = {"ok": False, "code": e.code}
    except MemoryError:
        out = {"ok": False, "code": "resource_limit"}
    except Exception:
        out = {"ok": False, "code": "parse_error"}
    sys.stdout.buffer.write(json.dumps(out).encode())  # -E라 PYTHONIOENCODING 무시됨 → 바이트로 직접


def _limits() -> None:  # pragma: no cover — Linux 자식 프로세스에서만 실행
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))  # 메모리 1GiB (압축폭탄·이미지폭탄)
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # 파일 쓰기 불가
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setsid()


def run(content: bytes, mime: str) -> dict:
    """부모 쪽: 샌드박스 프로세스를 띄우고 결과 JSON을 반환. 실패는 code로만 표현한다."""
    env = {"PATH": os.environ.get("PATH", "")}
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    try:
        # ponytail: Windows(로컬 개발)에는 rlimit이 없어 타임아웃·감사 훅만 적용. 운영은 Linux 컨테이너.
        p = subprocess.run(  # noqa: S603 — 고정 인자, 셸 미사용
            [sys.executable, "-B", "-E", "-s", "-m", "app.extraction.sandbox"],
            input=mime.encode() + b"\n" + content,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            env=env,
            cwd=API_ROOT,
            preexec_fn=_limits if os.name == "posix" else None,  # noqa: PLW1509
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": "timeout"}
    if p.returncode != 0 or not p.stdout:
        return {"ok": False, "code": "resource_limit" if p.returncode < 0 else "parse_error"}
    try:
        return json.loads(p.stdout)
    except ValueError:
        return {"ok": False, "code": "parse_error"}


if __name__ == "__main__":
    _child_main()
