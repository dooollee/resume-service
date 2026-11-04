"""정형 양식(docs/RESUME_FORM.md) 합성 이력서 생성기. 이름·연락처 등은 모두 무작위 가짜 값."""

import io
import os
import random
from pathlib import Path

SURNAMES = "김이박최정강조윤장임한오서신권황안송류홍"
SYLLABLES = "가나다라마바사아자차카타파하준서윤지민우현수영진"
SCHOOLS = ["가상대학교", "예시대학교", "샘플공과대학교", "테스트여자대학교"]
MAJORS = ["컴퓨터공학", "산업디자인", "경영학", "전자공학", "통계학"]
COMPANIES = ["예시주식회사", "가상테크", "샘플랩스", "테스트소프트"]
TITLES = ["백엔드 개발자", "프론트엔드 개발자", "데이터 엔지니어", "프로덕트 디자이너"]
SKILLS = [
    ("파이썬", "Python"),
    ("리액트", "React"),
    ("js", "JavaScript"),
    ("TypeScript", "TypeScript"),
    ("도커", "Docker"),
    ("k8s", "Kubernetes"),
    ("PostgreSQL", "PostgreSQL"),
    ("spring boot", "Spring"),
]
CERTS = [("정보처리기사", "한국산업인력공단"), ("SQLD", "한국데이터산업진흥원"), ("TOEIC 900", "ETS")]


def resume_truth(seed: int) -> dict:
    """생성기 입력이자 정답(정규화 후 값)."""
    r = random.Random(seed)
    name = r.choice(SURNAMES) + "".join(r.choice(SYLLABLES) for _ in range(2))
    mid, last = r.randint(1000, 9999), r.randint(1000, 9999)
    y = r.randint(1985, 2000)
    skills = r.sample(SKILLS, 3)
    levels = ["초급", "중급", "고급", "전문가"]
    return {
        "raw_phone": f"010-{mid}-{last}",
        "raw_birth": f"{y}.{r.randint(1, 12):02d}.{r.randint(1, 28):02d}",
        "raw_skills": [s[0] for s in skills],
        "identity": {
            "name": name,
            "phone": f"+8210{mid}{last}",
            "email": f"user{seed}@example.test",
            "gender": r.choice(["남", "여"]),
            "address": f"가상시 테스트구 샘플로 {r.randint(1, 300)}",
        },
        "education": [
            {
                "school": r.choice(SCHOOLS),
                "major": r.choice(MAJORS),
                "degree": "학사",
                "start_ym": f"{y + 19}-03",
                "end_ym": f"{y + 23}-02",
            }
        ],
        "career": [
            {
                "company": r.choice(COMPANIES),
                "title": r.choice(TITLES),
                "start_ym": f"{y + 23}-03",
                "end_ym": f"{y + 26}-12",
                "description": "합성 담당업무 설명 문장",
            }
        ],
        "skills": [{"name": s[1], "level": r.choice(levels), "years": float(r.randint(1, 8))} for s in skills],
        "certs": [{"name": c[0], "issuer": c[1], "acquired_ym": f"{y + 22}-11"} for c in r.sample(CERTS, 1)],
        "intro": "합성 자기소개 문단입니다. 실제 인물과 무관합니다.",
    }


def _birth_iso(t):
    yy, mm, dd = t["raw_birth"].split(".")
    return f"{yy}-{mm}-{dd}"


def photo_with_exif() -> bytes:
    """GPS 포함 EXIF가 박힌 세로형 가짜 증명사진."""
    from PIL import Image

    img = Image.new("RGB", (300, 400), (180, 200, 220))
    exif = Image.Exif()
    exif[0x010F] = "SyntheticCam"  # Make
    exif[0x8825] = {1: "N", 2: (37.0, 33.0, 0.0), 3: "E", 4: (126.0, 58.0, 0.0)}  # GPSInfo
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif)
    return buf.getvalue()


def _sections(t: dict, with_rrn: bool):
    ident = t["identity"]
    kv = [
        ["이름", ident["name"], "생년월일", t["raw_birth"]],
        ["성별", ident["gender"], "휴대폰", t["raw_phone"]],
        ["이메일", ident["email"].upper() if int(t["raw_phone"][-1]) % 2 else ident["email"], "주소", ident["address"]],
    ]
    if with_rrn:
        kv.append(["주민등록번호", "900101-1234567", "", ""])
    e, c = t["education"][0], t["career"][0]
    return [
        ("인적사항", kv, False),
        (
            "학력",
            [
                ["학교", "전공", "학위", "입학", "졸업"],
                [e["school"], e["major"], e["degree"], e["start_ym"].replace("-", "."), e["end_ym"].replace("-", ".")],
            ],
            True,
        ),
        (
            "경력",
            [
                ["회사", "직무", "시작", "종료", "담당업무"],
                [c["company"], c["title"], c["start_ym"], c["end_ym"], c["description"]],
            ],
            True,
        ),
        (
            "기술",
            [["기술", "숙련도", "경력(년)"]]
            + [[raw, s["level"], f"{int(s['years'])}년"] for raw, s in zip(t["raw_skills"], t["skills"], strict=True)],
            True,
        ),
        (
            "자격",
            [["자격증", "발급기관", "취득일"]] + [[x["name"], x["issuer"], x["acquired_ym"]] for x in t["certs"]],
            True,
        ),
    ]


def make_docx(t: dict, *, photo: bool = True, with_rrn: bool = False) -> bytes:
    import docx
    from docx.shared import Cm

    d = docx.Document()
    d.add_heading("이력서", 0)
    if photo:
        d.add_picture(io.BytesIO(photo_with_exif()), width=Cm(3))
    for title, rows, _ in _sections(t, with_rrn):
        d.add_paragraph(f"[{title}]")
        table = d.add_table(rows=len(rows), cols=len(rows[0]))
        for i, row in enumerate(rows):
            for j, cell in enumerate(row):
                table.cell(i, j).text = cell
    d.add_paragraph("[자기소개]")
    d.add_paragraph(t["intro"])
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def korean_font() -> str | None:
    candidates = [
        os.environ.get("TEST_KOREAN_FONT", ""),
        "C:/Windows/Fonts/malgun.ttf",
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/System/Library/Fonts/AppleSDGothicNeo.ttc",
    ]
    return next((c for c in candidates if c and Path(c).exists()), None)


def make_pdf(t: dict, *, photo: bool = True, with_rrn: bool = False) -> bytes:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("kr", fname=korean_font())
    pdf.set_font("kr", size=10)
    pdf.cell(text="이력서", new_x="LMARGIN", new_y="NEXT")
    if photo:
        pdf.image(io.BytesIO(photo_with_exif()), x=170, y=8, w=25)
    for title, rows, _ in _sections(t, with_rrn):
        pdf.ln(4)
        pdf.cell(text=f"[{title}]", new_x="LMARGIN", new_y="NEXT")
        with pdf.table(first_row_as_headings=False) as table:
            for row in rows:
                table.row(row)
    pdf.ln(4)
    pdf.cell(text="[자기소개]", new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, t["intro"])
    return bytes(pdf.output())


def expected(t: dict) -> dict:
    return {
        **{k: t[k] for k in ("education", "career", "skills", "certs", "intro")},
        "identity": {**t["identity"], "birth": _birth_iso(t)},
    }
