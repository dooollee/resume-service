"""정형 양식 규칙 파서 (샌드박스 안에서만 호출). 양식 규격: docs/RESUME_FORM.md

문서를 블록 흐름 [("text", 줄) | ("table", 행 목록)]으로 바꾼 뒤 섹션 헤더를 기준으로 해석한다.
주민등록번호는 파싱 전에 텍스트에서 제거되며 값은 어디에도 남지 않는다.
"""

import base64
import io
import re

from app import normalize, skills
from app.extraction import validate

RRN_RE = re.compile(r"(?<!\d)\d{6}\s*[-–]?\s*[1-8]\d{6}(?!\d)")
RRN_KEY_RE = re.compile(r"주민\s*(등록)?\s*번호|외국인\s*등록\s*번호")

SECTIONS = {
    "identity": ["인적사항", "인적 사항", "기본정보", "기본 정보", "개인정보"],
    "education": ["학력", "학력사항", "학력 사항"],
    "career": ["경력", "경력사항", "경력 사항"],
    "skills": ["기술", "보유기술", "보유 기술", "기술스택", "기술 스택"],
    "certs": ["자격", "자격증", "자격사항", "자격/어학", "자격증/어학"],
    "intro": ["자기소개", "자기 소개", "자기소개서"],
}
_HEADER = {name: sec for sec, names in SECTIONS.items() for name in names}

IDENTITY_KEYS = {
    "name": ["이름", "성명"],
    "birth": ["생년월일"],
    "gender": ["성별"],
    "phone": ["휴대폰", "휴대전화", "연락처", "전화번호", "핸드폰", "phone"],
    "email": ["이메일", "e-mail", "email", "전자우편"],
    "address": ["주소", "거주지"],
}
COLUMNS = {
    "education": {
        "school": ["학교", "학교명"],
        "major": ["전공"],
        "degree": ["학위", "구분"],
        "start_ym": ["입학", "입학일", "입학년월"],
        "end_ym": ["졸업", "졸업일", "졸업년월"],
    },
    "career": {
        "company": ["회사", "회사명", "근무처"],
        "title": ["직무", "직위", "담당", "직책"],
        "start_ym": ["시작", "입사", "입사일", "시작일"],
        "end_ym": ["종료", "퇴사", "퇴사일", "종료일"],
        "description": ["담당업무", "업무내용", "주요업무"],
    },
    "skills": {
        "name": ["기술", "기술명", "스킬"],
        "level": ["숙련도", "수준"],
        "years": ["경력", "경력(년)", "연수", "사용기간"],
    },
    "certs": {
        "name": ["자격증", "자격명", "명칭"],
        "issuer": ["발급기관", "발행처", "기관"],
        "acquired_ym": ["취득일", "취득", "취득년월"],
    },
}
LIMITS = {"description": 2000, "degree": 30, "name": 100}  # schemas.py의 최대 길이에 맞춤(초과 시 전체 실패 방지)
LEVELS = {
    "초급": "초급",
    "하": "초급",
    "중급": "중급",
    "중": "중급",
    "고급": "고급",
    "상": "고급",
    "전문가": "전문가",
    "특급": "전문가",
}
GENDERS = {"남": "남", "남성": "남", "m": "남", "male": "남", "여": "여", "여성": "여", "f": "여", "female": "여"}


def preload() -> None:
    import docx  # noqa: F401
    import pdfminer.high_level  # noqa: F401
    import pdfplumber  # noqa: F401
    import PIL.Image  # noqa: F401
    import PIL.JpegImagePlugin  # noqa: F401
    import PIL.PngImagePlugin  # noqa: F401


def _cell(text: str | None) -> str:
    return re.sub(r"\s+", " ", text or "").strip()  # PDF 셀 줄바꿈 등 공백 정규화


def _norm_key(s: str) -> str:
    return re.sub(r"[\s:：*]", "", s).lower()


def _header_of(text: str) -> str | None:
    t = re.sub(r"^[\[\(【■●▶\d.\s]+|[\]\)】\s:]+$", "", text.strip())
    return _HEADER.get(t)


# --- 문서 → 블록 ---


def _docx_blocks(content: bytes) -> tuple[list, list[bytes]]:
    import docx
    from docx.oxml.ns import qn
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    d = docx.Document(io.BytesIO(content))
    blocks = []
    for el in d.element.body.iterchildren():
        if el.tag == qn("w:p"):
            text = Paragraph(el, d).text
            blocks.extend(("text", line) for line in text.splitlines() if line.strip())
        elif el.tag == qn("w:tbl"):
            rows = []
            for row in Table(el, d).rows:
                cells = []
                for c in row.cells:  # 병합 셀 중복 제거
                    if not cells or c._tc is not cells[-1][0]:
                        cells.append((c._tc, _cell(c.text)))
                rows.append([t for _, t in cells])
            blocks.append(("table", rows))
    images = [p.blob for p in d.part.package.parts if p.content_type.startswith("image/")]
    return blocks, images


def _pdf_blocks(content: bytes) -> tuple[list, list[bytes]]:
    import pdfplumber

    blocks, images = [], []
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        for page in pdf.pages:
            tables = page.find_tables()
            items = [(t.bbox[1], ("table", [[_cell(c) for c in row] for row in t.extract()])) for t in tables]

            def outside(obj, boxes=tuple(t.bbox for t in tables)):
                return not any(
                    b[0] <= obj["x0"] and obj["x1"] <= b[2] and b[1] <= obj["top"] and obj["bottom"] <= b[3]
                    for b in boxes
                )

            for line in page.filter(outside).extract_text_lines():
                items.append((line["top"], ("text", line["text"])))
            blocks.extend(b for _, b in sorted(items, key=lambda x: x[0]))
            for img in page.images:
                data = _pdf_image_bytes(img["stream"])
                if data:
                    images.append(data)
    return blocks, images


def _pdf_image_bytes(stream) -> bytes | None:
    from PIL import Image

    filters = stream.get_filters()
    names = [getattr(f[0], "name", str(f[0])) for f in filters]
    if names == ["DCTDecode"]:
        return stream.get_rawdata()
    if names == ["FlateDecode"] and stream.attrs.get("BitsPerComponent") == 8:
        mode = {"DeviceRGB": "RGB", "DeviceGray": "L"}.get(getattr(stream.attrs.get("ColorSpace"), "name", ""))
        if mode:
            img = Image.frombytes(mode, (stream.attrs["Width"], stream.attrs["Height"]), stream.get_data())
            buf = io.BytesIO()
            img.save(buf, "PNG")
            return buf.getvalue()
    return None


# --- 금지 정보 필터 ---


def _scrub(blocks: list) -> tuple[list, bool]:
    found = False

    def clean(text: str) -> str:
        nonlocal found
        if RRN_RE.search(text) or RRN_KEY_RE.search(text):
            found = True
        return RRN_RE.sub("", text)

    out = []
    for kind, value in blocks:
        if kind == "text":
            if RRN_KEY_RE.search(value):  # "주민등록번호: 950412-1******" 처럼 마스킹된 값도 줄째 폐기
                found = True
                continue
            out.append((kind, clean(value)))
        else:
            rows = []
            for row in value:
                cells = list(row)
                for i, c in enumerate(cells):
                    if RRN_KEY_RE.search(c):  # 키 셀과 바로 옆 값 셀을 함께 폐기
                        found = True
                        cells[i] = ""
                        if i + 1 < len(cells):
                            cells[i + 1] = ""
                rows.append([clean(c) for c in cells])
            out.append((kind, rows))
    return out, found


# --- 섹션 해석 ---


def _key_values(blocks: list) -> dict[str, str]:
    pairs: list[tuple[str, str]] = []
    for kind, value in blocks:
        if kind == "text":
            for m in re.finditer(r"([^:：|]{1,10})\s*[:：]\s*([^|]*?)(?=\s*\|\s*[^:：|]{1,10}[:：]|$)", value):
                pairs.append((m.group(1), m.group(2)))
        else:
            for row in value:
                for i in range(0, len(row) - 1, 2):
                    pairs.append((row[i], row[i + 1]))
    lookup = {_norm_key(alias): field for field, aliases in IDENTITY_KEYS.items() for alias in aliases}
    out = {}
    for k, v in pairs:
        field = lookup.get(_norm_key(k))
        if field and v.strip() and field not in out:
            out[field] = v.strip()
    return out


def _rows(blocks: list) -> list[list[str]]:
    rows = []
    for kind, value in blocks:
        if kind == "table":
            rows.extend(value)
        elif "|" in value:
            rows.append([c.strip() for c in value.split("|")])
    return [r for r in rows if any(c for c in r)]


def _table(section: str, blocks: list) -> list[dict]:
    rows = _rows(blocks)
    if not rows:
        return []
    lookup = {_norm_key(alias): field for field, aliases in COLUMNS[section].items() for alias in aliases}
    header = [lookup.get(_norm_key(c)) for c in rows[0]]
    if not any(header):
        return []
    return [
        {f: cell[: LIMITS.get(f, 100)] for f, cell in zip(header, row, strict=False) if f and cell} for row in rows[1:]
    ]


def _years(value: str | None) -> float | None:
    m = re.search(r"\d+(\.\d+)?", value or "")
    return min(float(m.group()), 60.0) if m else None


def _build(sections: dict[str, list]) -> dict:
    kv = _key_values(sections.get("identity", []))
    identity = {
        "name": kv.get("name"),
        "birth": normalize.ymd(kv.get("birth")),
        "gender": GENDERS.get((kv.get("gender") or "").strip().lower()),
        "phone": normalize.phone(kv.get("phone")),
        "email": normalize.email(kv.get("email")),
        "address": kv.get("address"),
    }
    education = [
        {**r, "start_ym": normalize.ym(r.get("start_ym")), "end_ym": normalize.ym(r.get("end_ym"))}
        for r in _table("education", sections.get("education", []))
    ]
    career = [
        {**r, "start_ym": normalize.ym(r.get("start_ym")), "end_ym": normalize.ym(r.get("end_ym"))}
        for r in _table("career", sections.get("career", []))
    ]
    skill_rows = []
    for r in _table("skills", sections.get("skills", [])):
        names = [n for n in re.split(r"[,/·]", r.get("name", "")) if n.strip()]
        for n in names:
            skill_rows.append(
                {
                    "name": skills.canonical(n)[:50],
                    "level": LEVELS.get((r.get("level") or "").strip()),
                    "years": _years(r.get("years")),
                }
            )
    certs = [
        {**r, "acquired_ym": normalize.ym(r.get("acquired_ym"))} for r in _table("certs", sections.get("certs", []))
    ]
    intro_lines = [v if k == "text" else "\n".join(" ".join(row) for row in v) for k, v in sections.get("intro", [])]
    return {
        "identity": {
            **identity,
            "name": (identity["name"] or "")[:50] or None,
            "address": (identity["address"] or "")[:200] or None,
        },
        "intro": "\n".join(intro_lines)[:5000] or None,
        "education": education[:20],
        "career": [{**c, "description": (c.get("description") or "")[:2000] or None} for c in career[:30]],
        "skills": skill_rows[:100],
        "certs": certs[:30],
    }


# --- 사진 ---


def _photo(images: list[bytes]) -> str | None:
    """증명사진 후보(세로 비율)를 재인코딩: EXIF/GPS 등 메타데이터 제거, 해상도 제한."""
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = 20_000_000  # 이미지 폭탄 방어
    for data in images:
        try:
            with Image.open(io.BytesIO(data)) as img:
                w, h = img.size
                if not (100 <= w <= 5000 and 1.1 <= h / w <= 1.7):
                    continue
                img.load()
                clean = img.convert("RGB")
        except Exception:  # noqa: S112 — 손상된 이미지는 후보에서 제외
            continue
        clean.thumbnail((600, 800))
        buf = io.BytesIO()
        clean.save(buf, "JPEG", quality=85)  # exif 인자를 넘기지 않으므로 메타데이터 없음
        return base64.b64encode(buf.getvalue()).decode()
    return None


def extract(mime: str, content: bytes) -> dict:
    if mime == validate.PDF:
        validate.inspect_pdf(content)
        blocks, images = _pdf_blocks(content)
    elif mime == validate.DOCX:
        validate.inspect_docx(content)
        blocks, images = _docx_blocks(content)
    else:
        raise validate.Rejected("unsupported_type")

    blocks, rrn_found = _scrub(blocks)
    sections: dict[str, list] = {}
    current = None
    for kind, value in blocks:
        if kind == "text" and (sec := _header_of(value)):
            current = sec
            continue
        if kind == "table" and value and value[0] and (sec := _header_of(value[0][0])) and len(value[0]) == 1:
            current = sec  # 헤더가 표 첫 줄(1칸)인 양식
            value = value[1:]
        if current:
            sections.setdefault(current, []).append((kind, value))

    photo = _photo(images)
    warnings = (["rrn_removed"] if rrn_found else []) + ([] if photo else ["photo_not_found"])
    return {"data": _build(sections), "photo": photo, "warnings": warnings}
