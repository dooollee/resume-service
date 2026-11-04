"""샌드박스 안에서만 호출되는 추출 진입점."""

from app.extraction import validate


def preload() -> None:
    import docx  # noqa: F401
    import pdfminer.high_level  # noqa: F401
    import pdfplumber  # noqa: F401
    import PIL.Image  # noqa: F401


def extract(mime: str, content: bytes) -> dict:
    if mime == validate.PDF:
        validate.inspect_pdf(content)
    elif mime == validate.DOCX:
        validate.inspect_docx(content)
    else:
        raise validate.Rejected("unsupported_type")
    # ponytail: M3는 검증까지. 필드 추출은 M4에서 채운다.
    return {"data": {}, "photo": None, "warnings": []}
