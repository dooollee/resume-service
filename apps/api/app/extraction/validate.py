"""업로드 파일 검증. sniff()는 API에서, inspect_*()는 격리된 샌드박스 프로세스 안에서 실행된다.

검사 실패는 모두 Rejected(code)로 통일한다. code에는 개인정보가 들어가지 않는다.
"""

import io
import re
import xml.etree.ElementTree as ET  # noqa: S405 — 외부 엔터티 미해석, 3.12 번들 expat은 billion laughs 방어
import zipfile

PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
EXTENSIONS = {PDF: ".pdf", DOCX: ".docx"}
MAX_BYTES = 10 * 1024 * 1024


class Rejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sniff(content: bytes, filename: str) -> str:
    """확장자가 아니라 매직바이트로 판별하고, 확장자 위조는 거부한다."""
    if len(content) > MAX_BYTES:
        raise Rejected("too_large")
    if content.startswith(b"%PDF-"):
        mime = PDF
    elif content.startswith(b"PK\x03\x04"):
        mime = DOCX  # 실제 DOCX 구조인지는 샌드박스에서 확인
    else:
        raise Rejected("unsupported_type")
    if not filename.lower().endswith(EXTENSIONS[mime]):
        raise Rejected("extension_mismatch")
    return mime


# --- DOCX ---

MAX_ENTRIES = 1000
MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024
MAX_RATIO = 100
HYPERLINK_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
FORBIDDEN_PARTS = re.compile(r"(vbaProject|vbaData|activeX|embeddings/|oleObject|\.bin$|afchunk|altChunk)", re.I)
NESTED_ARCHIVE = re.compile(r"\.(zip|jar|docx|docm|xlsx|xlsm|pptx|7z|rar|gz|cab)$", re.I)


def inspect_docx(content: bytes) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise Rejected("invalid_file") from None
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise Rejected("zip_bomb")
    total = 0
    for info in infos:
        total += info.file_size
        ratio = info.file_size / max(info.compress_size, 1)
        if total > MAX_TOTAL_UNCOMPRESSED or (info.file_size > 1024 * 1024 and ratio > MAX_RATIO):
            raise Rejected("zip_bomb")
        if info.flag_bits & 0x1:
            raise Rejected("encrypted")
        if NESTED_ARCHIVE.search(info.filename):
            raise Rejected("nested_archive")
        if FORBIDDEN_PARTS.search(info.filename):
            raise Rejected("active_content")
    names = set(zf.namelist())
    if "word/document.xml" not in names or "[Content_Types].xml" not in names:
        raise Rejected("invalid_file")
    content_types = zf.read("[Content_Types].xml")
    if b"macroEnabled" in content_types or b"vbaProject" in content_types:
        raise Rejected("active_content")
    for name in names:
        if name.endswith(".rels"):
            try:
                root = ET.fromstring(zf.read(name))  # noqa: S314
            except ET.ParseError:
                raise Rejected("invalid_file") from None
            for rel in root:
                # 하이퍼링크 외 외부 참조(원격 템플릿·이미지·OLE)는 열람 시 외부 요청을 유발 → 거부
                if rel.get("TargetMode") == "External" and rel.get("Type") != HYPERLINK_REL:
                    raise Rejected("external_reference")
    return zf


# --- PDF ---

MAX_PAGES = 20
# 실행·외부 요청·내장 파일을 유발하는 PDF 이름들
FORBIDDEN_PDF_KEYS = {
    "JavaScript",
    "JS",
    "Launch",
    "EmbeddedFile",
    "EmbeddedFiles",
    "RichMedia",
    "XFA",
    "AA",
    "SubmitForm",
    "ImportData",
    "GoToR",
    "GoToE",
    "Sound",
    "Movie",
}


def _walk(obj, seen: set, doc, depth=0):
    from pdfminer.pdftypes import PDFObjectNotFound, PDFObjRef, PDFStream
    from pdfminer.psparser import PSLiteral

    if depth > 50:
        raise Rejected("invalid_file")
    if isinstance(obj, PDFObjRef):
        if obj.objid in seen:
            return
        seen.add(obj.objid)
        try:
            obj = obj.resolve()
        except PDFObjectNotFound:
            return  # 끊어진 참조 하나 때문에 같은 딕셔너리의 나머지 검사를 건너뛰지 않도록
    if isinstance(obj, PDFStream):
        if isinstance(obj.attrs.get("Type"), PSLiteral) and obj.attrs["Type"].name == "ObjStm":
            # xref에 등록되지 않은 객체도 압축 스트림 안에 숨길 수 있으므로 내용물을 직접 검사
            contained, _ = doc._get_objects(obj)
            for item in contained:
                _walk(item, seen, doc, depth + 1)
        obj = obj.attrs
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN_PDF_KEYS:
                raise Rejected("active_content")
            if k == "S" and isinstance(v, PSLiteral) and v.name in FORBIDDEN_PDF_KEYS:
                raise Rejected("active_content")
            _walk(v, seen, doc, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _walk(v, seen, doc, depth + 1)


def inspect_pdf(content: bytes):
    """오브젝트 스트림(압축) 안까지 디코드된 이름으로 검사한다(#4A 같은 이스케이프 우회 불가)."""
    from pdfminer.pdfdocument import PDFDocument, PDFEncryptionError, PDFPasswordIncorrect
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdftypes import PDFObjectNotFound

    try:
        doc = PDFDocument(PDFParser(io.BytesIO(content)))
    except (PDFEncryptionError, PDFPasswordIncorrect):
        raise Rejected("encrypted") from None
    except Exception:
        raise Rejected("invalid_file") from None
    if doc.encryption:
        raise Rejected("encrypted")
    seen: set = set()
    for xref in doc.xrefs:
        for objid in xref.get_objids():
            try:
                _walk(doc.getobj(objid), seen, doc)
            except PDFObjectNotFound:
                continue
            except Rejected:
                raise
            except Exception:
                raise Rejected("invalid_file") from None
    for trailer in (x.get_trailer() for x in doc.xrefs):
        _walk(trailer, seen, doc)
    pages = list(PDFPage.create_pages(doc))
    if not 1 <= len(pages) <= MAX_PAGES:
        raise Rejected("too_many_pages" if pages else "invalid_file")
    return doc
