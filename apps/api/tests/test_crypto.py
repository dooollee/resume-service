import pytest
from cryptography.exceptions import InvalidTag

from app import crypto

RID_A = "11111111-1111-4111-8111-111111111111"
RID_B = "22222222-2222-4222-8222-222222222222"


def test_roundtrip_and_ciphertext_is_not_plaintext():
    dek = crypto.new_dek()
    blob = crypto.encrypt(dek, f"{RID_A}|name", "홍길동")
    assert "홍길동".encode() not in blob
    assert crypto.decrypt_str(dek, f"{RID_A}|name", blob) == "홍길동"
    assert crypto.encrypt(dek, "x", "same") != crypto.encrypt(dek, "x", "same")  # 랜덤 nonce


@pytest.mark.parametrize("aad", [f"{RID_B}|name", f"{RID_A}|phone"])
def test_moving_ciphertext_to_other_row_or_field_fails(aad):
    dek = crypto.new_dek()
    blob = crypto.encrypt(dek, f"{RID_A}|name", "홍길동")
    with pytest.raises(InvalidTag):
        crypto.decrypt(dek, aad, blob)


def test_tampering_detected():
    dek = crypto.new_dek()
    blob = bytearray(crypto.encrypt(dek, "a", "010-0000-0000"))
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        crypto.decrypt(dek, "a", bytes(blob))


def test_envelope_wrap_bound_to_context():
    dek = crypto.new_dek()
    wrapped, version = crypto.wrap_dek(dek, f"resume:{RID_A}")
    assert crypto.unwrap_dek(wrapped, version, f"resume:{RID_A}") == dek
    with pytest.raises(InvalidTag):
        crypto.unwrap_dek(wrapped, version, f"resume:{RID_B}")


def test_kek_rotation(monkeypatch):
    dek = crypto.new_dek()
    monkeypatch.setattr(crypto, "KEK_CURRENT", 1)
    old, v1 = crypto.wrap_dek(dek, "ctx")
    monkeypatch.setattr(crypto, "KEK_CURRENT", 2)
    new, v2 = crypto.rewrap(old, v1, "ctx")
    assert (v1, v2) == (1, 2)
    assert crypto.unwrap_dek(new, v2, "ctx") == dek
    with pytest.raises(InvalidTag):
        crypto.unwrap_dek(new, 1, "ctx")  # 다른 버전 키로는 못 품


def test_blind_index():
    n = crypto.normalize_name
    assert crypto.blind_index("name", n(" 홍 길동 ")) == crypto.blind_index("name", n("홍길동"))
    assert crypto.blind_index("name", n("John Doe")) == crypto.blind_index("name", n("john doe"))
    assert crypto.blind_index("name", "x") != crypto.blind_index("email", "x")  # 필드 간 분리
    assert crypto.blind_index("name", "x") != crypto.sha256("x".encode())  # 키 없는 해시가 아님
    assert crypto.blind_index("name", "") is None
