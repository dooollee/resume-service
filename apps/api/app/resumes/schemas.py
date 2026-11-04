from typing import Literal

from pydantic import BaseModel, Field

YM = r"^\d{4}-(0[1-9]|1[0-2])$"
Level = Literal["초급", "중급", "고급", "전문가"]


class Identity(BaseModel):
    name: str | None = Field(default=None, max_length=50)
    phone: str | None = Field(default=None, max_length=20)
    email: str | None = Field(default=None, max_length=254)
    birth: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    gender: Literal["남", "여", "기타"] | None = None
    address: str | None = Field(default=None, max_length=200)


class Education(BaseModel):
    school: str | None = Field(default=None, max_length=100)
    major: str | None = Field(default=None, max_length=100)
    degree: str | None = Field(default=None, max_length=30)
    start_ym: str | None = Field(default=None, pattern=YM)
    end_ym: str | None = Field(default=None, pattern=YM)


class Career(BaseModel):
    company: str | None = Field(default=None, max_length=100)
    title: str | None = Field(default=None, max_length=100)
    start_ym: str | None = Field(default=None, pattern=YM)
    end_ym: str | None = Field(default=None, pattern=YM)
    description: str | None = Field(default=None, max_length=2000)


class Skill(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    level: Level | None = None
    years: float | None = Field(default=None, ge=0, le=60)


class Cert(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    issuer: str | None = Field(default=None, max_length=100)
    acquired_ym: str | None = Field(default=None, pattern=YM)


class ResumeData(BaseModel):
    identity: Identity = Identity()
    intro: str | None = Field(default=None, max_length=5000)
    education: list[Education] = Field(default=[], max_length=20)
    career: list[Career] = Field(default=[], max_length=30)
    skills: list[Skill] = Field(default=[], max_length=100)
    certs: list[Cert] = Field(default=[], max_length=30)
