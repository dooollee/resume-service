export type Identity = { name?: string | null; phone?: string | null; email?: string | null; birth?: string | null; gender?: string | null; address?: string | null };
export type Row = Record<string, string | number | null | undefined>;
export type ResumeData = { identity: Identity; intro?: string | null; education: Row[]; career: Row[]; skills: Row[]; certs: Row[] };

export const SECTIONS: { key: "education" | "career" | "skills" | "certs"; label: string; cols: [string, string][] }[] = [
  { key: "education", label: "학력", cols: [["school", "학교"], ["major", "전공"], ["degree", "학위"], ["start_ym", "입학(YYYY-MM)"], ["end_ym", "졸업(YYYY-MM)"]] },
  { key: "career", label: "경력", cols: [["company", "회사"], ["title", "직무"], ["start_ym", "시작"], ["end_ym", "종료"], ["description", "담당업무"]] },
  { key: "skills", label: "기술", cols: [["name", "기술"], ["level", "숙련도(초급/중급/고급/전문가)"], ["years", "연수"]] },
  { key: "certs", label: "자격", cols: [["name", "자격증"], ["issuer", "발급기관"], ["acquired_ym", "취득(YYYY-MM)"]] },
];

export const IDENTITY_LABELS: [keyof Identity, string][] = [
  ["name", "이름"],
  ["birth", "생년월일(YYYY-MM-DD)"],
  ["gender", "성별(남/여/기타)"],
  ["phone", "휴대폰"],
  ["email", "이메일"],
  ["address", "주소"],
];

// 다운로드 파일을 브라우저 메모리에서 바로 저장(서버 URL·저장소에 남기지 않음)
export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
