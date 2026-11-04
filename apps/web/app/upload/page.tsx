"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";

const CONSENT_VERSION = "2026-11-v1";
const ITEMS = ["신원", "연락처", "사진", "학력", "경력", "기술", "자격", "자기소개"];
const MAX_BYTES = 10 * 1024 * 1024;
const STATUS_LABEL: Record<string, string> = {
  UPLOADED: "대기 중",
  SCANNING: "악성코드 검사 중",
  EXTRACTING: "정보 추출 중",
  REVIEW: "검수 대기",
  CONFIRMED: "확정",
  FAILED: "실패",
};

type Job = { id: string; name: string; status: string; failure_code?: string | null };

export default function UploadPage() {
  return (
    <Shell>
      <Upload />
    </Shell>
  );
}

function Upload() {
  const [file, setFile] = useState<File | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);

  // 진행 중인 작업 상태 폴링 (메모리에만 보관 — 브라우저 저장소에 남기지 않음)
  useEffect(() => {
    const pending = jobs.filter((j) => ["UPLOADED", "SCANNING", "EXTRACTING"].includes(j.status));
    if (!pending.length) return;
    const t = setTimeout(async () => {
      const updated = await Promise.all(
        jobs.map((j) => (pending.includes(j) ? api<Job>(`/resumes/${j.id}/status`).then((s) => ({ ...j, ...s })) : j)),
      );
      setJobs(updated);
    }, 2000);
    return () => clearTimeout(t);
  }, [jobs]);

  function pick(f: File | undefined) {
    setError("");
    if (!f) return;
    if (!/\.(pdf|docx)$/i.test(f.name)) return setError("PDF 또는 DOCX만 업로드할 수 있습니다");
    if (f.size > MAX_BYTES) return setError("10MB 이하 파일만 업로드할 수 있습니다");
    setFile(f);
  }

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!file) return setError("파일을 선택하세요");
    const f = new FormData(e.currentTarget);
    const items = ITEMS.filter((i) => f.get(`item_${i}`));
    const form = new FormData();
    form.set("file", file);
    form.set("consent_agreed", f.get("consent_agreed") ? "true" : "false");
    form.set("consent_version", CONSENT_VERSION);
    form.set("consent_purpose", String(f.get("purpose")));
    form.set("consent_items", items.join(","));
    form.set("retention_months", String(f.get("retention_months")));
    form.set("agreed_on", String(f.get("agreed_on")));
    try {
      const r = await api<{ id: string; status: string }>("/resumes", { form });
      setJobs([{ id: r.id, name: file.name, status: r.status }, ...jobs]);
      setFile(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <form onSubmit={submit} className="space-y-4 rounded border bg-white p-4">
        <h1 className="text-xl font-semibold">이력서 업로드</h1>
        <label
          onDragOver={(e) => (e.preventDefault(), setDragging(true))}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => (e.preventDefault(), setDragging(false), pick(e.dataTransfer.files[0]))}
          className={`block cursor-pointer rounded border-2 border-dashed p-8 text-center ${dragging ? "border-slate-900 bg-slate-50" : ""}`}
        >
          {file ? file.name : "PDF·DOCX 파일을 끌어다 놓거나 클릭 (최대 10MB)"}
          <input type="file" accept=".pdf,.docx" className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
        </label>

        <fieldset className="space-y-2 rounded border p-3 text-sm">
          <legend className="px-1 font-medium">개인정보 수집·이용 동의 (정보주체 동의 기록)</legend>
          <p className="text-slate-600">동의서 버전 {CONSENT_VERSION}. 주민등록번호 등 고유식별정보는 수집하지 않으며, 감지되면 자동 폐기됩니다.</p>
          <label className="block">
            수집 목적
            <input name="purpose" required maxLength={200} defaultValue="채용 전형 진행 및 인재풀 관리" className="w-full rounded border p-2" />
          </label>
          <div className="flex flex-wrap gap-3">
            {ITEMS.map((i) => (
              <label key={i}>
                <input type="checkbox" name={`item_${i}`} defaultChecked={i !== "사진"} /> {i}
              </label>
            ))}
          </div>
          <label className="block">
            보존기간(개월)
            <input name="retention_months" type="number" min={1} max={60} defaultValue={12} required className="w-24 rounded border p-2" />
          </label>
          <label className="block">
            동의일
            <input name="agreed_on" type="date" required max={new Date().toISOString().slice(0, 10)} className="rounded border p-2" />
          </label>
          <label className="block font-medium">
            <input type="checkbox" name="consent_agreed" required /> 정보주체가 위 내용에 동의했음을 확인합니다
          </label>
        </fieldset>

        {error && <p className="text-sm text-red-600">{error}</p>}
        <button className="rounded bg-slate-900 px-4 py-2 text-white">업로드</button>
      </form>

      <section className="space-y-2">
        <h2 className="font-semibold">처리 현황</h2>
        {jobs.length === 0 && <p className="text-sm text-slate-500">이번 화면에서 올린 파일이 여기에 표시됩니다.</p>}
        {jobs.map((j) => (
          <div key={j.id} className="flex items-center justify-between rounded border bg-white p-3 text-sm">
            <span className="truncate">{j.name}</span>
            <span className={j.status === "FAILED" ? "text-red-600" : ""}>
              {STATUS_LABEL[j.status] ?? j.status}
              {j.failure_code ? ` (${j.failure_code})` : ""}
              {j.status === "REVIEW" && (
                <Link href={`/review/${j.id}`} className="ml-2 underline">
                  검수하기
                </Link>
              )}
            </span>
          </div>
        ))}
      </section>
    </div>
  );
}
