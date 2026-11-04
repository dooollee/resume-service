"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { api } from "@/lib/api";
import { IDENTITY_LABELS, type ResumeData, type Row, saveBlob, SECTIONS } from "@/lib/resume";

type Review = { id: string; status: string; warnings: string[]; has_photo: boolean; data: ResumeData };

export default function ReviewPage() {
  return (
    <Shell>
      <ReviewForm />
    </Shell>
  );
}

function ReviewForm() {
  const { id } = useParams<{ id: string }>();
  const [review, setReview] = useState<Review | null>(null);
  const [data, setData] = useState<ResumeData | null>(null);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    api<Review>(`/resumes/${id}/review`)
      .then((r) => (setReview(r), setData(r.data)))
      .catch((e) => setMsg(e.message));
  }, [id]);

  if (!data || !review) return <p>{msg || "불러오는 중…"}</p>;

  const setIdentity = (k: string, v: string) => setData({ ...data, identity: { ...data.identity, [k]: v || null } });
  const setCell = (sec: keyof ResumeData, i: number, k: string, v: string) => {
    const rows = [...(data[sec] as Row[])];
    rows[i] = { ...rows[i], [k]: k === "years" ? (v === "" ? null : Number(v)) : v || null };
    setData({ ...data, [sec]: rows });
  };
  const addRow = (sec: keyof ResumeData) => setData({ ...data, [sec]: [...(data[sec] as Row[]), sec === "skills" ? { name: "" } : {}] });
  const delRow = (sec: keyof ResumeData, i: number) => setData({ ...data, [sec]: (data[sec] as Row[]).filter((_, j) => j !== i) });

  async function save(confirm: boolean) {
    setMsg("");
    try {
      const r = await api<{ status: string; changed: string[] }>(`/resumes/${id}`, { method: "PUT", json: { ...data, confirm } });
      setReview({ ...review!, status: r.status });
      setMsg(confirm ? "확정했습니다. 이제 검색에 포함됩니다." : `저장했습니다 (변경: ${r.changed.join(", ") || "없음"})`);
    } catch (e) {
      setMsg((e as Error).message);
    }
  }

  async function downloadSource() {
    const reason = window.prompt("원본 열람 사유 (감사 로그에 기록됩니다. 개인정보는 입력하지 마세요)");
    if (!reason) return;
    try {
      const blob = await api<Blob>(`/resumes/${id}/source`, { json: { reason } });
      saveBlob(blob, `${id}${blob.type.includes("pdf") ? ".pdf" : ".docx"}`);
    } catch (e) {
      setMsg((e as Error).message);
    }
  }

  const cell = "w-full rounded border p-1 text-sm";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">추출 결과 검수</h1>
        <span className="rounded bg-slate-200 px-2 py-0.5 text-sm">{review.status}</span>
        {review.status === "REVIEW" && (
          <button onClick={downloadSource} className="rounded border px-3 py-1 text-sm">
            원본 내려받아 대조
          </button>
        )}
      </div>
      {review.warnings.includes("rrn_removed") && (
        <p className="rounded bg-amber-50 p-2 text-sm text-amber-800">원본에서 주민등록번호가 감지되어 저장하지 않고 폐기했습니다.</p>
      )}

      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 font-semibold">인적사항</h2>
        <div className="grid gap-2 md:grid-cols-3">
          {IDENTITY_LABELS.map(([k, label]) => (
            <label key={k} className="text-sm">
              {label}
              <input value={data.identity[k] ?? ""} onChange={(e) => setIdentity(k, e.target.value)} className={cell} />
            </label>
          ))}
        </div>
      </section>

      {SECTIONS.map((s) => (
        <section key={s.key} className="rounded border bg-white p-4">
          <h2 className="mb-2 font-semibold">{s.label}</h2>
          <table className="w-full">
            <thead>
              <tr>
                {s.cols.map(([, label]) => (
                  <th key={label} className="text-left text-xs font-normal text-slate-500">
                    {label}
                  </th>
                ))}
                <th />
              </tr>
            </thead>
            <tbody>
              {(data[s.key] as Row[]).map((row, i) => (
                <tr key={i}>
                  {s.cols.map(([k]) => (
                    <td key={k} className="p-0.5">
                      <input value={row[k] ?? ""} onChange={(e) => setCell(s.key, i, k, e.target.value)} className={cell} />
                    </td>
                  ))}
                  <td>
                    <button onClick={() => delRow(s.key, i)} className="px-2 text-red-600" aria-label="행 삭제">
                      ×
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button onClick={() => addRow(s.key)} className="mt-2 text-sm underline">
            + 행 추가
          </button>
        </section>
      ))}

      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 font-semibold">자기소개</h2>
        <textarea value={data.intro ?? ""} onChange={(e) => setData({ ...data, intro: e.target.value || null })} rows={6} className={cell} />
      </section>

      <div className="flex items-center gap-2">
        <button onClick={() => save(false)} className="rounded border px-4 py-2">
          저장
        </button>
        {review.status === "REVIEW" && (
          <button onClick={() => save(true)} className="rounded bg-slate-900 px-4 py-2 text-white">
            확정 (검색에 포함)
          </button>
        )}
        {msg && <span className="text-sm">{msg}</span>}
      </div>
    </div>
  );
}
