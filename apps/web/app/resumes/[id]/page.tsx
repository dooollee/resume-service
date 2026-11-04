"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import Shell, { useMe } from "@/components/Shell";
import { api } from "@/lib/api";

type Detail = {
  id: string;
  identity?: { name: string | null; phone: string | null; email: string | null };
  skills: { name: string; level: string | null; years: number | null }[];
  career: { company: string | null; title: string | null; start_ym: string | null; end_ym: string | null }[];
  education: { school: string | null; major: string | null; degree: string | null }[];
  certs: { name: string | null; issuer: string | null; acquired_ym: string | null }[];
  has_photo: boolean;
  can_reveal: boolean;
};
type Revealed = {
  expires_at: string;
  identity: Record<string, string | null>;
  intro: string | null;
  career_descriptions: (string | null)[];
};

export default function DetailPage() {
  return (
    <Shell>
      <ResumeDetail />
    </Shell>
  );
}

function ResumeDetail() {
  const { id } = useParams<{ id: string }>();
  const me = useMe();
  const [d, setD] = useState<Detail | null>(null);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [left, setLeft] = useState(0);
  const [modal, setModal] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Detail>(`/resumes/${id}`).then(setD).catch((e) => setError(e.message));
  }, [id]);

  // 원문은 허가 만료 시각까지만 메모리에 두고, 만료되면 즉시 지운다.
  useEffect(() => {
    if (!revealed) return;
    const tick = () => {
      const s = Math.max(0, Math.round((new Date(revealed.expires_at).getTime() - Date.now()) / 1000));
      setLeft(s);
      if (s === 0) setRevealed(null);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [revealed]);

  async function reveal(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const reason = String(new FormData(e.currentTarget).get("reason"));
    try {
      setRevealed(await api<Revealed>(`/resumes/${id}/reveal`, { json: { reason } }));
      setModal(false);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (!d) return <p>{error || "불러오는 중…"}</p>;
  const ident = revealed?.identity ?? d.identity;

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-4 rounded border bg-white p-4">
        {d.has_photo && (
          <div className="flex h-32 w-24 items-center justify-center overflow-hidden rounded bg-slate-100 text-xs text-slate-400">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            {revealed ? <img src={`/api/resumes/${id}/photo`} alt="증명사진" className="h-full w-full object-cover" /> : "사진 숨김"}
          </div>
        )}
        <div className="flex-1 space-y-1">
          {ident ? (
            <>
              <p className="text-lg font-semibold">{ident.name ?? "(이름 없음)"}</p>
              <p className="text-sm">
                {ident.phone} · {ident.email}
              </p>
              {revealed && (
                <p className="text-sm">
                  {revealed.identity.birth} · {revealed.identity.gender} · {revealed.identity.address}
                </p>
              )}
            </>
          ) : (
            <p className="text-slate-500">신원 정보는 표시되지 않습니다 (viewer)</p>
          )}
        </div>
        {d.can_reveal && me?.role !== "viewer" && (
          revealed ? (
            <span className="rounded bg-amber-100 px-2 py-1 text-sm">원문 표시 중 · {left}초 후 다시 가려짐</span>
          ) : (
            <button onClick={() => setModal(true)} className="rounded bg-slate-900 px-3 py-2 text-sm text-white">
              원문 보기
            </button>
          )
        )}
      </div>

      <section className="rounded border bg-white p-4">
        <h2 className="font-semibold">경력</h2>
        {d.career.map((c, i) => (
          <div key={i} className="mt-2 text-sm">
            <p>
              {[c.company, c.title].filter(Boolean).join(" · ")} ({c.start_ym} ~ {c.end_ym ?? "재직 중"})
            </p>
            {revealed?.career_descriptions[i] && <p className="text-slate-600">{revealed.career_descriptions[i]}</p>}
          </div>
        ))}
      </section>
      <section className="rounded border bg-white p-4 text-sm">
        <h2 className="font-semibold">학력</h2>
        {d.education.map((e, i) => (
          <p key={i}>{[e.school, e.major, e.degree].filter(Boolean).join(" · ")}</p>
        ))}
        <h2 className="mt-3 font-semibold">기술</h2>
        <p>{d.skills.map((s) => `${s.name}${s.years != null ? ` ${s.years}년` : ""}${s.level ? `(${s.level})` : ""}`).join(", ")}</p>
        <h2 className="mt-3 font-semibold">자격</h2>
        {d.certs.map((c, i) => (
          <p key={i}>
            {c.name} · {c.issuer} · {c.acquired_ym}
          </p>
        ))}
      </section>
      {revealed?.intro && (
        <section className="rounded border bg-white p-4 text-sm whitespace-pre-wrap">
          <h2 className="font-semibold">자기소개</h2>
          {revealed.intro}
        </section>
      )}

      {modal && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40" role="dialog" aria-modal="true">
          <form onSubmit={reveal} className="w-full max-w-md space-y-3 rounded bg-white p-5">
            <h2 className="font-semibold">원문 열람 사유</h2>
            <p className="text-sm text-slate-600">열람 사유와 시각·IP가 감사 로그에 기록되며, 원문은 5분 동안만 표시됩니다. 사유에 개인정보를 적지 마세요.</p>
            <textarea name="reason" required minLength={5} maxLength={300} rows={3} className="w-full rounded border p-2" placeholder="예: 1차 면접 일정 안내 연락" />
            {error && <p className="text-sm text-red-600">{error}</p>}
            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setModal(false)} className="rounded border px-3 py-1">
                취소
              </button>
              <button className="rounded bg-slate-900 px-3 py-1 text-white">열람</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
