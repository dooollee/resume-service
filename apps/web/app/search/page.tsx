"use client";

import Link from "next/link";
import { useState } from "react";
import Shell, { useMe } from "@/components/Shell";
import { api } from "@/lib/api";

type Item = {
  id: string;
  identity?: { name: string | null; phone: string | null; email: string | null };
  skills: { name: string; level: string | null; years: number | null }[];
  career: { company: string | null; title: string | null; start_ym: string | null; end_ym: string | null }[];
  education: { school: string | null; major: string | null; degree: string | null }[];
};
type Result = { total: number; page: number; size: number; items: Item[] };

export default function SearchPage() {
  return (
    <Shell>
      <Search />
    </Shell>
  );
}

function Search() {
  const me = useMe();
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState("");
  const [mode, setMode] = useState<"and" | "or">("and");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [lastQuery, setLastQuery] = useState<Record<string, unknown>>({});
  const viewer = me?.role === "viewer";

  function addTag() {
    const t = tagInput.trim();
    if (t && !tags.includes(t) && tags.length < 10) setTags([...tags, t]);
    setTagInput("");
  }

  async function run(query: Record<string, unknown>, page = 1) {
    setError("");
    try {
      // 검색어(신원 정보 포함)는 POST 본문으로만 전송 — URL·브라우저 기록에 남지 않음
      setResult(await api<Result>("/resumes/search", { json: { ...query, page } }));
      setLastQuery(query);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const q: Record<string, unknown> = { skills: tags, skill_mode: mode };
    for (const k of ["company", "title", "school", "major", "name", "phone", "email"]) {
      const v = String(f.get(k) ?? "").trim();
      if (v) q[k] = v;
    }
    const years = String(f.get("min_years") ?? "");
    if (years) q.min_years = Number(years);
    run(q);
  }

  const input = "w-full rounded border p-2 text-sm";

  return (
    <div className="grid gap-6 md:grid-cols-[320px_1fr]">
      <form onSubmit={submit} className="space-y-3 rounded border bg-white p-4" autoComplete="off">
        <h1 className="text-lg font-semibold">검색</h1>
        <div>
          <label className="text-sm font-medium">기술 스택</label>
          <div className="mt-1 flex flex-wrap gap-1">
            {tags.map((t) => (
              <button type="button" key={t} onClick={() => setTags(tags.filter((x) => x !== t))} className="rounded bg-slate-900 px-2 py-0.5 text-xs text-white">
                {t} ×
              </button>
            ))}
          </div>
          <input
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addTag())}
            placeholder="예: React (Enter로 추가)"
            className={`${input} mt-1`}
          />
          <div className="mt-1 flex gap-3 text-sm">
            <label>
              <input type="radio" checked={mode === "and"} onChange={() => setMode("and")} /> 모두 포함(AND)
            </label>
            <label>
              <input type="radio" checked={mode === "or"} onChange={() => setMode("or")} /> 하나 이상(OR)
            </label>
          </div>
          <input name="min_years" type="number" min={0} max={60} step={0.5} placeholder="최소 경력(년)" className={`${input} mt-1`} />
        </div>
        <fieldset className="space-y-1">
          <legend className="text-sm font-medium">경력·학력</legend>
          {!viewer && <input name="company" placeholder="회사" className={input} />}
          <input name="title" placeholder="직무" className={input} />
          {!viewer && <input name="school" placeholder="학교" className={input} />}
          <input name="major" placeholder="전공" className={input} />
        </fieldset>
        {!viewer && (
          <fieldset className="space-y-1">
            <legend className="text-sm font-medium">신원 (정확히 일치하는 경우만)</legend>
            <input name="name" placeholder="이름" className={input} />
            <input name="phone" placeholder="휴대폰" className={input} />
            <input name="email" type="email" placeholder="이메일" className={input} />
          </fieldset>
        )}
        {error && <p className="text-sm text-red-600">{error}</p>}
        <button className="w-full rounded bg-slate-900 p-2 text-white">검색</button>
      </form>

      <section className="space-y-3">
        {result && <p className="text-sm text-slate-600">총 {result.total}건</p>}
        {result?.items.map((it) => (
          <Link key={it.id} href={`/resumes/${it.id}`} className="block rounded border bg-white p-4 hover:border-slate-400">
            {it.identity && (
              <p className="font-medium">
                {it.identity.name ?? "(이름 없음)"} <span className="text-sm font-normal text-slate-500">{it.identity.phone} · {it.identity.email}</span>
              </p>
            )}
            <p className="mt-1 text-sm">
              {it.career.map((c) => [c.company, c.title].filter(Boolean).join(" ")).join(" / ") || "경력 없음"}
            </p>
            <p className="text-sm text-slate-600">{it.education.map((e) => [e.school, e.major, e.degree].filter(Boolean).join(" ")).join(" / ")}</p>
            <div className="mt-2 flex flex-wrap gap-1">
              {it.skills.map((s) => (
                <span key={s.name} className="rounded bg-slate-100 px-2 py-0.5 text-xs">
                  {s.name}
                  {s.years != null && ` ${s.years}년`}
                  {s.level && ` · ${s.level}`}
                </span>
              ))}
            </div>
          </Link>
        ))}
        {result && result.total > result.page * result.size && (
          <button onClick={() => run(lastQuery, result.page + 1)} className="rounded border px-3 py-1">
            다음 페이지
          </button>
        )}
      </section>
    </div>
  );
}
