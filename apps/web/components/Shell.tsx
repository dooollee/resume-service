"use client";

import Link from "next/link";
import { createContext, useContext, useEffect, useState } from "react";
import { api, type Me } from "@/lib/api";

const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext);

const NAV: { href: string; label: string; roles: Me["role"][] }[] = [
  { href: "/search", label: "검색", roles: ["admin", "recruiter", "viewer"] },
  { href: "/upload", label: "업로드", roles: ["admin", "recruiter"] },
  { href: "/admin/users", label: "사용자", roles: ["admin"] },
  { href: "/admin/audit", label: "감사 로그", roles: ["admin"] },
  { href: "/admin/retention", label: "보존·파기", roles: ["admin"] },
];

// 로그인 이후 모든 화면의 공통 틀: 세션 확인, 역할별 메뉴, 화면 캡처 억제용 워터마크.
export default function Shell({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    api<Me>("/auth/me")
      .then((m) => (m.mfa_ok && !m.must_change_password ? setMe(m) : window.location.assign("/login")))
      .catch(() => window.location.assign("/login"));
  }, []);

  if (!me) return <p className="p-8 text-slate-500">확인 중…</p>;

  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => {});
    window.location.assign("/login");
  }

  return (
    <MeContext.Provider value={me}>
      <header className="border-b bg-white">
        <nav className="mx-auto flex max-w-6xl items-center gap-4 p-3 text-sm">
          <span className="font-semibold">이력서 검색</span>
          {NAV.filter((n) => n.roles.includes(me.role)).map((n) => (
            <Link key={n.href} href={n.href} className="text-slate-700 hover:underline">
              {n.label}
            </Link>
          ))}
          <span className="ml-auto text-slate-500">{me.role}</span>
          <button onClick={logout} className="rounded border px-2 py-1">
            로그아웃
          </button>
        </nav>
      </header>
      <main className="mx-auto max-w-6xl p-4">{children}</main>
      <Watermark id={me.id} />
    </MeContext.Provider>
  );
}

function Watermark({ id }: { id: string }) {
  const text = `${id.slice(0, 8)} · ${new Date().toISOString().slice(0, 16).replace("T", " ")}`;
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-50 flex flex-wrap content-start gap-24 overflow-hidden p-8 opacity-[0.07] select-none">
      {Array.from({ length: 60 }, (_, i) => (
        <span key={i} className="-rotate-30 text-lg whitespace-nowrap">
          {text}
        </span>
      ))}
    </div>
  );
}

export function StepUp({ onDone }: { onDone: () => void }) {
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      await api("/auth/step-up", { json: { password: f.get("password"), code: f.get("code") } });
      onDone();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <form onSubmit={submit} className="max-w-sm space-y-2 rounded border bg-white p-4">
      <p className="text-sm text-slate-600">관리자 기능은 재인증이 필요합니다 (10분 유효).</p>
      <input name="password" type="password" required autoComplete="current-password" placeholder="비밀번호" className="w-full rounded border p-2" />
      <input name="code" inputMode="numeric" pattern="\d{6}" required autoComplete="one-time-code" placeholder="OTP 6자리" className="w-full rounded border p-2" />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <button className="rounded bg-slate-900 px-3 py-2 text-white">재인증</button>
    </form>
  );
}

// 관리자 화면 공통: step-up이 필요하면 재인증 폼을 보여주고, 끝나면 다시 불러온다.
export function useAdminLoad<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [needStepUp, setNeedStepUp] = useState(false);
  const [error, setError] = useState("");
  const reload = () =>
    load()
      .then((d) => {
        setData(d);
        setNeedStepUp(false);
      })
      .catch((e) => (e.status === 403 && /step-up/i.test(e.message) ? setNeedStepUp(true) : setError(e.message)));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void reload(), deps);
  return { data, needStepUp, error, reload };
}
