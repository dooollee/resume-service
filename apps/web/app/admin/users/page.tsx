"use client";

import { useState } from "react";
import Shell, { StepUp, useAdminLoad } from "@/components/Shell";
import { api } from "@/lib/api";

type U = { id: string; email: string; role: string; mfa_enabled: boolean; disabled: boolean; locked: boolean; last_login_at: string | null };

export default function UsersPage() {
  return (
    <Shell>
      <Users />
    </Shell>
  );
}

function Users() {
  const { data, needStepUp, error, reload } = useAdminLoad(() => api<U[]>("/admin/users"));
  const [msg, setMsg] = useState("");

  async function act(fn: () => Promise<unknown>, ok: string) {
    setMsg("");
    try {
      await fn();
      setMsg(ok);
      reload();
    } catch (e) {
      setMsg((e as Error).message);
    }
  }

  function create(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const form = e.currentTarget;
    act(() => api("/admin/users", { json: { email: f.get("email"), role: f.get("role"), password: f.get("password") } }), "생성했습니다").then(() => form.reset());
  }
  const patch = (id: string, body: object, ok: string) => act(() => api(`/admin/users/${id}`, { method: "PATCH", json: body }), ok);

  if (needStepUp) return <StepUp onDone={reload} />;
  if (error) return <p className="text-red-600">{error}</p>;
  if (!data) return null;

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">사용자 관리</h1>
      <form onSubmit={create} className="flex flex-wrap gap-2 rounded border bg-white p-3">
        <input name="email" type="email" required placeholder="이메일" className="rounded border p-2" />
        <select name="role" className="rounded border p-2">
          <option value="viewer">viewer</option>
          <option value="recruiter">recruiter</option>
          <option value="admin">admin</option>
        </select>
        <input name="password" type="password" required minLength={12} autoComplete="new-password" placeholder="초기 비밀번호(첫 로그인 시 변경 강제)" className="w-72 rounded border p-2" />
        <button className="rounded bg-slate-900 px-3 text-white">추가</button>
      </form>
      {msg && <p className="text-sm">{msg}</p>}
      <table className="w-full bg-white text-sm">
        <thead>
          <tr className="border-b text-left">
            <th className="p-2">이메일</th>
            <th>역할</th>
            <th>MFA</th>
            <th>상태</th>
            <th>최근 로그인</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data.map((u) => (
            <tr key={u.id} className="border-b">
              <td className="p-2">{u.email}</td>
              <td>
                <select defaultValue={u.role} onChange={(e) => patch(u.id, { role: e.target.value }, "역할을 변경했습니다")} className="rounded border p-1">
                  <option>viewer</option>
                  <option>recruiter</option>
                  <option>admin</option>
                </select>
              </td>
              <td>{u.mfa_enabled ? "등록" : "미등록"}</td>
              <td>{u.disabled ? "비활성" : u.locked ? "잠김" : "활성"}</td>
              <td>{u.last_login_at?.slice(0, 16).replace("T", " ") ?? "-"}</td>
              <td className="space-x-2 text-right whitespace-nowrap">
                {u.locked && <button onClick={() => patch(u.id, { unlock: true }, "잠금 해제")} className="underline">잠금 해제</button>}
                <button onClick={() => patch(u.id, { reset_mfa: true }, "MFA 초기화")} className="underline">MFA 초기화</button>
                <button onClick={() => patch(u.id, { disabled: !u.disabled }, u.disabled ? "활성화" : "비활성화")} className="underline">
                  {u.disabled ? "활성화" : "비활성화"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
