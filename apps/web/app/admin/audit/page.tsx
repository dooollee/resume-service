"use client";

import { useState } from "react";
import Shell, { StepUp, useAdminLoad } from "@/components/Shell";
import { api } from "@/lib/api";

type Log = { id: number; ts: string; actor_id: string | null; action: string; resource_type: string | null; resource_id: string | null; ip: string | null; reason: string | null };

export default function AuditPage() {
  return (
    <Shell>
      <Audit />
    </Shell>
  );
}

function Audit() {
  const [action, setAction] = useState("");
  const [page, setPage] = useState(1);
  const [verify, setVerify] = useState<string>("");
  const query = () => api<Log[]>(`/audit-logs?page=${page}${action ? `&action=${encodeURIComponent(action)}` : ""}`);
  const { data, needStepUp, error, reload } = useAdminLoad(query, [page]);

  async function check() {
    const r = await api<{ ok: boolean; broken_id: number | null }>("/audit-logs/verify");
    setVerify(r.ok ? "✅ 해시 체인 정상" : `❌ 변조 감지: 레코드 #${r.broken_id}`);
  }

  if (needStepUp) return <StepUp onDone={reload} />;
  if (error) return <p className="text-red-600">{error}</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">감사 로그</h1>
      <div className="flex flex-wrap gap-2">
        <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="행위 접두사 (예: alert., resume.reveal)" className="w-72 rounded border p-2" />
        <button onClick={() => (page === 1 ? reload() : setPage(1))} className="rounded border px-3">조회</button>
        <button onClick={() => setAction("alert.")} className="rounded border px-3">이상 징후만</button>
        <button onClick={check} className="rounded border px-3">무결성 검증</button>
        {verify && <span className="self-center">{verify}</span>}
      </div>
      <table className="w-full bg-white text-xs">
        <thead>
          <tr className="border-b text-left">
            <th className="p-2">#</th>
            <th>시각</th>
            <th>행위자</th>
            <th>행위</th>
            <th>대상</th>
            <th>IP</th>
            <th>사유</th>
          </tr>
        </thead>
        <tbody>
          {data?.map((l) => (
            <tr key={l.id} className={`border-b ${l.action.startsWith("alert.") ? "bg-red-50" : ""}`}>
              <td className="p-2">{l.id}</td>
              <td>{l.ts.slice(0, 19).replace("T", " ")}</td>
              <td className="font-mono">{l.actor_id?.slice(0, 8) ?? "-"}</td>
              <td>{l.action}</td>
              <td className="font-mono">{l.resource_id?.slice(0, 8) ?? ""}</td>
              <td>{l.ip}</td>
              <td>{l.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex gap-2">
        <button disabled={page === 1} onClick={() => setPage(page - 1)} className="rounded border px-3 disabled:opacity-40">이전</button>
        <button onClick={() => setPage(page + 1)} className="rounded border px-3">다음</button>
      </div>
    </div>
  );
}
