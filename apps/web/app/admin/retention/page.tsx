"use client";

import Link from "next/link";
import Shell, { StepUp, useAdminLoad } from "@/components/Shell";
import { api } from "@/lib/api";

type Status = {
  active: number;
  pending_deletion: number;
  expiring_30d: number;
  purged_30d: number;
  grace_days: number;
  pending: { id: string; deleted_at: string; purge_after: string }[];
  expiring: { id: string; retention_until: string }[];
};

export default function RetentionPage() {
  return (
    <Shell>
      <Retention />
    </Shell>
  );
}

const day = (s: string) => s.slice(0, 10);

function Retention() {
  const { data, needStepUp, error, reload } = useAdminLoad(() => api<Status>("/admin/retention"));
  if (needStepUp) return <StepUp onDone={reload} />;
  if (error) return <p className="text-red-600">{error}</p>;
  if (!data) return null;
  const stats: [string, number][] = [
    ["보유 중", data.active],
    ["삭제 대기", data.pending_deletion],
    ["30일 내 보존기간 만료", data.expiring_30d],
    ["최근 30일 파기", data.purged_30d],
  ];
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">보존·파기 현황</h1>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {stats.map(([label, n]) => (
          <div key={label} className="rounded border bg-white p-4">
            <p className="text-sm text-slate-500">{label}</p>
            <p className="text-2xl font-semibold">{n}</p>
          </div>
        ))}
      </div>
      <p className="text-sm text-slate-600">
        삭제 요청된 이력서는 즉시 비활성화되고 {data.grace_days}일 후 자동 파기됩니다. 보존기간이 끝난 이력서는 즉시 파기되며, 레코드별 암호화 키도 함께 삭제됩니다(crypto-shredding).
      </p>
      <section className="grid gap-4 md:grid-cols-2">
        <div className="rounded border bg-white p-4 text-sm">
          <h2 className="mb-2 font-semibold">삭제 대기</h2>
          {data.pending.map((p) => (
            <p key={p.id} className="font-mono">
              {p.id.slice(0, 8)} · 요청 {day(p.deleted_at)} → 파기 {day(p.purge_after)}
            </p>
          ))}
        </div>
        <div className="rounded border bg-white p-4 text-sm">
          <h2 className="mb-2 font-semibold">만료 예정</h2>
          {data.expiring.map((e) => (
            <p key={e.id} className="font-mono">
              <Link href={`/resumes/${e.id}`} className="underline">
                {e.id.slice(0, 8)}
              </Link>{" "}
              · {day(e.retention_until)}
            </p>
          ))}
        </div>
      </section>
    </div>
  );
}
