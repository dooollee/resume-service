"use client";

import { useState } from "react";
import { api } from "@/lib/api";

type Step = "password" | "mfa_verify" | "mfa_enroll" | "recovery_codes" | "change_password";

export default function LoginPage() {
  const [step, setStep] = useState<Step>("password");
  const [error, setError] = useState("");
  const [enroll, setEnroll] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [mustChange, setMustChange] = useState(false);
  const [useRecovery, setUseRecovery] = useState(false);

  async function run(fn: () => Promise<void>) {
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const finish = (must: boolean) => (must ? setStep("change_password") : window.location.assign("/search"));

  function onPassword(f: FormData) {
    run(async () => {
      const r = await api<{ next: Step }>("/auth/login", { json: { email: f.get("email"), password: f.get("password") } });
      if (r.next === "mfa_enroll") setEnroll(await api("/auth/mfa/enroll", { method: "POST" }));
      setStep(r.next);
    });
  }

  function onMfa(f: FormData) {
    run(async () => {
      const body = useRecovery ? { recovery_code: f.get("code") } : { code: f.get("code") };
      const r = await api<{ recovery_codes: string[] | null; must_change_password: boolean }>("/auth/mfa/verify", { json: body });
      if (r.recovery_codes) {
        setCodes(r.recovery_codes);
        setMustChange(r.must_change_password);
        setStep("recovery_codes");
      } else finish(r.must_change_password);
    });
  }

  function onChangePassword(f: FormData) {
    run(async () => {
      if (f.get("new_password") !== f.get("confirm")) throw new Error("새 비밀번호가 일치하지 않습니다");
      await api("/auth/password", { json: { current_password: f.get("current_password"), new_password: f.get("new_password") } });
      window.location.assign("/search");
    });
  }

  const submit = (handler: (f: FormData) => void) => (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    handler(new FormData(e.currentTarget));
  };
  const input = "w-full rounded border p-2";
  const button = "w-full rounded bg-slate-900 p-2 text-white";

  return (
    <main className="mx-auto mt-24 max-w-sm space-y-4 rounded border bg-white p-6">
      <h1 className="text-xl font-semibold">로그인</h1>

      {step === "password" && (
        <form onSubmit={submit(onPassword)} className="space-y-3">
          <input name="email" type="email" required autoComplete="username" placeholder="이메일" className={input} />
          <input name="password" type="password" required autoComplete="current-password" placeholder="비밀번호" className={input} />
          <button className={button}>다음</button>
        </form>
      )}

      {step === "mfa_enroll" && enroll && (
        <div className="space-y-2 text-sm">
          <p>2단계 인증이 필요합니다. 인증 앱(Google Authenticator 등)에 아래 키를 직접 입력하세요.</p>
          <code className="block rounded bg-slate-100 p-2 break-all">{enroll.secret}</code>
          <details>
            <summary className="cursor-pointer text-slate-500">otpauth URI</summary>
            <code className="block break-all">{enroll.otpauth_uri}</code>
          </details>
        </div>
      )}

      {(step === "mfa_verify" || step === "mfa_enroll") && (
        <form onSubmit={submit(onMfa)} className="space-y-3">
          <input
            name="code"
            required
            autoComplete="one-time-code"
            inputMode={useRecovery ? "text" : "numeric"}
            pattern={useRecovery ? undefined : "\\d{6}"}
            placeholder={useRecovery ? "복구 코드" : "OTP 6자리"}
            className={input}
          />
          <button className={button}>확인</button>
          {step === "mfa_verify" && (
            <button type="button" onClick={() => setUseRecovery(!useRecovery)} className="text-sm text-slate-500 underline">
              {useRecovery ? "OTP 코드 사용" : "복구 코드 사용"}
            </button>
          )}
        </form>
      )}

      {step === "recovery_codes" && (
        <div className="space-y-3 text-sm">
          <p>복구 코드입니다. <b>지금 한 번만 표시</b>되며 각 코드는 1회용입니다. 안전한 곳에 보관하세요.</p>
          <ul className="grid grid-cols-2 gap-1 rounded bg-slate-100 p-2 font-mono">
            {codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <button onClick={() => finish(mustChange)} className={button}>
            보관했습니다
          </button>
        </div>
      )}

      {step === "change_password" && (
        <form onSubmit={submit(onChangePassword)} className="space-y-3">
          <p className="text-sm">초기 비밀번호를 변경해야 합니다 (12자 이상, 유출 비밀번호 불가).</p>
          <input name="current_password" type="password" required autoComplete="current-password" placeholder="현재 비밀번호" className={input} />
          <input name="new_password" type="password" required minLength={12} autoComplete="new-password" placeholder="새 비밀번호" className={input} />
          <input name="confirm" type="password" required minLength={12} autoComplete="new-password" placeholder="새 비밀번호 확인" className={input} />
          <button className={button}>변경</button>
        </form>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}
    </main>
  );
}
