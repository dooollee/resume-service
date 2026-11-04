// 모든 API 호출은 같은 오리진의 /api 로만 간다(BFF). 개인정보는 localStorage/sessionStorage/URL에 두지 않는다.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)__Host-csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export async function api<T = unknown>(path: string, init: { method?: string; json?: unknown; form?: FormData } = {}): Promise<T> {
  const headers: Record<string, string> = { "x-csrf-token": csrfToken() };
  let body: BodyInit | undefined;
  if (init.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.json);
  } else if (init.form) {
    body = init.form;
  }
  const res = await fetch(`/api${path}`, {
    method: init.method ?? (body ? "POST" : "GET"),
    headers,
    body,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.location.assign("/login");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = typeof data.detail === "string" ? data.detail : "입력값을 확인하세요";
    } catch {}
    throw new ApiError(res.status, detail);
  }
  const type = res.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? res.json() : res.blob()) as Promise<T>;
}

export type Me = {
  id: string;
  role: "admin" | "recruiter" | "viewer";
  mfa_ok: boolean;
  mfa_enabled: boolean;
  must_change_password: boolean;
  stepup_valid: boolean;
};
