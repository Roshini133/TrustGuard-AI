const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "";

export class ApiError extends Error {
  status: number;
  retryAfter?: number;
  constructor(message: string, status: number, retryAfter?: number) {
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

function csrfToken(): string {
  const m = document.cookie.split("; ").find((c) => c.startsWith("tg_csrf="));
  return m ? decodeURIComponent(m.split("=")[1]) : "";
}

function formatDetail(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d: { loc?: unknown[]; msg?: string }) => {
        const field = Array.isArray(d.loc) ? String(d.loc[d.loc.length - 1]) : "";
        const msg = (d.msg ?? "Invalid value").replace(/^Value error, /, "");
        return field && field !== "body" ? `${field.replace(/_/g, " ")}: ${msg}` : msg;
      })
      .join(" ");
  }
  return fallback;
}

let refreshing: Promise<boolean> | null = null;
async function tryRefresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = fetch(`${BASE}/api/auth/refresh`, {
      method: "POST", credentials: "include", headers: { "X-CSRF-Token": csrfToken() },
    }).then((r) => r.ok).catch(() => false).finally(() => { setTimeout(() => (refreshing = null), 0); });
  }
  return refreshing;
}

export interface ReqOptions { method?: string; body?: unknown; form?: FormData; noRefresh?: boolean }

export async function api<T = any>(path: string, opts: ReqOptions = {}): Promise<T> {
  const method = opts.method ?? (opts.body || opts.form ? "POST" : "GET");
  const build = (): RequestInit => {
    const headers: Record<string, string> = {};
    let body: BodyInit | undefined;
    if (opts.form) body = opts.form;
    else if (opts.body !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.body); }
    if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
    return { method, headers, body, credentials: "include" };
  };
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, build());
    if (res.status === 401 && !opts.noRefresh && !path.startsWith("/api/auth/")) {
      if (await tryRefresh()) res = await fetch(`${BASE}${path}`, build());
    }
  } catch {
    throw new ApiError("Cannot reach the server. Check your connection and try again.", 0);
  }
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) {
    const ra = res.headers.get("Retry-After");
    throw new ApiError(formatDetail(data?.detail, `Request failed (${res.status})`), res.status, ra ? parseInt(ra, 10) : undefined);
  }
  return data as T;
}

export const downloadUrl = (path: string) => `${BASE}${path}`;
