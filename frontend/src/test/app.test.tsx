import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { AuthProvider } from "../lib/auth";
import { api, ApiError } from "../lib/api";
import { ForgotPassword, Login, PENDING_KEY, Register, ResetPassword, VerifyEmail } from "../pages/Auth";
import Dashboard from "../pages/Dashboard";

type Handler = (url: string, init?: RequestInit) => { status?: number; body?: unknown };
let calls: { url: string; init?: RequestInit }[] = [];

function mockFetch(handler: Handler) {
  calls = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const r = handler(url, init);
    const status = r.status ?? 200;
    return new Response(r.body === undefined ? "" : JSON.stringify(r.body), { status, headers: { "Content-Type": "application/json" } });
  }));
}

const DASH = {
  stats: { total_datasets: 3, records_processed: 1200, suspicious_records: 40, quarantined_records: 12, awaiting_review: 1, data_quality_issues: 5, models_trained: 2, active_experiments: 0 },
  charts: { trust_distribution: [], trusted_vs_suspicious: [], detection_methods: [], model_before_after: [], experiment_outcomes: [], quality_issues_over_time: [] },
  recent_alerts: [], recent_security_events: [],
};

const USER = { id: "1", email: "a@b.com", full_name: "Ada Admin", role: "analyst", permissions: ["dataset:read", "dataset:write"], is_verified: true };

function renderAt(path: string, ui?: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><MemoryRouter initialEntries={[path]}><AuthProvider>
      {ui ?? <App />}
      <Routes><Route path="/__probe" element={null} /></Routes>
    </AuthProvider></MemoryRouter></QueryClientProvider>,
  );
}

beforeEach(() => { sessionStorage.clear(); localStorage.clear(); });
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("authentication redirects & protected routes", () => {
  it("redirects unauthenticated users to the login page", async () => {
    mockFetch((u) => (u.includes("/auth/me") ? { status: 401, body: { detail: "Not authenticated" } } : { body: {} }));
    renderAt("/datasets");
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
  });

  it("blocks non-admins from admin pages", async () => {
    mockFetch((u) => (u.includes("/auth/me") ? { body: { user: USER } } : { body: { items: [], unread: 0 } }));
    renderAt("/users");
    expect(await screen.findByRole("heading", { name: /access denied/i })).toBeInTheDocument();
  });

  it("shows the app shell for an authenticated user", async () => {
    mockFetch((u) => (u.includes("/auth/me") ? { body: { user: USER } } : { body: { items: [], unread: 0, total: 0, page: 1, page_size: 20 } }));
    renderAt("/datasets");
    expect(await screen.findByRole("heading", { name: "Datasets" })).toBeInTheDocument();
    expect(screen.getByText("Ada Admin")).toBeInTheDocument();
    expect(await screen.findByText(/no datasets found/i)).toBeInTheDocument();
  });
});

describe("registration", () => {
  it("validates fields on the client before calling the API", async () => {
    mockFetch((u) => (u.includes("/auth/me") ? { status: 401, body: {} } : { body: {} }));
    renderAt("/register");
    const u = userEvent.setup();
    await u.type(screen.getByLabelText(/full name/i), "A");
    await u.type(screen.getByLabelText(/email address/i), "bad-email");
    await u.click(screen.getByRole("button", { name: /create account/i }));
    expect(await screen.findByText(/enter your full name/i)).toBeInTheDocument();
    expect(screen.getByText(/enter a valid email/i)).toBeInTheDocument();
    expect(screen.getByText(/does not meet all requirements/i)).toBeInTheDocument();
    expect(screen.getByText(/you must accept/i)).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes("/auth/register"))).toBe(false);
  });

  it("flags mismatched passwords", async () => {
    mockFetch(() => ({ body: {} }));
    renderAt("/register", <Register />);
    const u = userEvent.setup();
    const pw = screen.getAllByLabelText(/password/i).filter((e) => e.tagName === "INPUT");
    await u.type(pw[0], "Str0ng!Passw0rd"); await u.type(pw[1], "Different!Pass1");
    await u.click(screen.getByRole("button", { name: /create account/i }));
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
  });

  it("submits to the backend and stores only email + timing (never an OTP)", async () => {
    mockFetch((u) => (u.includes("/auth/register") ? { status: 202, body: { otp_expires_in: 300, resend_cooldown: 60 } } : { status: 401, body: {} }));
    renderAt("/register");
    const u = userEvent.setup();
    await u.type(screen.getByLabelText(/full name/i), "Ada Lovelace");
    await u.type(screen.getByLabelText(/email address/i), "Ada@Example.com");
    const pw = screen.getAllByLabelText(/password/i).filter((e) => e.tagName === "INPUT");
    await u.type(pw[0], "Str0ng!Passw0rd"); await u.type(pw[1], "Str0ng!Passw0rd");
    await u.click(screen.getByRole("checkbox"));
    await u.click(screen.getByRole("button", { name: /create account/i }));
    expect(await screen.findByRole("heading", { name: /verify your email/i })).toBeInTheDocument();
    const pending = JSON.parse(sessionStorage.getItem(PENDING_KEY)!);
    expect(pending.email).toBe("ada@example.com");
    expect(Object.keys(pending).sort()).toEqual(["email", "expiresAt", "resendAt"]);
    expect(localStorage.length).toBe(0);
    const body = JSON.parse(calls.find((c) => c.url.includes("/auth/register"))!.init!.body as string);
    expect(body.accept_terms).toBe(true);
  });

  it("shows server-side errors without crashing", async () => {
    mockFetch((u) => (u.includes("/auth/register") ? { status: 502, body: { detail: "We could not send the verification email. Please try again shortly." } } : { status: 401, body: {} }));
    renderAt("/register");
    const u = userEvent.setup();
    await u.type(screen.getByLabelText(/full name/i), "Ada Lovelace");
    await u.type(screen.getByLabelText(/email address/i), "ada@example.com");
    const pw = screen.getAllByLabelText(/password/i).filter((e) => e.tagName === "INPUT");
    await u.type(pw[0], "Str0ng!Passw0rd"); await u.type(pw[1], "Str0ng!Passw0rd");
    await u.click(screen.getByRole("checkbox"));
    await u.click(screen.getByRole("button", { name: /create account/i }));
    expect(await screen.findByText(/could not send the verification email/i)).toBeInTheDocument();
    expect(sessionStorage.getItem(PENDING_KEY)).toBeNull();
  });
});

describe("OTP verification", () => {
  const seed = (expiresIn = 300, resendIn = 60) => sessionStorage.setItem(PENDING_KEY, JSON.stringify({ email: "ada@example.com", expiresAt: Date.now() + expiresIn * 1000, resendAt: Date.now() + resendIn * 1000 }));

  it("returns to registration when there is no pending signup", async () => {
    mockFetch(() => ({ status: 401, body: {} }));
    renderAt("/verify-email");
    expect(await screen.findByRole("heading", { name: /create your account/i })).toBeInTheDocument();
  });

  it("masks the email, shows countdown, disables resend during cooldown", async () => {
    seed(); mockFetch(() => ({ status: 401, body: {} }));
    renderAt("/verify-email");
    expect(await screen.findByText(/ad\*\*\*@example\.com/)).toBeInTheDocument();
    expect(screen.getByText(/code expires in/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /resend code in \d+s/i })).toBeDisabled();
  });

  it("supports paste, verifies on the backend and redirects to login", async () => {
    seed(); mockFetch((u) => (u.includes("/verify-email") ? { body: { message: "ok" } } : { status: 401, body: {} }));
    renderAt("/verify-email");
    const first = await screen.findByLabelText("Digit 1");
    fireEvent.paste(first, { clipboardData: { getData: () => "123 456" } });
    await waitFor(() => expect(screen.getByLabelText("Digit 6")).toHaveValue("6"));
    await userEvent.setup().click(screen.getByRole("button", { name: /verify email/i }));
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByText(/email verified/i)).toBeInTheDocument();
    const body = JSON.parse(calls.find((c) => c.url.includes("/verify-email"))!.init!.body as string);
    expect(body).toEqual({ email: "ada@example.com", otp: "123456" });
    expect(sessionStorage.getItem(PENDING_KEY)).toBeNull();
  });

  it("requires 6 digits and displays backend errors (invalid / too many attempts)", async () => {
    seed(); mockFetch((u) => (u.includes("/verify-email") ? { status: 429, body: { detail: "Too many incorrect attempts. Request a new code." } } : { status: 401, body: {} }));
    renderAt("/verify-email");
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: /verify email/i }));
    expect(screen.getByRole("alert")).toHaveTextContent(/enter the 6-digit code/i);
    fireEvent.paste(screen.getByLabelText("Digit 1"), { clipboardData: { getData: () => "000000" } });
    await u.click(screen.getByRole("button", { name: /verify email/i }));
    expect(await screen.findByText(/too many incorrect attempts/i)).toBeInTheDocument();
  });

  it("enables resend after the cooldown elapses and calls the API", async () => {
    seed(300, 1); mockFetch((u) => (u.includes("/resend-otp") ? { body: { otp_expires_in: 300, resend_cooldown: 60 } } : { status: 401, body: {} }));
    renderAt("/verify-email");
    const btn = await screen.findByRole("button", { name: /resend code/i });
    await waitFor(() => expect(btn).toBeEnabled(), { timeout: 4000 });
    await userEvent.setup().click(btn);
    expect(await screen.findByText(/new code has been sent/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /resend code in/i })).toBeDisabled();
  });

  it("shows an expired message when the timer runs out", async () => {
    seed(0, 0); mockFetch(() => ({ status: 401, body: {} }));
    renderAt("/verify-email");
    expect(await screen.findByText(/this code has expired/i)).toBeInTheDocument();
  });
});

describe("login", () => {
  it("validates input then signs in via the backend", async () => {
    let signedIn = false;
    mockFetch((u) => {
      if (u.includes("/auth/login")) { signedIn = true; return { body: { user: USER } }; }
      if (u.includes("/auth/me")) return signedIn ? { body: { user: USER } } : { status: 401, body: {} };
      if (u.includes("/api/dashboard")) return { body: DASH };
      return { body: { items: [], unread: 0 } };
    });
    renderAt("/login");
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: /^sign in$/i }));
    expect(screen.getByText(/enter a valid email/i)).toBeInTheDocument();
    await u.type(screen.getByLabelText(/email address/i), "a@b.com");
    await u.type(screen.getByLabelText(/^password$/i), "Str0ng!Passw0rd");
    await u.click(screen.getByRole("checkbox", { name: /remember me/i }));
    await u.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    const body = JSON.parse(calls.find((c) => c.url.includes("/auth/login"))!.init!.body as string);
    expect(body).toEqual({ email: "a@b.com", password: "Str0ng!Passw0rd", remember_me: true });
  });

  it("toggles password visibility and shows backend errors", async () => {
    mockFetch((u) => (u.includes("/auth/login") ? { status: 401, body: { detail: "Incorrect email or password." } } : { status: 401, body: {} }));
    renderAt("/login");
    const u = userEvent.setup();
    const pw = await screen.findByLabelText(/^password$/i);
    expect(pw).toHaveAttribute("type", "password");
    await u.click(screen.getByRole("button", { name: /show password/i }));
    expect(pw).toHaveAttribute("type", "text");
    await u.type(screen.getByLabelText(/email address/i), "a@b.com"); await u.type(pw, "x");
    await u.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByText(/incorrect email or password/i)).toBeInTheDocument();
  });
});

describe("forgot & reset password", () => {
  it("shows the generic confirmation message", async () => {
    mockFetch(() => ({ body: { message: "If an account exists for that email, a password reset link has been sent." } }));
    renderAt("/forgot-password", <ForgotPassword />);
    const u = userEvent.setup();
    await u.type(screen.getByLabelText(/email address/i), "someone@example.com");
    await u.click(screen.getByRole("button", { name: /send password-reset link/i }));
    expect(await screen.findByText(/if an account exists/i)).toBeInTheDocument();
  });

  it("reads the token from the URL fragment, scrubs it, validates and resets", async () => {
    window.history.replaceState(null, "", "/reset-password#token=" + "t".repeat(43));
    mockFetch((u) => ({ body: u.includes("reset-password") ? { message: "ok" } : { valid: true } }));
    renderAt("/reset-password", <Routes><Route path="/reset-password" element={<ResetPassword />} /><Route path="/password-reset-complete" element={<h1>done</h1>} /></Routes>);
    expect(await screen.findByRole("heading", { name: /set a new password/i })).toBeInTheDocument();
    expect(window.location.hash).toBe("");                       // token removed from address bar
    const u = userEvent.setup();
    const [a, b] = screen.getAllByLabelText(/new password/i).filter((e) => e.tagName === "INPUT");
    await u.type(a, "N3w!Passw0rd-xyz"); await u.type(b, "mismatch");
    await u.click(screen.getByRole("button", { name: /reset password/i }));
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
    await u.clear(b); await u.type(b, "N3w!Passw0rd-xyz");
    await u.click(screen.getByRole("button", { name: /reset password/i }));
    expect(await screen.findByRole("heading", { name: "done" })).toBeInTheDocument();
    const body = JSON.parse(calls.find((c) => c.url.endsWith("/auth/reset-password"))!.init!.body as string);
    expect(body.token).toBe("t".repeat(43));
  });

  it("rejects missing or expired tokens", async () => {
    window.history.replaceState(null, "", "/reset-password#token=" + "x".repeat(43));
    mockFetch(() => ({ status: 400, body: { detail: "This reset link is invalid or has expired." } }));
    renderAt("/reset-password", <ResetPassword />);
    expect(await screen.findByRole("heading", { name: /link invalid or expired/i })).toBeInTheDocument();
  });
});

describe("dashboard & API error handling", () => {
  it("renders real backend statistics and empty chart states", async () => {
    mockFetch(() => ({ body: DASH }));
    renderAt("/", <Dashboard />);
    expect(screen.getByRole("status")).toBeInTheDocument();                 // loading state
    expect(await screen.findByText("1,200")).toBeInTheDocument();
    expect(screen.getByText("Total datasets").previousSibling).toHaveTextContent("3");
    expect(screen.getAllByText(/no data yet/i).length).toBeGreaterThan(0);
  });

  it("shows an error state with retry when the API fails", async () => {
    mockFetch(() => ({ status: 500, body: { detail: "Internal server error" } }));
    renderAt("/", <Dashboard />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/internal server error/i);
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("formats pydantic validation errors and network failures", async () => {
    mockFetch(() => ({ status: 422, body: { detail: [{ loc: ["body", "email"], msg: "value is not a valid email address" }] } }));
    await expect(api("/x", { body: {} })).rejects.toThrow(/email: value is not a valid email/);
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("fail"); }));
    await expect(api("/x")).rejects.toMatchObject({ status: 0 });
    mockFetch(() => ({ status: 429, body: { detail: "Too many requests." } }));
    await api("/y").catch((e) => expect(e).toBeInstanceOf(ApiError));
  });

  it("refreshes the session once on 401 and retries", async () => {
    let n = 0;
    mockFetch((u) => { if (u.includes("/auth/refresh")) return { body: {} }; n++; return n === 1 ? { status: 401, body: {} } : { body: { ok: true } }; });
    await expect(api("/api/datasets")).resolves.toEqual({ ok: true });
    expect(calls.filter((c) => c.url.includes("/auth/refresh")).length).toBe(1);
  });

  it("sends the CSRF header on mutating requests", async () => {
    document.cookie = "tg_csrf=abc123";
    mockFetch(() => ({ body: {} }));
    await api("/api/datasets/x/pipeline", { method: "POST", body: {} });
    expect((calls[0].init!.headers as Record<string, string>)["X-CSRF-Token"]).toBe("abc123");
    expect(calls[0].init!.credentials).toBe("include");
  });
});
