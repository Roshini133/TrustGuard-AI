import { FormEvent, ReactNode, useEffect, useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Loader2, MailCheck, ShieldCheck, ShieldX, CheckCircle2 } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Alert, Field } from "../components/ui";
import OtpInput from "../components/OtpInput";

export function AuthShell({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-primary-light to-white p-4">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-center gap-2 text-2xl font-bold text-primary-dark"><ShieldCheck className="h-8 w-8 text-primary" /> TrustGuard AI</div>
        <div className="card p-6 sm:p-8 fade-in">
          <h1 className="text-xl font-bold text-primary-navy">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
          <div className="mt-5">{children}</div>
        </div>
        <p className="mt-4 text-center text-xs text-muted">Secure machine-learning data pipelines</p>
      </div>
    </div>
  );
}

export const passwordChecks = (pw: string) => [
  { ok: pw.length >= 10, label: "At least 10 characters" },
  { ok: /[a-z]/.test(pw), label: "Lowercase letter" },
  { ok: /[A-Z]/.test(pw), label: "Uppercase letter" },
  { ok: /\d/.test(pw), label: "Number" },
  { ok: /[^A-Za-z0-9]/.test(pw), label: "Special character" },
];

function PasswordInput({ value, onChange, id, autoComplete, placeholder }: { value: string; onChange: (v: string) => void; id?: string; autoComplete?: string; placeholder?: string }) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <input id={id} className="input pr-10" type={show ? "text" : "password"} value={value} autoComplete={autoComplete} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
      <button type="button" aria-label={show ? "Hide password" : "Show password"} className="absolute inset-y-0 right-0 px-3 text-muted hover:text-primary" onClick={() => setShow(!show)}>
        {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  );
}

const Strength = ({ pw }: { pw: string }) => (
  <ul className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs" aria-label="Password requirements">
    {passwordChecks(pw).map((c) => <li key={c.label} className={c.ok ? "text-ok" : "text-muted"}>{c.ok ? "✓" : "○"} {c.label}</li>)}
  </ul>
);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const Submit = ({ busy, children }: { busy: boolean; children: ReactNode }) => (
  <button className="btn-primary w-full" type="submit" disabled={busy}>{busy && <Loader2 className="h-4 w-4 animate-spin" />}{children}</button>
);

// ---------------- Login ----------------
export function Login() {
  const { user, login } = useAuth();
  const nav = useNavigate();
  const loc = useLocation() as { state?: { from?: string; notice?: string } };
  const [email, setEmail] = useState(""); const [pw, setPw] = useState(""); const [remember, setRemember] = useState(false);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  if (user) return <Navigate to={loc.state?.from ?? "/"} replace />;
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr("");
    if (!EMAIL_RE.test(email.trim())) return setErr("Enter a valid email address.");
    if (!pw) return setErr("Enter your password.");
    setBusy(true);
    try { await login(email.trim(), pw, remember); nav(loc.state?.from ?? "/", { replace: true }); }
    catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Sign-in failed."); }
    finally { setBusy(false); }
  };
  return (
    <AuthShell title="Sign in" subtitle="Welcome back. Sign in to your workspace.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {loc.state?.notice && <Alert kind="success">{loc.state.notice}</Alert>}
        {err && <Alert kind="error">{err}</Alert>}
        <Field label="Email address"><input className="input" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" /></Field>
        <Field label="Password"><PasswordInput value={pw} onChange={setPw} autoComplete="current-password" /></Field>
        <div className="flex items-center justify-between text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="rounded border-line text-primary" /> Remember me</label>
          <Link to="/forgot-password" className="font-medium text-primary hover:underline">Forgot password?</Link>
        </div>
        <Submit busy={busy}>Sign in</Submit>
        <p className="text-center text-sm text-muted">No account? <Link to="/register" className="font-semibold text-primary hover:underline">Create one</Link></p>
      </form>
    </AuthShell>
  );
}

// ---------------- Register ----------------
export const PENDING_KEY = "tg_pending";   // stores only email + timing hints, never the OTP

export function Register() {
  const nav = useNavigate();
  const [f, setF] = useState({ full_name: "", email: "", password: "", confirm_password: "", accept_terms: false });
  const [errs, setErrs] = useState<Record<string, string>>({}); const [serverErr, setServerErr] = useState(""); const [busy, setBusy] = useState(false);
  const set = (k: string, v: string | boolean) => setF((p) => ({ ...p, [k]: v }));
  const validate = () => {
    const e: Record<string, string> = {};
    if (f.full_name.trim().length < 2) e.full_name = "Enter your full name.";
    if (!EMAIL_RE.test(f.email.trim())) e.email = "Enter a valid email address.";
    if (passwordChecks(f.password).some((c) => !c.ok)) e.password = "Password does not meet all requirements.";
    if (f.password !== f.confirm_password) e.confirm_password = "Passwords do not match.";
    if (!f.accept_terms) e.accept_terms = "You must accept the Terms and Privacy Policy.";
    setErrs(e); return Object.keys(e).length === 0;
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setServerErr("");
    if (!validate()) return;
    setBusy(true);
    try {
      const r = await api<{ otp_expires_in: number; resend_cooldown: number }>("/api/auth/register", { body: { ...f, email: f.email.trim() } });
      const now = Date.now();
      sessionStorage.setItem(PENDING_KEY, JSON.stringify({ email: f.email.trim().toLowerCase(), expiresAt: now + r.otp_expires_in * 1000, resendAt: now + r.resend_cooldown * 1000 }));
      nav("/verify-email");
    } catch (ex) { setServerErr(ex instanceof ApiError ? ex.message : "Registration failed."); }
    finally { setBusy(false); }
  };
  return (
    <AuthShell title="Create your account" subtitle="We'll email a 6-digit code to verify your address.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {serverErr && <Alert kind="error">{serverErr}</Alert>}
        <Field label="Full name" error={errs.full_name}><input className="input" autoComplete="name" value={f.full_name} onChange={(e) => set("full_name", e.target.value)} /></Field>
        <Field label="Email address" error={errs.email}><input className="input" type="email" autoComplete="email" value={f.email} onChange={(e) => set("email", e.target.value)} /></Field>
        <Field label="Password" error={errs.password}><PasswordInput value={f.password} onChange={(v) => set("password", v)} autoComplete="new-password" /><Strength pw={f.password} /></Field>
        <Field label="Confirm password" error={errs.confirm_password}><PasswordInput value={f.confirm_password} onChange={(v) => set("confirm_password", v)} autoComplete="new-password" /></Field>
        <div>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1 rounded border-line text-primary" checked={f.accept_terms} onChange={(e) => set("accept_terms", e.target.checked)} />
            <span>I accept the <Link to="/help#terms" className="text-primary underline">Terms</Link> and <Link to="/help#privacy" className="text-primary underline">Privacy Policy</Link>.</span></label>
          {errs.accept_terms && <span role="alert" className="mt-1 block text-xs text-crit">{errs.accept_terms}</span>}
        </div>
        <Submit busy={busy}>Create account</Submit>
        <p className="text-center text-sm text-muted">Already registered? <Link to="/login" className="font-semibold text-primary hover:underline">Sign in</Link></p>
      </form>
    </AuthShell>
  );
}

// ---------------- Verify email ----------------
const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

export function VerifyEmail() {
  const nav = useNavigate();
  const raw = sessionStorage.getItem(PENDING_KEY);
  const pending = raw ? (JSON.parse(raw) as { email: string; expiresAt: number; resendAt: number }) : null;
  const [otp, setOtp] = useState(""); const [err, setErr] = useState(""); const [info, setInfo] = useState(""); const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now()); const [exp, setExp] = useState(pending?.expiresAt ?? 0); const [resendAt, setResendAt] = useState(pending?.resendAt ?? 0);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  if (!pending) return <Navigate to="/register" replace />;
  const left = Math.max(0, Math.ceil((exp - now) / 1000)); const cool = Math.max(0, Math.ceil((resendAt - now) / 1000));
  const masked = pending.email.replace(/^(.{2}).*(@.*)$/, "$1***$2");
  const verify = async (e: FormEvent) => {
    e.preventDefault(); setErr(""); setInfo("");
    if (otp.length !== 6) return setErr("Enter the 6-digit code.");
    setBusy(true);
    try {
      await api("/api/auth/verify-email", { body: { email: pending.email, otp } });
      sessionStorage.removeItem(PENDING_KEY);
      nav("/login", { replace: true, state: { notice: "Email verified. You can now sign in." } });
    } catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Verification failed."); setOtp(""); }
    finally { setBusy(false); }
  };
  const resend = async () => {
    setErr(""); setInfo(""); setBusy(true);
    try {
      const r = await api<{ otp_expires_in: number; resend_cooldown: number }>("/api/auth/resend-otp", { body: { email: pending.email } });
      const t = Date.now(); setExp(t + r.otp_expires_in * 1000); setResendAt(t + r.resend_cooldown * 1000);
      sessionStorage.setItem(PENDING_KEY, JSON.stringify({ ...pending, expiresAt: t + r.otp_expires_in * 1000, resendAt: t + r.resend_cooldown * 1000 }));
      setInfo("A new code has been sent."); setOtp("");
    } catch (ex) {
      if (ex instanceof ApiError && ex.retryAfter) setResendAt(Date.now() + ex.retryAfter * 1000);
      setErr(ex instanceof ApiError ? ex.message : "Could not resend the code.");
    } finally { setBusy(false); }
  };
  return (
    <AuthShell title="Verify your email" subtitle={`Enter the 6-digit code we sent to ${masked}.`}>
      <form onSubmit={verify} className="space-y-4">
        <div className="mb-1 flex justify-center text-primary"><MailCheck className="h-10 w-10" /></div>
        {err && <Alert kind="error">{err}</Alert>}
        {info && <Alert kind="success">{info}</Alert>}
        <OtpInput value={otp} onChange={setOtp} disabled={busy} />
        <p className="text-center text-sm" aria-live="polite">{left > 0 ? <>Code expires in <span className="font-semibold text-primary-dark">{mmss(left)}</span></> : <span className="text-crit">This code has expired. Request a new one.</span>}</p>
        <Submit busy={busy}>Verify email</Submit>
        <button type="button" className="btn-secondary w-full" disabled={cool > 0 || busy} onClick={resend}>{cool > 0 ? `Resend code in ${cool}s` : "Resend code"}</button>
        <p className="text-center text-sm text-muted"><Link to="/register" className="font-medium text-primary hover:underline" onClick={() => sessionStorage.removeItem(PENDING_KEY)}>Use a different email</Link></p>
      </form>
    </AuthShell>
  );
}

// ---------------- Forgot password ----------------
export function ForgotPassword() {
  const [email, setEmail] = useState(""); const [err, setErr] = useState(""); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(""); setMsg("");
    if (!EMAIL_RE.test(email.trim())) return setErr("Enter a valid email address.");
    setBusy(true);
    try { const r = await api<{ message: string }>("/api/auth/forgot-password", { body: { email: email.trim() } }); setMsg(r.message); }
    catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Request failed."); }
    finally { setBusy(false); }
  };
  return (
    <AuthShell title="Forgot your password?" subtitle="Enter your email and we'll send you a reset link.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {err && <Alert kind="error">{err}</Alert>}
        {msg && <Alert kind="success">{msg} The link expires in 15 minutes.</Alert>}
        <Field label="Email address"><input className="input" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
        <Submit busy={busy}>Send password-reset link</Submit>
        <p className="text-center text-sm"><Link to="/login" className="font-medium text-primary hover:underline">← Back to sign in</Link></p>
      </form>
    </AuthShell>
  );
}

// ---------------- Reset password ----------------
export function ResetPassword() {
  const nav = useNavigate();
  const [token] = useState(() => new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") ?? "");
  const [state, setState] = useState<"checking" | "ok" | "bad">(token ? "checking" : "bad");
  const [pw, setPw] = useState(""); const [pw2, setPw2] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (token) window.history.replaceState(null, "", window.location.pathname);   // remove token from address bar/history
    if (!token) return;
    api("/api/auth/validate-reset-token", { body: { token } }).then(() => setState("ok")).catch(() => setState("bad"));
  }, [token]);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr("");
    if (passwordChecks(pw).some((c) => !c.ok)) return setErr("Password does not meet all requirements.");
    if (pw !== pw2) return setErr("Passwords do not match.");
    setBusy(true);
    try { await api("/api/auth/reset-password", { body: { token, password: pw, confirm_password: pw2 } }); nav("/password-reset-complete", { replace: true }); }
    catch (ex) { setErr(ex instanceof ApiError ? ex.message : "Reset failed."); }
    finally { setBusy(false); }
  };
  if (state === "checking") return <AuthShell title="Checking your link…"><div className="flex justify-center p-6"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div></AuthShell>;
  if (state === "bad") return (
    <AuthShell title="Link invalid or expired"><div className="space-y-4"><div className="flex justify-center text-crit"><ShieldX className="h-10 w-10" /></div>
      <p className="text-sm text-muted">This reset link is invalid, already used, or has expired.</p><Link className="btn-primary w-full" to="/forgot-password">Request a new link</Link></div></AuthShell>
  );
  return (
    <AuthShell title="Set a new password" subtitle="Choose a strong password you haven't used before.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {err && <Alert kind="error">{err}</Alert>}
        <Field label="New password"><PasswordInput value={pw} onChange={setPw} autoComplete="new-password" /><Strength pw={pw} /></Field>
        <Field label="Confirm new password"><PasswordInput value={pw2} onChange={setPw2} autoComplete="new-password" /></Field>
        <Submit busy={busy}>Reset password</Submit>
      </form>
    </AuthShell>
  );
}

export function ResetComplete() {
  return (
    <AuthShell title="Password updated">
      <div className="space-y-4 text-center"><div className="flex justify-center text-ok"><CheckCircle2 className="h-12 w-12" /></div>
        <p className="text-sm text-muted">Your password was changed and all devices were signed out. Please sign in with your new password.</p>
        <Link to="/login" className="btn-primary w-full">Go to sign in</Link></div>
    </AuthShell>
  );
}

export function AccessDenied() {
  return (
    <AuthShell title="Access denied">
      <div className="space-y-4 text-center"><div className="flex justify-center text-crit"><ShieldX className="h-12 w-12" /></div>
        <p className="text-sm text-muted">Your role does not permit access to this page.</p><Link to="/" className="btn-primary w-full">Back to dashboard</Link></div>
    </AuthShell>
  );
}
