# Manual end-to-end email test (real delivery)

Automated tests use a mock mail provider and **cannot prove real delivery**. Run this checklist once against any
deployment (local Docker or Render) that has real Resend credentials. A `200`/`202` from the API only means the request
was accepted — you must see the email in a real inbox.

## 0. Prerequisites
1. A Resend account and an API key (`RESEND_API_KEY`).
2. A **permitted sender** in `EMAIL_FROM`:
   - **Production:** verify a domain in Resend (add the DNS records Resend shows: SPF/DKIM) and use an address on it,
     e.g. `TrustGuard AI <no-reply@yourdomain.com>`.
   - **Testing without a domain:** Resend's shared `onboarding@resend.dev` sender can only deliver to the email address
     that owns your Resend account. Use that address as the recipient.
   - An unverified sender/domain makes Resend reject the send; the API then returns `502` ("could not send the
     verification email") and writes an `auth.otp_email_failed` security event — **no account is verified**.
3. `EMAIL_PROVIDER=resend` (not `console`), `FRONTEND_URL` set to the real public URL of the frontend.

## 1. Registration OTP
1. Open `<FRONTEND_URL>/register`, register with an inbox you control.
2. Expect redirect to **Verify your email** with a 5:00 countdown and a disabled "Resend code in 60s" button.
3. Within ~1 minute a "Your TrustGuard AI verification code" email must arrive (check spam on first send).
   Confirm: TrustGuard branding, 6-digit code as text, expiry note, security warning, sender = `EMAIL_FROM`.
4. Enter a **wrong** code → "Incorrect verification code. 4 attempt(s) remaining."
5. Wait for the cooldown, press **Resend** → a new email arrives; the **old code no longer works**.
6. Enter the new code → redirected to Sign in with "Email verified." Sign in succeeds.
7. Negative checks: (a) let a code expire (5 min) → "expired"; (b) enter 5 wrong codes → "Too many incorrect attempts";
   (c) reuse a consumed code → "Invalid or expired".

## 2. Forgot / reset password
1. Open `<FRONTEND_URL>/forgot-password`, submit the registered address. Expect the generic confirmation message.
2. Submit an **unregistered** address → identical message, and **no email** is sent.
3. The "Reset your TrustGuard AI password" email must arrive with a **Reset password** button whose URL starts with
   your `FRONTEND_URL` (`…/reset-password#token=…`). Hover the button: the host must be your frontend, not localhost.
4. Click it → "Set a new password" page; the address bar is cleaned (token removed from the URL).
5. Submit mismatched passwords → error; submit a valid matching password → "Password updated".
6. A "Your password was changed" confirmation email must arrive.
7. Signing in with the **old** password fails; the new password works; other open sessions are signed out.
8. Click the original link again → "Link invalid or expired" (single use). Request another link and wait 15 minutes → expired.

## 3. Provider-side confirmation
In the Resend dashboard → **Emails**, confirm each message shows status **Delivered** (not just *Sent*). A *Bounced* or
*Complained* status means a recipient/domain problem, not an application problem.

## 4. Record the result
| Check | Pass/Fail | Date | Tester |
|---|---|---|---|
| OTP email delivered | | | |
| Reset email delivered | | | |
| Confirmation email delivered | | | |
| Links open the deployed frontend | | | |
