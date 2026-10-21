import { ClipboardEvent, KeyboardEvent, useRef } from "react";

export default function OtpInput({ value, onChange, disabled }: { value: string; onChange: (v: string) => void; disabled?: boolean }) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const digits = Array.from({ length: 6 }, (_, i) => value[i] ?? "");
  const set = (i: number, d: string) => {
    const arr = [...digits]; arr[i] = d; onChange(arr.join("").slice(0, 6));
  };
  const onInput = (i: number, raw: string) => {
    const d = raw.replace(/\D/g, "");
    if (!d) { set(i, ""); return; }
    if (d.length > 1) { onChange((value.slice(0, i) + d).slice(0, 6)); refs.current[Math.min(i + d.length, 5)]?.focus(); return; }
    set(i, d);
    if (i < 5) refs.current[i + 1]?.focus();
  };
  const onKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !digits[i] && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowRight" && i < 5) refs.current[i + 1]?.focus();
  };
  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const d = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (!d) return;
    e.preventDefault(); onChange(d); refs.current[Math.min(d.length, 5)]?.focus();
  };
  return (
    <div className="flex justify-center gap-2" role="group" aria-label="6-digit verification code">
      {digits.map((d, i) => (
        <input key={i} ref={(el) => (refs.current[i] = el)} value={d} disabled={disabled} inputMode="numeric" autoComplete={i === 0 ? "one-time-code" : "off"}
          aria-label={`Digit ${i + 1}`} maxLength={6}
          className="h-12 w-11 rounded-lg border border-line bg-white text-center text-xl font-semibold text-primary-dark focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/30 sm:h-14 sm:w-12"
          onChange={(e) => onInput(i, e.target.value)} onKeyDown={(e) => onKey(i, e)} onPaste={onPaste} onFocus={(e) => e.target.select()} />
      ))}
    </div>
  );
}
