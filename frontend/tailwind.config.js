/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        primary: { DEFAULT: "#2563EB", dark: "#1E3A8A", navy: "#0F172A", light: "#EFF6FF" },
        page: "#F8FAFC", line: "#DBEAFE", ink: "#1E293B", muted: "#64748B",
        ok: "#16A34A", warn: "#D97706", crit: "#DC2626",
      },
      boxShadow: { card: "0 1px 2px rgba(30,58,138,.06), 0 1px 3px rgba(30,58,138,.08)" },
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"] },
    },
  },
  plugins: [],
};
