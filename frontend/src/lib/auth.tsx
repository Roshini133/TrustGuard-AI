import { createContext, ReactNode, useContext } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "./api";

export interface User { id: string; email: string; full_name: string; role: string; permissions: string[]; is_verified: boolean }
interface Ctx { user: User | null; loading: boolean; can: (perm: string) => boolean; login: (email: string, password: string, remember: boolean) => Promise<void>; logout: () => Promise<void> }

const AuthCtx = createContext<Ctx>(null as unknown as Ctx);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["me"],
    retry: false,
    staleTime: 60_000,
    queryFn: async () => {
      try { return (await api<{ user: User }>("/api/auth/me")).user; }
      catch (e) { if (e instanceof ApiError && e.status === 401) return null; throw e; }
    },
  });
  const user = data ?? null;
  // Evict all cached data except the session query, whose observer must stay attached to re-render the app.
  const resetCache = (u: User | null) => {
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
    qc.setQueryData(["me"], u);
  };
  const value: Ctx = {
    user, loading: isLoading,
    can: (p) => !!user && (user.permissions.includes("*") || user.permissions.includes(p)),
    login: async (email, password, remember_me) => {
      const r = await api<{ user: User }>("/api/auth/login", { body: { email, password, remember_me } });
      resetCache(r.user);
    },
    logout: async () => {
      try { await api("/api/auth/logout", { method: "POST", body: {}, noRefresh: true }); } catch { /* cookie cleared server-side when reachable */ }
      resetCache(null);
    },
  };
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}
