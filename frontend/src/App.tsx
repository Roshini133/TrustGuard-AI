import { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./lib/auth";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import { AccessDenied, ForgotPassword, Login, Register, ResetComplete, ResetPassword, VerifyEmail } from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import { DatasetDetail, Datasets, DatasetUpload } from "./pages/Datasets";
import { Experiments, Lineage, ModelImpact, Models, Pipeline, Quality, Quarantine, Suspicious, Training, TrustAnalysis } from "./pages/Analysis";
import { Audit, Help, Notifications, Reports, Security, Settings, System, Users } from "./pages/Admin";

export function RequireAuth({ children, admin, perm }: { children: ReactNode; admin?: boolean; perm?: string }) {
  const { user, loading, can } = useAuth();
  const loc = useLocation();
  if (loading) return <Loading label="Checking your session…" />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if ((admin && user.role !== "admin") || (perm && !can(perm))) return <Navigate to="/access-denied" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/password-reset-complete" element={<ResetComplete />} />
      <Route path="/access-denied" element={<AccessDenied />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Dashboard />} />
        <Route path="datasets" element={<Datasets />} />
        <Route path="datasets/upload" element={<RequireAuth perm="dataset:write"><DatasetUpload /></RequireAuth>} />
        <Route path="datasets/:id" element={<DatasetDetail />} />
        <Route path="pipeline" element={<Pipeline />} />
        <Route path="trust-analysis" element={<TrustAnalysis />} />
        <Route path="suspicious" element={<Suspicious />} />
        <Route path="quarantine" element={<Quarantine />} />
        <Route path="training" element={<Training />} />
        <Route path="models" element={<Models />} />
        <Route path="model-impact" element={<ModelImpact />} />
        <Route path="experiments" element={<Experiments />} />
        <Route path="lineage" element={<Lineage />} />
        <Route path="quality" element={<Quality />} />
        <Route path="security" element={<Security />} />
        <Route path="audit" element={<RequireAuth admin><Audit /></RequireAuth>} />
        <Route path="reports" element={<Reports />} />
        <Route path="notifications" element={<Notifications />} />
        <Route path="users" element={<RequireAuth admin><Users /></RequireAuth>} />
        <Route path="system" element={<RequireAuth admin><System /></RequireAuth>} />
        <Route path="settings" element={<Settings />} />
        <Route path="help" element={<Help />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
