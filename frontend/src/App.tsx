import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/AppShell";
import { RequireAuth } from "@/components/RequireAuth";
import { RequireAdmin } from "@/components/RequireAdmin";
import LoginPage from "@/routes/LoginPage";
import DashboardPage from "@/routes/DashboardPage";
import ScopesPage from "@/routes/ScopesPage";
import ScopeDetailPage from "@/routes/ScopeDetailPage";
import ScansPage from "@/routes/ScansPage";
import ScanDetailPage from "@/routes/ScanDetailPage";
import SbomViewerPage from "@/routes/SbomViewerPage";
import ReposPage from "@/routes/admin/ReposPage";
import SettingsPage from "@/routes/admin/SettingsPage";
import CredentialsPage from "@/routes/admin/CredentialsPage";
import NotFoundPage from "@/routes/NotFoundPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/scopes" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/scopes" element={<ScopesPage />} />
        <Route path="/scopes/:id" element={<ScopeDetailPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/scans/:id/sbom" element={<SbomViewerPage />} />
        <Route
          path="/admin/repos"
          element={
            <RequireAdmin>
              <ReposPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <RequireAdmin>
              <SettingsPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/admin/credentials"
          element={
            <RequireAdmin>
              <CredentialsPage />
            </RequireAdmin>
          }
        />
      </Route>

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
