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
import ScopeSbomViewerPage from "@/routes/ScopeSbomViewerPage";
import SastSarifViewerPage from "@/routes/SastSarifViewerPage";
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
        {/* M6q: nested routes for scope detail — tab + row state driven by URL.
            /scopes/:id                       → SCA tab, no row expanded
            /scopes/:id/sca                   → SCA tab
            /scopes/:id/sca/:issueId          → SCA tab, row expanded
            /scopes/:id/sast                  → SAST tab
            /scopes/:id/sast/:issueId         → SAST tab, row expanded
            /scopes/:id/components            → Components tab
            /scopes/:id/components/:componentId → Components tab, row expanded */}
        <Route path="/scopes/:id" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/sca" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/sca/:issueId" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/sast" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/sast/:issueId" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/components" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/components/:componentId" element={<ScopeDetailPage />} />
        <Route path="/scopes/:id/sbom" element={<ScopeSbomViewerPage />} />
        <Route path="/scans" element={<ScansPage />} />
        {/* M6q: nested routes for scan detail */}
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/scans/:id/findings" element={<ScanDetailPage />} />
        <Route path="/scans/:id/sast" element={<ScanDetailPage />} />
        <Route path="/scans/:id/components" element={<ScanDetailPage />} />
        <Route path="/scans/:id/components/:componentId" element={<ScanDetailPage />} />
        <Route path="/scans/:id/sbom" element={<SbomViewerPage />} />
        <Route path="/scans/:id/sast-sarif" element={<SastSarifViewerPage />} />
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
