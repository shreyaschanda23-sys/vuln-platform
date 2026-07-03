import { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuthStore } from './store/authStore';

import Layout from './components/Layout/Layout';
import LoginPage from './pages/LoginPage';
import OverviewPage from './pages/OverviewPage';
import ScansPage from './pages/ScansPage';
import FindingsPage from './pages/FindingsPage';
import AttackSurfacePage from './pages/AttackSurfacePage';
import SchedulerPage from './pages/SchedulerPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';

function ProtectedRoute({ children }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

export default function App() {
  const hydrate = useAuthStore((s) => s.hydrate);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  return (
    <>
      <Toaster position="top-right" toastOptions={{
        style: { background: '#18181b', color: '#e4e4e7', border: '1px solid #27272a' },
      }} />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
          <Route index element={<OverviewPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="attack-surface" element={<AttackSurfacePage />} />
          <Route path="scheduler" element={<SchedulerPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </>
  );
}