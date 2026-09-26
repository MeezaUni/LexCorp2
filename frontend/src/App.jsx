import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Shell from './components/Shell';
import { Loading, Notice, PageHeader } from './components/ui';
import SignIn from './pages/SignIn';
import Enrolment from './pages/Enrolment';
import Dashboard from './pages/Dashboard';
import DigitalAssets from './pages/DigitalAssets';
import DigitalAssetDetail from './pages/DigitalAssetDetail';
import PhysicalAssets from './pages/PhysicalAssets';
import PhysicalAssetDetail from './pages/PhysicalAssetDetail';
import Requests from './pages/Requests';
import Alerts from './pages/Alerts';
import Audit from './pages/Audit';
import Identity from './pages/Identity';
import Admin from './pages/Admin';
import { VerifyAction, VerifyAsset } from './pages/Verify';

/** UI-level route hiding only; the server authorizes every request independently. */
function RoleRoute({ roles, children }) {
  const { user } = useAuth();
  if (roles.includes(user.role)) return children;
  return (
    <>
      <PageHeader title="Not available for your role" />
      <div className="content"><Notice tone="warning">This area is not part of your role. <Link to="/">Return to the dashboard</Link>.</Notice></div>
    </>
  );
}

function NotFound() {
  return (<><PageHeader title="Page not found" /><div className="content"><Notice tone="info">There is no page at this address. <Link to="/">Return to the dashboard</Link>.</Notice></div></>);
}

function Gate() {
  const { user, loading } = useAuth();
  if (loading) return <div style={{ padding: 48 }}><Loading label="Checking your session" /></div>;
  if (!user) return <SignIn />;
  if (user.onboarding_pending) return <Enrolment />;
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Dashboard />} />
        <Route path="digital" element={<DigitalAssets />} />
        <Route path="digital/:serial" element={<DigitalAssetDetail />} />
        <Route path="physical" element={<PhysicalAssets />} />
        <Route path="physical/:serial" element={<PhysicalAssetDetail />} />
        <Route path="requests" element={<Requests />} />
        <Route path="alerts" element={<RoleRoute roles={['AUDITOR', 'MANAGER', 'ADMIN']}><Alerts /></RoleRoute>} />
        <Route path="audit" element={<RoleRoute roles={['AUDITOR', 'MANAGER', 'ADMIN']}><Audit /></RoleRoute>} />
        <Route path="identity" element={<Identity />} />
        <Route path="admin" element={<RoleRoute roles={['ADMIN', 'MANAGER']}><Admin /></RoleRoute>} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <a className="sr-only" href="#main">Skip to content</a>
        <Routes>
          <Route path="/verify/action/:actionId" element={<VerifyAction />} />
          <Route path="/verify/token/:tokenId" element={<VerifyAsset />} />
          <Route path="/verify/:serial" element={<VerifyAsset />} />
          <Route path="/*" element={<Gate />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
