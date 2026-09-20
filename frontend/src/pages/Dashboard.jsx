import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import ManagerDashboard from './ManagerDashboard';
import AuditorDashboard from './AuditorDashboard';
import UserDashboard from './UserDashboard';
import AssetRegistry from './AssetRegistry';
import AdminDashboard from './AdminDashboard';
import Identity from './Identity';

function ExecutiveDashboard() {
  const [metrics, setMetrics] = useState({ totalAssets: 0, riskStatus: 'LOW', activeDIDs: 0 });
  const [loading, setLoading] = useState(true);

  const fetchMetrics = async () => {
    try {
      const [assetsRes, auditRes, usersRes] = await Promise.all([
        fetch('/api/assets/registry').then(r => r.json()),
        fetch('/api/audit/stats').then(r => r.json()),
        fetch('/api/users').then(r => r.json()),
      ]);

      setMetrics({
        totalAssets: Array.isArray(assetsRes) ? assetsRes.length : 0,
        riskStatus: auditRes?.latest_risk || 'LOW',
        activeDIDs: Array.isArray(usersRes) ? usersRes.length : 0,
      });
    } catch (err) {
      console.error('Failed to load metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ width: '100%' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#0f172a', margin: '0 0 6px 0' }}>
          System Intelligence & Executive Overview
        </h2>
        <p style={{ fontSize: '14px', color: '#64748b', margin: 0 }}>
          Real-time decentralized identity verification, on-chain asset registry statistics, and air-gapped AI anomaly detection.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ background: '#fff', padding: '1.75rem', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            Total Minted Assets
          </div>
          <div style={{ fontSize: '32px', fontWeight: '700', color: '#0f172a' }}>
            {loading ? '...' : metrics.totalAssets}
          </div>
          <div style={{ fontSize: '12px', color: '#10b981', marginTop: '6px', fontWeight: '500' }}>
            Verified on Besu Consortium (Chain 13371)
          </div>
        </div>

        <div style={{ background: '#fff', padding: '1.75rem', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            Air-Gapped AI Risk Status
          </div>
          <div style={{
            fontSize: '32px',
            fontWeight: '700',
            color: metrics.riskStatus === 'LOW' ? '#16a34a' : metrics.riskStatus === 'MEDIUM' ? '#d97706' : '#dc2626'
          }}>
            {loading ? '...' : metrics.riskStatus}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
            Local IsolationForest Anomaly Engine
          </div>
        </div>

        <div style={{ background: '#fff', padding: '1.75rem', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            Active Cryptographic DIDs
          </div>
          <div style={{ fontSize: '32px', fontWeight: '700', color: '#0f172a' }}>
            {loading ? '...' : metrics.activeDIDs}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
            W3C Verifiable Credential Holders
          </div>
        </div>
      </div>

      <div style={{ background: '#fff', borderRadius: '12px', border: '1px solid #e2e8f0', padding: '1.75rem', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#0f172a', margin: '0 0 12px 0' }}>
          Network & Contract Architecture
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem', fontSize: '13px' }}>
          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: '8px', border: '1px solid #f1f5f9' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase' }}>Consensus Network</span>
            <strong style={{ color: '#0f172a' }}>Hyperledger Besu QBFT (Chain ID: 13371)</strong>
          </div>
          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: '8px', border: '1px solid #f1f5f9' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase' }}>Security Standard</span>
            <strong style={{ color: '#0f172a' }}>ERC-721 Digital Twin + W3C DID-VC</strong>
          </div>
          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: '8px', border: '1px solid #f1f5f9' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase' }}>AI Processing Mode</span>
            <strong style={{ color: '#0f172a' }}>100% Embedded Air-Gapped (Zero Cloud Calls)</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { wallet, user, isManager, connect, disconnect, loading } = useAuth();
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('auto');

  useEffect(() => {
    if (!wallet) {
      setActiveTab('auto');
    }
  }, [wallet]);

  const handleConnect = async () => {
    setError('');
    try {
      await connect();
    } catch (err) {
      setError(err.message || 'Failed to connect wallet');
    }
  };

  const userDbRole = user?.role?.toLowerCase() || 'user';

  const getValidatedRole = () => {
    if (activeTab === 'auto') {
      return userDbRole === 'user' ? 'user' : 'executive';
    }

    const canAccess = {
      executive: ['manager', 'auditor', 'admin'],
      manager: ['manager', 'admin'],
      auditor: ['auditor', 'admin'],
      registry: ['manager', 'auditor', 'admin'],
      admin: ['manager', 'admin'],
      user: ['user', 'manager', 'auditor', 'admin'],
      identity: ['user', 'manager', 'auditor', 'admin']
    };

    if (canAccess[activeTab]?.includes(userDbRole)) return activeTab;
    return userDbRole === 'user' ? 'user' : 'executive';
  };

  const currentRole = getValidatedRole();
  const walletAddress = wallet?.address || (typeof wallet === 'string' ? wallet : '');

  const styles = {
    container: {
      minHeight: '100vh',
      width: '100%',
      background: '#f8fafc',
      margin: 0,
      padding: 0,
      fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      boxSizing: 'border-box',
    },
    header: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '1rem 2.5rem',
      background: '#0f172a',
      color: '#fff',
      borderBottom: '1px solid #334155',
      width: '100%',
      boxSizing: 'border-box',
    },
    logo: {
      fontSize: '22px',
      fontWeight: '800',
      letterSpacing: '-0.03em',
      color: '#ffffff',
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    },
    logoSub: {
      fontSize: '11px',
      color: '#94a3b8',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      fontWeight: '600',
      marginTop: '2px',
    },
    walletInfo: {
      display: 'flex',
      alignItems: 'center',
      gap: '1.25rem',
    },
    walletBadge: {
      background: '#1e293b',
      border: '1px solid #334155',
      padding: '6px 14px',
      borderRadius: '8px',
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
    },
    walletAddress: {
      fontFamily: 'monospace',
      fontSize: '13px',
      fontWeight: '600',
      color: '#e2e8f0',
    },
    roleBadge: {
      fontSize: '11px',
      fontWeight: '700',
      textTransform: 'uppercase',
      letterSpacing: '0.06em',
      padding: '4px 8px',
      borderRadius: '6px',
      background: userDbRole === 'admin' ? '#ef4444' : userDbRole === 'manager' ? '#3b82f6' : userDbRole === 'auditor' ? '#f59e0b' : '#64748b',
      color: '#ffffff',
    },
    disconnectBtn: {
      background: 'transparent',
      color: '#f87171',
      border: '1px solid #7f1d1d',
      padding: '7px 16px',
      borderRadius: '6px',
      fontSize: '12px',
      fontWeight: '600',
      cursor: 'pointer',
      transition: 'all 0.2s',
    },
    tabs: {
      display: 'flex',
      gap: '8px',
      padding: '0.75rem 2.5rem',
      background: '#ffffff',
      borderBottom: '1px solid #e2e8f0',
      width: '100%',
      boxSizing: 'border-box',
    },
    tab: (active) => ({
      padding: '9px 18px',
      background: active ? '#0f172a' : 'transparent',
      color: active ? '#ffffff' : '#64748b',
      border: 'none',
      borderRadius: '6px',
      fontSize: '13px',
      fontWeight: '600',
      cursor: 'pointer',
      transition: 'all 0.15s ease-in-out',
    }),
    content: {
      flex: 1,
      padding: '2rem 2.5rem',
      width: '100%',
      boxSizing: 'border-box',
    },
  };

  if (!wallet) {
    return (
      <div style={{ ...styles.container, justifyContent: 'center', alignItems: 'center', background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)' }}>
        <div style={{ background: '#ffffff', padding: '3.5rem', borderRadius: '16px', textAlign: 'center', maxWidth: '440px', width: '90%', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.35)' }}>
          <div style={{ fontSize: '28px', fontWeight: '800', color: '#0f172a', letterSpacing: '-0.03em', marginBottom: '6px' }}>LexCorp</div>
          <div style={{ fontSize: '13px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: '600', marginBottom: '1.5rem' }}>
            Blockchain Identity & Asset Traceability
          </div>
          <p style={{ fontSize: '14px', color: '#475569', marginBottom: '2rem', lineHeight: '1.5' }}>
            Authenticate using your localized, self-controlled cryptographic EVM keyring to access the asset twins and compliance audit logs.
          </p>
          {error && <div style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', padding: '10px', borderRadius: '6px', fontSize: '13px', marginBottom: '1.5rem' }}>{error}</div>}
          <button
            onClick={handleConnect}
            disabled={loading}
            style={{
              background: '#0f172a',
              color: '#ffffff',
              border: 'none',
              padding: '14px 28px',
              borderRadius: '8px',
              fontSize: '14px',
              fontWeight: '600',
              cursor: loading ? 'not-allowed' : 'pointer',
              width: '100%',
              boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)'
            }}
          >
            {loading ? 'Authenticating...' : 'Unlock Cryptographic Keyring'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <div>
          <div style={styles.logo}>LexCorp</div>
          <div style={styles.logoSub}>PS-26125</div>
        </div>
        <div style={styles.walletInfo}>
          <div style={styles.walletBadge}>
            <span style={styles.walletAddress}>
              {walletAddress ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}` : 'Connected'}
            </span>
            <span style={styles.roleBadge}>{userDbRole}</span>
          </div>
          <button onClick={disconnect} style={styles.disconnectBtn}>
            Disconnect
          </button>
        </div>
      </header>

      <nav style={styles.tabs}>
        <button onClick={() => setActiveTab('auto')} style={styles.tab(activeTab === 'auto')}>
          Dashboard
        </button>

        {(userDbRole === 'manager' || userDbRole === 'admin' || isManager) && (
          <button onClick={() => setActiveTab('manager')} style={styles.tab(activeTab === 'manager')}>
            Operations
          </button>
        )}

        {(userDbRole === 'auditor' || userDbRole === 'admin') && (
          <button onClick={() => setActiveTab('auditor')} style={styles.tab(activeTab === 'auditor')}>
            Audit Trail
          </button>
        )}

        {(userDbRole === 'manager' || userDbRole === 'auditor' || userDbRole === 'admin') && (
          <button onClick={() => setActiveTab('registry')} style={styles.tab(activeTab === 'registry')}>
            Asset Registry
          </button>
        )}

        {(userDbRole === 'manager' || userDbRole === 'admin') && (
          <button onClick={() => setActiveTab('admin')} style={styles.tab(activeTab === 'admin')}>
            Users & Keypairs
          </button>
        )}

        {userDbRole !== 'user' && (
          <button onClick={() => setActiveTab('user')} style={styles.tab(activeTab === 'user')}>
            My Assets
          </button>
        )}

        <button onClick={() => setActiveTab('identity')} style={styles.tab(activeTab === 'identity')}>
          My Identity
        </button>
      </nav>

      <main style={styles.content}>
        {currentRole === 'executive' && <ExecutiveDashboard />}
        {currentRole === 'manager' && <ManagerDashboard />}
        {currentRole === 'auditor' && <AuditorDashboard />}
        {currentRole === 'registry' && <AssetRegistry />}
        {currentRole === 'admin' && <AdminDashboard />}
        {currentRole === 'user' && <UserDashboard />}
        {currentRole === 'identity' && <Identity />}
      </main>
    </div>
  );
}
