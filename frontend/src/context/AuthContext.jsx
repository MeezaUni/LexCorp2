import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import { getRpcProvider } from '../services/web3';
import { getMe, getWalletKey, logoutSession } from '../services/api';
import { hasEncryptedWallet, purgeLegacyPlaintextWallet, unlockWallet } from '../services/walletCore';
import WalletModal from '../components/WalletModal';

const AuthContext = createContext(null);
// Mirrors the server's INACTIVITY_TIMEOUT_MINUTES; the server is authoritative.
const INACTIVITY_MS = 15 * 60 * 1000;

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [signer, setSigner] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [notice, setNotice] = useState('');
  const inactivityTimerRef = useRef(null);

  const clearSession = useCallback(() => {
    localStorage.removeItem('lexcorp_token');
    localStorage.removeItem('lexcorp_user');
    localStorage.removeItem('lexcorp_wallet');
    setUser(null);
    setSigner(null);
  }, []);

  const endSession = useCallback((message) => {
    clearSession();
    setNotice(message || '');
    setIsModalOpen(true);
  }, [clearSession]);

  /** Decrypt the local keystore in memory with the session-released wrapping key. */
  const unlockSigner = useCallback(async () => {
    if (!hasEncryptedWallet()) throw new Error('No wallet on this device. Import it with a provisioning PIN.');
    const key = await getWalletKey();
    const wallet = await unlockWallet(key);
    const connected = wallet.connect(getRpcProvider());
    setSigner(connected);
    return connected;
  }, []);

  const establish = useCallback(async (result) => {
    localStorage.setItem('lexcorp_token', result.token);
    const me = await getMe();
    setUser(me);
    setNotice('');
    if (!me.onboarding_pending && hasEncryptedWallet()) {
      unlockSigner().catch((err) => console.warn('Wallet signer unavailable:', err.message));
    }
    return me;
  }, [unlockSigner]);

  // Restore a server-validated session on load; never trust cached profile data.
  useEffect(() => {
    if (purgeLegacyPlaintextWallet()) {
      setNotice('An unencrypted wallet copy from an older version was removed from this device. Re-import your wallet with a provisioning PIN to sign transactions.');
    }
    const token = localStorage.getItem('lexcorp_token');
    if (!token) { setLoading(false); setIsModalOpen(true); return; }
    getMe()
      .then((me) => {
        setUser(me);
        if (!me.onboarding_pending && hasEncryptedWallet()) unlockSigner().catch(() => {});
      })
      .catch(() => { clearSession(); setIsModalOpen(true); })
      .finally(() => setLoading(false));
  }, [clearSession, unlockSigner]);

  useEffect(() => {
    const onEnded = (e) => endSession(e.detail || 'Your session ended. Please sign in again.');
    window.addEventListener('lexcorp:session-ended', onEnded);
    return () => window.removeEventListener('lexcorp:session-ended', onEnded);
  }, [endSession]);

  const disconnect = useCallback(async () => {
    await logoutSession();
    clearSession();
    setIsModalOpen(true);
  }, [clearSession]);

  useEffect(() => {
    if (!user) return undefined;
    const reset = () => {
      if (inactivityTimerRef.current) window.clearTimeout(inactivityTimerRef.current);
      inactivityTimerRef.current = window.setTimeout(() => {
        logoutSession().finally(() => endSession('Signed out after 15 minutes of inactivity.'));
      }, INACTIVITY_MS);
    };
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((ev) => window.addEventListener(ev, reset));
    reset();
    return () => {
      events.forEach((ev) => window.removeEventListener(ev, reset));
      if (inactivityTimerRef.current) window.clearTimeout(inactivityTimerRef.current);
    };
  }, [user, endSession]);

  const wallet = user ? { address: user.wallet_address } : null;

  return (
    <AuthContext.Provider value={{
      wallet,
      signer,
      user,
      isManager: user?.role === 'ADMIN' || user?.role === 'MANAGER',
      setupRequired: Boolean(user?.onboarding_pending),
      loading,
      connect: () => setIsModalOpen(true),
      disconnect,
      unlockSigner,
      establishSession: establish,
      refreshUser: async () => { const me = await getMe(); setUser(me); return me; },
      openWalletModal: () => setIsModalOpen(true),
    }}>
      {children}
      <WalletModal
        isOpen={isModalOpen && !user}
        onClose={() => setIsModalOpen(false)}
        onAuthenticated={establish}
        notice={notice}
      />
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
