import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { getMe, getSession, getWalletKey, logoutSession } from '../services/api';
import { hasEncryptedWallet, purgeLegacyPlaintextWallet, unlockWallet } from '../services/walletCore';
import { getRpcProvider } from '../services/web3';

const AuthContext = createContext(null);

// Mirrors the server's INACTIVITY_TIMEOUT_MINUTES; the server enforces it regardless.
const INACTIVITY_MS = 15 * 60 * 1000;

/**
 * Session state for the UI. The session itself is an HttpOnly cookie the page cannot
 * read; `user` is always what the server returns from /auth/me. Role and department
 * here only decide what to SHOW - every request is authorized again by the server.
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');
  const [lastActivity, setLastActivity] = useState(Date.now());
  const signerRef = useRef(null);
  const timerRef = useRef(null);

  const clear = useCallback((message = '') => {
    signerRef.current = null;
    setUser(null);
    setNotice(message);
    localStorage.removeItem('lexcorp_token'); // remove any token left by older versions
  }, []);

  const refresh = useCallback(async () => {
    const me = await getMe();
    setUser(me);
    return me;
  }, []);

  useEffect(() => {
    if (purgeLegacyPlaintextWallet()) {
      setNotice('An unencrypted wallet copy from an older version was removed from this device. Provision the wallet again with a new PIN.');
    }
    localStorage.removeItem('lexcorp_token');
    getSession()
      .then((st) => (st.authenticated ? getMe().then(setUser) : setUser(null)))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const onEnded = (e) => clear(e.detail || 'Your session ended. Sign in again.');
    window.addEventListener('lexcorp:session-ended', onEnded);
    return () => window.removeEventListener('lexcorp:session-ended', onEnded);
  }, [clear]);

  const signOut = useCallback(async (message = '') => {
    await logoutSession();
    clear(message);
  }, [clear]);

  // Inactivity timeout (client side mirror).
  useEffect(() => {
    if (!user) return undefined;
    const reset = () => {
      setLastActivity(Date.now());
      window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => signOut('You were signed out after 15 minutes of inactivity.'), INACTIVITY_MS);
    };
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((ev) => window.addEventListener(ev, reset, { passive: true }));
    reset();
    return () => {
      events.forEach((ev) => window.removeEventListener(ev, reset));
      window.clearTimeout(timerRef.current);
    };
  }, [user, signOut]);

  /** Decrypt this device's keystore in memory with the session-released wrapping key. */
  const getSigner = useCallback(async () => {
    if (signerRef.current) return signerRef.current;
    if (!hasEncryptedWallet()) {
      throw new Error('This device holds no wallet for your identity. Provision it with a PIN from your administrator to sign blockchain transactions.');
    }
    const wallet = await unlockWallet(await getWalletKey());
    if (user && wallet.address.toLowerCase() !== user.wallet_address.toLowerCase()) {
      throw new Error('The wallet stored on this device belongs to a different identity.');
    }
    signerRef.current = wallet.connect(getRpcProvider());
    return signerRef.current;
  }, [user]);

  const value = {
    user,
    loading,
    notice,
    setNotice,
    lastActivity,
    setupRequired: Boolean(user?.onboarding_pending),
    role: user?.role,
    isAdmin: user?.role === 'ADMIN',
    isManager: user?.role === 'MANAGER',
    canApprove: user?.role === 'ADMIN' || user?.role === 'MANAGER',
    isSecurity: ['ADMIN', 'MANAGER', 'AUDITOR'].includes(user?.role),
    refresh,
    signOut,
    getSigner,
    onAuthenticated: async () => { setNotice(''); return refresh(); },
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
