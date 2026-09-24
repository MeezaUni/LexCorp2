import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import { getRpcProvider, checkManagerRole } from '../services/web3';
import { getNonce, login } from '../services/api';
import { hasEncryptedWallet, unlockWallet } from '../services/walletCore';
import WalletModal from '../components/WalletModal';

const AuthContext = createContext(null);
const SESSION_TTL_MS = 5 * 60 * 1000;

export function AuthProvider({ children }) {
  const [reauthRequired, setReauthRequired] = useState(() => Boolean(localStorage.getItem('lexcorp_user') || localStorage.getItem('lexcorp_token')));
  const [wallet, setWallet] = useState(null);
  const [signer, setSigner] = useState(null);
  const [user, setUser] = useState(null);
  const [isManager, setIsManager] = useState(false);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const inactivityTimerRef = useRef(null);
  const lastActivityRef = useRef(0);

  useEffect(() => {
    const hasPreviousSession = localStorage.getItem('lexcorp_user') || localStorage.getItem('lexcorp_token');
    if (hasEncryptedWallet() || hasPreviousSession) {
      localStorage.removeItem('lexcorp_wallet');
      localStorage.removeItem('lexcorp_user');
      localStorage.removeItem('lexcorp_token');
      setIsModalOpen(true);
    }
  }, []);

  const expireInactiveSession = useCallback(() => {
      localStorage.removeItem('lexcorp_wallet');
      localStorage.removeItem('lexcorp_user');
      localStorage.removeItem('lexcorp_token');
      setWallet(null);
      setSigner(null);
      setUser(null);
      setIsManager(false);
      setReauthRequired(true);
      setIsModalOpen(true);
  }, []);

  const resetInactivityTimer = useCallback(() => {
    if (!user && !signer) return;
    const now = Date.now();
    if (now - lastActivityRef.current < 1000) return;
    lastActivityRef.current = now;
    if (inactivityTimerRef.current) window.clearTimeout(inactivityTimerRef.current);
    inactivityTimerRef.current = window.setTimeout(expireInactiveSession, SESSION_TTL_MS);
  }, [expireInactiveSession, signer, user]);

  useEffect(() => {
    if (!user && !signer) return undefined;
    const activityEvents = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    activityEvents.forEach((eventName) => window.addEventListener(eventName, resetInactivityTimer));
    resetInactivityTimer();
    return () => {
      activityEvents.forEach((eventName) => window.removeEventListener(eventName, resetInactivityTimer));
      if (inactivityTimerRef.current) window.clearTimeout(inactivityTimerRef.current);
    };
  }, [resetInactivityTimer, signer, user]);

  // Authenticate when a wallet is unlocked
  const authenticateWithWallet = useCallback(async (unlockedWallet) => {
    setLoading(true);
    try {
      const provider = getRpcProvider();
      const connectedSigner = unlockedWallet.connect(provider);
      const address = await connectedSigner.getAddress();

      // SIWE Auth Flow
      const { nonce, message } = await getNonce(address);
      const signature = await connectedSigner.signMessage(message);
      const result = await login(message, signature, nonce);
      const manager = await checkManagerRole(connectedSigner, address);

      // Persist state
      const walletData = { address };
      localStorage.setItem('lexcorp_wallet', JSON.stringify(walletData));
      localStorage.setItem('lexcorp_user', JSON.stringify(result.user));

      setWallet(walletData);
      setSigner(connectedSigner);
      setUser(result.user);
      setIsManager(manager);
      setReauthRequired(false);

      return { address, isManager: manager, user: result.user };
    } catch (err) {
      console.error('Auth error:', err);
      disconnect();
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const authenticateWithSession = useCallback(async (result) => {
    const walletData = { address: result.user.wallet_address };
    localStorage.setItem('lexcorp_wallet', JSON.stringify(walletData));
    localStorage.setItem('lexcorp_user', JSON.stringify(result.user));
    localStorage.setItem('lexcorp_token', result.token);

    let connectedSigner = null;
    try {
      if (hasEncryptedWallet()) {
        const unlocked = await unlockWallet();
        const provider = getRpcProvider();
        connectedSigner = unlocked.connect(provider);
      }
    } catch (err) {
      console.warn('Could not auto-bind local wallet signer on session login:', err);
    }

    setWallet(walletData);
    setUser(result.user);
    setSigner(connectedSigner);
    setIsManager(result.user.role === 'ADMIN' || result.user.role === 'MANAGER');
    setReauthRequired(false);
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const token = localStorage.getItem('lexcorp_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch('/api/auth/me', { headers });
      if (res.ok) {
        const userData = await res.json();
        setUser(userData);
        localStorage.setItem('lexcorp_user', JSON.stringify(userData));
        setIsManager(userData.role === 'ADMIN' || userData.role === 'MANAGER');
        return userData;
      }
    } catch (err) {
      console.error('Failed to refresh user profile:', err);
    }
    return null;
  }, []);

  const connect = useCallback(() => {
    setIsModalOpen(true);
  }, []);

  const disconnect = useCallback(() => {
    localStorage.removeItem('lexcorp_wallet');
    localStorage.removeItem('lexcorp_user');
    localStorage.removeItem('lexcorp_token');
    setWallet(null);
    setSigner(null);
    setUser(null);
    setIsManager(false);
  }, []);

  return (
    <AuthContext.Provider value={{
      wallet,
      signer,
      user,
      isManager,
      loading,
      connect,
      disconnect,
      refreshUser,
      openWalletModal: () => setIsModalOpen(true),
    }}>
      {children}
      <WalletModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onUnlocked={(w) => authenticateWithWallet(w)}
        onAuthenticated={authenticateWithSession}
        forceLogin={reauthRequired}
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
