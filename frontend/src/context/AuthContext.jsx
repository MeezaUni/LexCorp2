import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { getRpcProvider, checkManagerRole } from '../services/web3';
import { getNonce, login } from '../services/api';
import { hasEncryptedWallet } from '../services/walletCore';
import WalletModal from '../components/WalletModal';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [wallet, setWallet] = useState(() => JSON.parse(localStorage.getItem('lexcorp_wallet')));
  const [signer, setSigner] = useState(null);
  const [user, setUser] = useState(() => JSON.parse(localStorage.getItem('lexcorp_user')));
  const [isManager, setIsManager] = useState(false);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);

  useEffect(() => {
    if (wallet?.address && !signer && hasEncryptedWallet()) {
      setIsModalOpen(true);
    }
  }, [wallet?.address, signer]);

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

      return { address, isManager: manager, user: result.user };
    } catch (err) {
      console.error('Auth error:', err);
      disconnect();
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const authenticateWithSession = useCallback((result) => {
    const walletData = { address: result.user.wallet_address };
    localStorage.setItem('lexcorp_wallet', JSON.stringify(walletData));
    localStorage.setItem('lexcorp_user', JSON.stringify(result.user));
    localStorage.setItem('lexcorp_token', result.token);
    setWallet(walletData);
    setUser(result.user);
    setSigner(null);
    setIsManager(result.user.role === 'ADMIN' || result.user.role === 'MANAGER');
  }, []);

  const connect = useCallback(() => {
    setIsModalOpen(true);
  }, []);

  const disconnect = useCallback(() => {
    localStorage.removeItem('lexcorp_wallet');
    localStorage.removeItem('lexcorp_user');
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
      openWalletModal: () => setIsModalOpen(true),
    }}>
      {children}
      <WalletModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onUnlocked={(w) => authenticateWithWallet(w)}
        onAuthenticated={authenticateWithSession}
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
