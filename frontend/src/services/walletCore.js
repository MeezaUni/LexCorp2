import { ethers } from 'ethers';

const STORAGE_KEY = 'lexcorp_keystore';

/**
 * Creates a brand new random wallet and stores its private key locally without password.
 *
 * @returns {Promise<ethers.Wallet>} - The unencrypted wallet instance
 */
export async function createNewWallet() {
  const wallet = ethers.Wallet.createRandom();
  localStorage.setItem(STORAGE_KEY, wallet.privateKey);
  return wallet;
}

/**
 * Imports an existing private key or mnemonic and stores it.
 *
 * @param {string} keyOrMnemonic - Valid Private Key or 12/24 word Mnemonic
 * @returns {Promise<ethers.Wallet>} - The imported wallet instance
 */
export async function importWallet(keyOrMnemonic) {
  let wallet;
  try {
    if (keyOrMnemonic.includes(' ')) {
      wallet = ethers.Wallet.fromPhrase(keyOrMnemonic.trim());
    } else {
      wallet = new ethers.Wallet(keyOrMnemonic.trim());
    }
  } catch (err) {
    throw new Error('Invalid private key or mnemonic phrase');
  }

  localStorage.setItem(STORAGE_KEY, wallet.privateKey);
  return wallet;
}

/**
 * Checks if a wallet is stored in local storage.
 * @returns {boolean}
 */
export function hasEncryptedWallet() {
  // Still called hasEncryptedWallet by consumers, but implies HAS wallet.
  return !!localStorage.getItem(STORAGE_KEY);
}

/**
 * Loads the locally stored wallet keystore without password.
 *
 * @returns {Promise<ethers.Wallet>} - Wallet instance
 */
export async function unlockWallet() {
  const privateKey = localStorage.getItem(STORAGE_KEY);
  if (!privateKey) {
    throw new Error('No wallet found on this device');
  }

  try {
    // If it is stored as an encrypted JSON originally, it will fail here.
    // So we try parsing it. If it fails, maybe we should clear it or alert the user.
    if (privateKey.startsWith('{')) {
       throw new Error('Legacy password-encrypted wallet found. Please logout and re-import your key.');
    }
    const wallet = new ethers.Wallet(privateKey);
    return wallet;
  } catch (err) {
    console.error("Failed to load wallet:", err);
    throw new Error(err.message || 'Corrupted wallet file');
  }
}

/**
 * Connects an unencrypted wallet instance to a network provider.
 *
 * @param {ethers.Wallet} wallet - Unlocked wallet
 * @param {ethers.Provider} provider - The RPC provider (Besu)
 * @returns {ethers.Wallet} - The connected signer ready to execute transactions
 */
export function connectWalletToProvider(wallet, provider) {
  return wallet.connect(provider);
}

/**
 * Clears the stored keystore (Logout/Reset)
 */
export function removeWallet() {
  localStorage.removeItem(STORAGE_KEY);
}
