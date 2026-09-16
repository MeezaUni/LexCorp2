import { ethers } from 'ethers';

const STORAGE_KEY = 'lexcorp_keystore';

/**
 * Creates a brand new random wallet, encrypts it with the provided password,
 * and stores the Keystore JSON locally.
 *
 * @param {string} password - User's chosen password
 * @returns {Promise<ethers.Wallet>} - The unencrypted wallet instance (for immediate use)
 */
export async function createNewWallet(password) {
  if (!password || password.length < 6) {
    throw new Error('Password must be at least 6 characters long');
  }

  // 1. Generate a secure random mnemonic/private key
  const wallet = ethers.Wallet.createRandom();

  // 2. Encrypt the wallet using the password (Ethers handles PBKDF2/scrypt and AES)
  // Note: encrypt() can take a few seconds as it heavily derives the key to prevent brute-forcing
  const encryptedJson = await wallet.encrypt(password);

  // 3. Store the encrypted JSON safely in localStorage
  localStorage.setItem(STORAGE_KEY, encryptedJson);

  return wallet;
}

/**
 * Imports an existing private key or mnemonic, encrypts it, and stores it.
 *
 * @param {string} keyOrMnemonic - Valid Private Key or 12/24 word Mnemonic
 * @param {string} password - User's chosen password
 * @returns {Promise<ethers.Wallet>} - The imported wallet instance
 */
export async function importWallet(keyOrMnemonic, password) {
  if (!password || password.length < 6) {
    throw new Error('Password must be at least 6 characters long');
  }

  let wallet;
  try {
    if (keyOrMnemonic.includes(' ')) {
      // It's a mnemonic
      wallet = ethers.Wallet.fromPhrase(keyOrMnemonic.trim());
    } else {
      // It's a private key
      wallet = new ethers.Wallet(keyOrMnemonic.trim());
    }
  } catch (err) {
    throw new Error('Invalid private key or mnemonic phrase');
  }

  const encryptedJson = await wallet.encrypt(password);
  localStorage.setItem(STORAGE_KEY, encryptedJson);

  return wallet;
}

/**
 * Checks if a wallet keystore exists in local storage.
 * @returns {boolean}
 */
export function hasEncryptedWallet() {
  return !!localStorage.getItem(STORAGE_KEY);
}

/**
 * Unlocks the locally stored encrypted keystore.
 *
 * @param {string} password - The password used to encrypt the wallet
 * @returns {Promise<ethers.Wallet>} - Decrypted wallet instance
 */
export async function unlockWallet(password) {
  const encryptedJson = localStorage.getItem(STORAGE_KEY);
  if (!encryptedJson) {
    throw new Error('No wallet found on this device');
  }

  try {
    // This throws an error if the password is wrong
    const wallet = await ethers.Wallet.fromEncryptedJson(encryptedJson, password);
    return wallet;
  } catch (err) {
    console.error("Failed to unlock wallet:", err);
    throw new Error('Invalid password or corrupted wallet file');
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
