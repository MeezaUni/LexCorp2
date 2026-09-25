import { ethers } from 'ethers';

/**
 * Encrypted wallet storage.
 *
 * The wallet is stored only as an ethers v3 JSON keystore (scrypt + AES-128-CTR).
 * The keystore is unlocked with a random wrapping secret held by the LexCorp server,
 * which releases it only to an authenticated session (GET /api/auth/wallet-key) and
 * rotates it on every provisioning or admin reset. A copy of this browser's storage
 * is therefore useless without logging in, and the private key / mnemonic is never
 * written to storage in plaintext.
 *
 * The keystore is NOT the authentication boundary: login always requires the typed
 * wallet address plus Login TOTP 1 or Login Passkey 1, verified server-side.
 */

const STORAGE_KEY = 'lexcorp_keystore_v2';
const LEGACY_PLAINTEXT_KEY = 'lexcorp_keystore';

export function parseWalletInput(keyOrMnemonic) {
  const value = (keyOrMnemonic || '').trim();
  try {
    return value.includes(' ') ? ethers.Wallet.fromPhrase(value) : new ethers.Wallet(value);
  } catch {
    throw new Error('Invalid private key or recovery phrase.');
  }
}

/** Encrypt and store a wallet with the server-issued wrapping secret. */
export async function storeEncryptedWallet(wallet, walletKey) {
  if (!walletKey) throw new Error('Missing wallet wrapping key from server.');
  const keystore = await wallet.encrypt(walletKey);
  localStorage.setItem(STORAGE_KEY, keystore);
  // Remove any legacy plaintext copy written by older versions of this app.
  localStorage.removeItem(LEGACY_PLAINTEXT_KEY);
}

export function hasEncryptedWallet() {
  return !!localStorage.getItem(STORAGE_KEY);
}

/** The address recorded in the keystore (public; never used as an auth boundary). */
export function storedWalletAddress() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? ethers.getAddress('0x' + JSON.parse(raw).address) : null;
  } catch {
    return null;
  }
}

/** Decrypt the keystore in memory with the wrapping secret from an authenticated session. */
export async function unlockWallet(walletKey) {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) throw new Error('No wallet on this device. Import it with a provisioning PIN.');
  try {
    return await ethers.Wallet.fromEncryptedJson(raw, walletKey);
  } catch {
    throw new Error('This device\'s wallet copy is out of date (it was re-provisioned). Re-import it with a new PIN.');
  }
}

export function purgeLegacyPlaintextWallet() {
  if (localStorage.getItem(LEGACY_PLAINTEXT_KEY)) {
    localStorage.removeItem(LEGACY_PLAINTEXT_KEY);
    return true;
  }
  return false;
}

export function clearWallet() {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(LEGACY_PLAINTEXT_KEY);
}
