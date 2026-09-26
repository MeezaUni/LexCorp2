import { ethers } from 'ethers';
import deployment from '../../../contracts/deployments/besu.json';

/**
 * Chain access for the browser.
 *
 * The Besu JSON-RPC endpoint is NOT reachable from browsers (bound to 127.0.0.1, no
 * CORS origins). All chain traffic goes through the authenticated backend relay
 * /api/chain/rpc, which only allows read/submit methods and only forwards
 * transactions signed by the logged-in user's own wallet to the LexCorp2 contract.
 * Authorization is enforced by the AssetNFT v3 contract roles, not by this code.
 */

export const CHAIN_ID = 13371;
export const CONTRACT_ADDRESS = deployment.address;
const ABI = deployment.abi;
const NETWORK = new ethers.Network('lexcorp2-besu', CHAIN_ID);

export function getRpcProvider() {
  // Same-origin fetch (browser default credentials) sends the HttpOnly session cookie.
  const req = new ethers.FetchRequest(`${window.location.origin}/api/chain/rpc`);
  return new ethers.JsonRpcProvider(req, NETWORK, { staticNetwork: NETWORK, batchMaxCount: 1 });
}

export async function getContract(signerOrProvider) {
  return new ethers.Contract(CONTRACT_ADDRESS, ABI, signerOrProvider || getRpcProvider());
}

// Zero-fee permissioned network: explicit legacy transactions with gasPrice 0.
const TX = { gasLimit: 2_000_000, gasPrice: 0, type: 0 };

async function waitForReceipt(txHash, timeoutMs = 60000) {
  const provider = getRpcProvider();
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const rcpt = await provider.getTransactionReceipt(txHash).catch(() => null);
    if (rcpt && rcpt.status !== undefined && rcpt.status !== null) {
      if (rcpt.status !== 1) throw new Error('The transaction was rejected by the LexCorp2 contract (reverted).');
      return rcpt;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('Transaction confirmation timed out');
}

/** Submit backend-prepared calldata (mint / anchor / grant) with the user's wallet. */
export async function sendPreparedCalldata(wallet, calldata, contractAddress) {
  const to = calldata.to || contractAddress;
  if (!to || to.toLowerCase() !== CONTRACT_ADDRESS.toLowerCase()) {
    throw new Error('Refusing to sign: calldata is not addressed to the LexCorp2 contract.');
  }
  const signer = wallet.connect(getRpcProvider());
  const tx = await signer.sendTransaction({ to, data: calldata.data, ...TX });
  const rcpt = await waitForReceipt(tx.hash);
  return { txHash: rcpt.hash, blockNumber: rcpt.blockNumber };
}

async function call(signer, method, ...args) {
  const contract = await getContract(signer);
  const tx = await contract[method](...args, TX);
  const rcpt = await waitForReceipt(tx.hash);
  return { txHash: rcpt.hash, blockNumber: rcpt.blockNumber };
}

export const mintAsset = (signer, to, tokenId, serial, ownerDID) => call(signer, 'mint', to, tokenId, serial, ownerDID);
export const mintDigitalAsset = (signer, to, tokenId, serial, ownerDID, fileHash, uri) =>
  call(signer, 'mintDigitalAsset', to, tokenId, serial, ownerDID, fileHash, uri);
export const updateDigitalAsset = (signer, tokenId, newFileHash, newUri) => call(signer, 'updateDigitalAsset', tokenId, newFileHash, newUri);
export const grantAssetAccess = (signer, tokenId, targetDID, level = 1) => call(signer, 'grantAssetAccess', tokenId, targetDID, level);
export const revokeAssetAccess = (signer, tokenId, targetDID) => call(signer, 'revokeAssetAccess', tokenId, targetDID);
export const recordAccessAttempt = (signer, tokenId, actorDID, granted, reason) =>
  call(signer, 'recordAccessAttempt', tokenId, actorDID, granted, reason);
export const transferAsset = (signer, to, tokenId, newOwnerDID) => call(signer, 'transferAsset', to, tokenId, newOwnerDID);
export const revokeAsset = (signer, tokenId) => call(signer, 'revoke', tokenId);

/** Informational only (the contract enforces roles itself). */
export async function hasChainRole(address, roleName) {
  const contract = await getContract();
  const role = roleName === 'DEFAULT_ADMIN_ROLE' ? ethers.ZeroHash : ethers.keccak256(ethers.toUtf8Bytes(roleName));
  return contract.hasRole(role, address);
}

export async function checkManagerRole(_signer, address) {
  try {
    return await hasChainRole(address, 'MANAGER_ROLE');
  } catch {
    return false;
  }
}

export async function checkAssetAccess(signerOrProvider, tokenId, requesterDID, callerAddress) {
  const contract = await getContract(signerOrProvider);
  const [authorized, level] = await contract.checkAssetAccess(tokenId, requesterDID, callerAddress);
  return { authorized, level: Number(level) };
}

export async function getAsset(tokenId) {
  const contract = await getContract();
  try {
    const res = await contract.getDigitalAsset(tokenId);
    const ownerAddress = await contract.ownerOf(tokenId);
    return { tokenId: Number(tokenId), serialNumber: res[0], ownerDID: res[1], fileHash: res[2], offchainURI: res[3], isDigital: res[4], ownerAddress };
  } catch {
    return null;
  }
}
