import { confirmChainEffect } from './api';
import { sendPreparedCalldata } from './web3';

/**
 * Sign backend-prepared calldata with this device's wallet, wait for the Besu receipt,
 * then ask the server to record the effect. The server re-reads the receipt AND the
 * contract state before recording anything, and the contract itself rejects wallets
 * without MINTER/ANCHOR/MANAGER_ROLE - nothing is marked done on the client's word.
 */
export async function signAndConfirm(getSigner, calldata, contractAddress, serial, onProgress = () => {}) {
  onProgress('Unlocking your wallet on this device');
  const signer = await getSigner();
  onProgress('Submitting the transaction to the LexCorp2 ledger');
  const { txHash } = await sendPreparedCalldata(signer, calldata, contractAddress);
  onProgress('Verifying the receipt and contract state');
  return confirmChainEffect(serial, txHash);
}
