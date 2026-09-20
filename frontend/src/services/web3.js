import { ethers } from 'ethers';
import deployment from '../../../contracts/deployments/localhost.json';

const CONTRACT_ADDRESS = deployment.address;
const ABI = deployment.abi;

const getRpcUrl = () => {
  if (import.meta.env.VITE_RPC_URL && import.meta.env.VITE_RPC_URL !== 'http://localhost:8545') {
    return import.meta.env.VITE_RPC_URL;
  }
  const host = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
  return `http://${host}:8545`;
};

export const BESU_NETWORK_PARAMS = {
  chainId: '0x343B', // 13371 in hex
  chainName: 'LexCorp Besu Private Consortium',
  nativeCurrency: {
    name: 'LexCorp Enterprise Credit',
    symbol: 'LEX',
    decimals: 18,
  },
  get rpcUrls() {
    return [getRpcUrl()];
  },
  blockExplorerUrls: null,
};

export function getRpcProvider() {
  return new ethers.JsonRpcProvider(getRpcUrl());
}

export async function connectWallet() {
  // We no longer rely on MetaMask!
  // This now just checks the network is alive and returns the provider.
  const provider = getRpcProvider();

  // Test connection
  try {
    await provider.getNetwork();
  } catch (err) {
    throw new Error('Failed to connect to LexCorp Besu network at ' + getRpcUrl());
  }

  return { provider };
}

export async function getContract(signerOrProvider) {
  return new ethers.Contract(CONTRACT_ADDRESS, ABI, signerOrProvider);
}

export async function checkManagerRole(signer, address) {
  try {
    const contract = await getContract(signer);
    const managerRole = ethers.keccak256(ethers.toUtf8Bytes("MANAGER_ROLE"));
    const adminRole = ethers.ZeroHash;

    const isMgr = await contract.hasRole(managerRole, address);
    const isAdmin = await contract.hasRole(adminRole, address);

    return isMgr || isAdmin;
  } catch (err) {
    console.error('Role check error details:', err);
    return false;
  }
}

export async function mintAsset(signer, toAddress, tokenId, serialNumber, ownerDID) {
  const contract = await getContract(signer);
  const tx = await contract.mint(toAddress, tokenId, serialNumber, ownerDID);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function mintDigitalAsset(signer, toAddress, tokenId, serialNumber, ownerDID, fileHash, offchainURI) {
  const contract = await getContract(signer);
  const tx = await contract.mintDigitalAsset(toAddress, tokenId, serialNumber, ownerDID, fileHash, offchainURI);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function updateDigitalAsset(signer, tokenId, requesterDID, newFileHash, newOffchainURI) {
  const contract = await getContract(signer);
  const tx = await contract.updateDigitalAsset(tokenId, requesterDID, newFileHash, newOffchainURI);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function grantAssetAccess(signer, tokenId, targetDID, level = 1) {
  const contract = await getContract(signer);
  const tx = await contract.grantAssetAccess(tokenId, targetDID, level);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function revokeAssetAccess(signer, tokenId, targetDID) {
  const contract = await getContract(signer);
  const tx = await contract.revokeAssetAccess(tokenId, targetDID);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function checkAssetAccess(signerOrProvider, tokenId, requesterDID, callerAddress) {
  const contract = await getContract(signerOrProvider);
  const [authorized, level] = await contract.checkAssetAccess(tokenId, requesterDID, callerAddress);
  return { authorized, level: Number(level) };
}

export async function recordAccessAttempt(signer, tokenId, actorDID, granted, reason) {
  const contract = await getContract(signer);
  const tx = await contract.recordAccessAttempt(tokenId, actorDID, granted, reason);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function transferAsset(signer, toAddress, tokenId, newOwnerDID) {
  const contract = await getContract(signer);
  const tx = await contract.transferAsset(toAddress, tokenId, newOwnerDID);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function revokeAsset(signer, tokenId) {
  const contract = await getContract(signer);
  const tx = await contract.revoke(tokenId);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
}

export async function getAsset(tokenId) {
  const provider = getRpcProvider();
  const contract = await getContract(provider);

  try {
    const res = await contract.getDigitalAsset(tokenId);
    const ownerAddress = await contract.ownerOf(tokenId);

    return {
      tokenId: Number(tokenId),
      serialNumber: res[0],
      ownerDID: res[1],
      fileHash: res[2],
      offchainURI: res[3],
      isDigital: res[4],
      ownerAddress,
    };
  } catch (error) {
    try {
      const [serialNumber, ownerDID] = await contract.getAsset(tokenId);
      const ownerAddress = await contract.ownerOf(tokenId);
      return {
        tokenId: Number(tokenId),
        serialNumber,
        ownerDID,
        isDigital: false,
        ownerAddress,
      };
    } catch {
      return null;
    }
  }
}

export async function addTokenToMetaMask(address, tokenId) {
  if (!window.ethereum) return;
  try {
    await window.ethereum.request({
      method: 'wallet_watchAsset',
      params: {
        type: 'ERC721',
        options: {
          address,
          tokenId,
        },
      },
    });
  } catch (error) {
    console.error('Failed to add token to MetaMask:', error);
  }
}
