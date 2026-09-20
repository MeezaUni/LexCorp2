const hre = require("hardhat");

async function main() {
  const deployment = require("../deployments/localhost.json");
  const [deployer] = await hre.ethers.getSigners();
  const contract = await hre.ethers.getContractAt("AssetNFT", deployment.address, deployer);

  console.log("=== Contract State Check ===");

  // 1. Check specific token IDs via getAsset (safe)
  for (const tokenId of [101, 102, 103]) {
    try {
      const owner = await contract.ownerOf(tokenId);
      const [serial, did] = await contract.getAsset(tokenId);
      console.log(`Token ${tokenId} -> Owner: ${owner}, Serial: ${serial}`);
    } catch (err) {
      console.log(`Token ${tokenId} -> Does not exist`);
    }
  }

  // 2. Check serials
  const serials = ["LEX-DRONE-ALPHA-01", "LEX-SECURE-SERVER-99", "LEX-QUANTUM-NODE-07"];
  for (const s of serials) {
    try {
      const tokenId = await contract.getTokenBySerial(s);
      console.log(`Serial ${s} -> Token ID: ${tokenId.toString()}`);
    } catch (err) {
      console.log(`Serial ${s} -> Error: ${err.message}`);
    }
  }

  // 3. Check owner's assets
  const user1 = "0x0d98054ea37fd3db3a068080a14619b44c7887ac";
  console.log("\nChecking assets for User 1...");
  try {
    const balance = await contract.balanceOf(user1);
    console.log("Balance:", balance.toString());
    // Note: tokenOfOwnerByIndex requires ERC721Enumerable, which AssetNFT might not have.
    // If it fails, we simply accept it's not enumerable.
    for (let i = 0; i < Number(balance); i++) {
        console.log(`  Token index ${i} found (Non-Enumerable contract - cannot map index to ID)`);
    }
  } catch (err) {
    console.log("Error checking User 1 assets:", err.message);
  }
}

main().catch(console.error);
