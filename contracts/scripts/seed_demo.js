const hre = require("hardhat");

async function main() {
  const deployment = require("../deployments/localhost.json");
  const [deployer] = await hre.ethers.getSigners();

  console.log("==========================================");
  console.log("🌱 SEEDING DEMO ENVIRONMENT (V2 Consortium)");
  console.log("==========================================");
  console.log("Deployer / Authority:", deployer.address);
  console.log("Contract Address:", deployment.address);

  const contract = await hre.ethers.getContractAt("AssetNFT", deployment.address, deployer);

  // 1. Target Accounts
  const accounts = {
    admin: (await hre.ethers.getSigners())[0].address,
    user1: (await hre.ethers.getSigners())[1].address,
    user2: (await hre.ethers.getSigners())[2].address,
  };

  // Skip funding since they are pre-funded with 100 ETH in ibft-config.json

  // 3. Grant MANAGER_ROLE & AUDITOR_ROLE
  console.log("\n🛡️ Granting Contract Roles...");
  const MANAGER_ROLE = await contract.MANAGER_ROLE();
  const AUDITOR_ROLE = await contract.AUDITOR_ROLE();
  try {
    const txRole = await contract.grantRole(MANAGER_ROLE, accounts.admin);
    await txRole.wait();
    console.log(`  ✓ Granted MANAGER_ROLE to Admin (${accounts.admin})`);

    const txAuditor = await contract.grantRole(AUDITOR_ROLE, accounts.user2);
    await txAuditor.wait();
    console.log(`  ✓ Granted AUDITOR_ROLE to Auditor User2 (${accounts.user2})`);
  } catch (err) {
    console.log(`  ! Role grant error: ${err.message}`);
  }

  // 4. Pre-Mint Physical Demo Assets
  console.log("\n📦 Minting Physical Demo Assets...");
  const physicalAssets = [
    {
      tokenId: 101,
      serial: "LEX-DRONE-ALPHA-01",
      owner: accounts.user1,
      name: "User 1",
    },
    {
      tokenId: 102,
      serial: "LEX-SECURE-SERVER-99",
      owner: accounts.user1,
      name: "User 1",
    },
  ];

  for (const asset of physicalAssets) {
    try {
      const did = `did:ethr:13371:${asset.owner.toLowerCase()}`;
      const txMint = await contract.mint(
        asset.owner,
        asset.tokenId,
        asset.serial,
        did
      );
      await txMint.wait();
      console.log(`  ✓ Minted Physical Asset #${asset.tokenId} (${asset.serial}) -> Assigned to ${asset.name}`);
    } catch (err) {
      console.log(`  ! Minting #${asset.tokenId} failed: ${err.message}`);
    }
  }

  // 5. Pre-Mint Digital Demo Assets (Encrypted Files & Hashes)
  console.log("\n📄 Minting Digital Assets with Access Permissions...");
  const digitalAssets = [
    {
      tokenId: 201,
      serial: "LEX-CONFIDENTIAL-AI-SPECS.pdf",
      owner: accounts.user1,
      fileHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      offchainURI: "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
      authorizedDIDs: [`did:ethr:13371:${accounts.user2.toLowerCase()}`],
    },
    {
      tokenId: 202,
      serial: "LEX-QUANTUM-ALGO-V2.pdf",
      owner: accounts.admin,
      fileHash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      offchainURI: "ipfs://QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx",
      authorizedDIDs: [`did:ethr:13371:${accounts.user1.toLowerCase()}`],
    },
  ];

  for (const asset of digitalAssets) {
    try {
      const did = `did:ethr:13371:${asset.owner.toLowerCase()}`;
      const txMint = await contract.mintDigitalAsset(
        asset.owner,
        asset.tokenId,
        asset.serial,
        did,
        asset.fileHash,
        asset.offchainURI
      );
      await txMint.wait();
      console.log(`  ✓ Minted Digital Asset #${asset.tokenId} (${asset.serial}) [SHA256: ${asset.fileHash.substring(0, 10)}...]`);

      // Assign access permissions
      for (const targetDID of asset.authorizedDIDs) {
        const txPerm = await contract.grantAssetAccess(asset.tokenId, targetDID, 1); // 1 = READ
        await txPerm.wait();
        console.log(`    ↳ Granted READ access on #${asset.tokenId} to ${targetDID}`);
      }
    } catch (err) {
      console.log(`  ! Digital Minting #${asset.tokenId} failed: ${err.message}`);
    }
  }

  console.log("\n==========================================");
  console.log("✅ V2 CONSORTIUM DEMO SEEDED SUCCESSFULLY!");
  console.log("==========================================");
}

main().catch(console.error);
