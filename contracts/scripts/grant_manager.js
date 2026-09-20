const { ethers } = require("hardhat");

async function main() {
  const [admin] = await ethers.getSigners();
  const deployment = require("../deployments/localhost.json");
  const AssetNFT = await ethers.getContractFactory("AssetNFT");
  const contract = AssetNFT.attach(deployment.address);

  const target = "0x31AAc4E1a4DBD3b9792007519c3e8BA6Fa6978f0";
  const MANAGER_ROLE = await contract.MANAGER_ROLE();

  console.log("Admin:", admin.address);
  console.log("Granting MANAGER_ROLE to:", target);

  const tx = await contract.grantRole(MANAGER_ROLE, target);
  await tx.wait();

  console.log("✓ MANAGER_ROLE granted!");
  console.log("Has MANAGER_ROLE:", await contract.hasRole(MANAGER_ROLE, target));
}

main().catch(console.error);