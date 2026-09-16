const hre = require("hardhat");

async function main() {
  const deployment = require("../deployments/localhost.json");
  const [deployer] = await hre.ethers.getSigners();

  const contract = await hre.ethers.getContractAt("AssetNFT", deployment.address, deployer);

  const MANAGER_ROLE = await contract.MANAGER_ROLE();

  // Grant to Admin
  const adminAddr = "0x31aac4e1a4dbd3b9792007519c3e8ba6fa6978f0";
  console.log(`Granting MANAGER_ROLE to ${adminAddr}...`);
  const tx = await contract.grantRole(MANAGER_ROLE, adminAddr);
  await tx.wait();

  console.log("MANAGER_ROLE granted successfully to Admin!");
}

main().catch(console.error);
