const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  // Read deployment data
  const deploymentPath = path.join(__dirname, "../deployments/localhost.json");
  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));

  console.log("Granting MANAGER_ROLE to admin user...");
  console.log("Contract Address:", deployment.address);

  // Admin wallet address
  const adminAddress = "0x95ea9708BCf136d710A4b8e76FE20F895ecA003A";

  // Attach to deployed contract
  const AssetNFT = await hre.ethers.getContractFactory("AssetNFT");
  const contract = AssetNFT.attach(deployment.address);

  // Get MANAGER_ROLE hash
  const MANAGER_ROLE = await contract.MANAGER_ROLE();

  // Check if admin already has the role
  const hasRole = await contract.hasRole(MANAGER_ROLE, adminAddress);

  if (hasRole) {
    console.log(`✓ Admin ${adminAddress} already has MANAGER_ROLE`);
  } else {
    console.log(`Granting MANAGER_ROLE to ${adminAddress}...`);
    const tx = await contract.grantRole(MANAGER_ROLE, adminAddress);
    await tx.wait();
    console.log(`✓ MANAGER_ROLE granted to ${adminAddress}`);
    console.log(`Transaction hash: ${tx.hash}`);
  }

  // Verify
  const verified = await contract.hasRole(MANAGER_ROLE, adminAddress);
  console.log(`\nVerification: Admin has MANAGER_ROLE = ${verified}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
