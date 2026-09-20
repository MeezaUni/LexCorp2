const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying AssetNFT with account:", deployer.address);

  const AssetNFT = await hre.ethers.getContractFactory("AssetNFT");
  const assetNFT = await AssetNFT.deploy();
  await assetNFT.waitForDeployment();

  const address = await assetNFT.getAddress();
  console.log("AssetNFT deployed to:", address);

  // Grant MANAGER_ROLE to deployer automatically
  const managerRole = await assetNFT.MANAGER_ROLE();
  const grantTx = await assetNFT.grantRole(managerRole, deployer.address);
  await grantTx.wait();
  console.log("Granted MANAGER_ROLE to deployer:", deployer.address);

  // Get the ABI - handle different ethers versions
  let abi;
  try {
    abi = assetNFT.interface.formatJson();
  } catch {
    abi = assetNFT.interface.format(hre.ethers.utils.FormatTypes.json);
  }

  const deploymentData = {
    address: address,
    abi: typeof abi === "string" ? JSON.parse(abi) : abi,
  };

  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  fs.writeFileSync(
    path.join(deploymentsDir, "localhost.json"),
    JSON.stringify(deploymentData, null, 2)
  );
  console.log("Deployment data saved to deployments/localhost.json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });