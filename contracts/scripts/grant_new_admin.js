const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  // 1. Load the locally deployed contract address
  const deploymentPath = path.join(__dirname, "../deployments/localhost.json");
  const deploymentData = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const contractAddress = deploymentData.address;

  // 2. The default admin private key established during local network configuration
  // Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  const defaultAdminKey =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  const defaultAdminWallet = new ethers.Wallet(defaultAdminKey, ethers.provider);

  // 3. Generate a brand new Wallet
  const newAdminWallet = ethers.Wallet.createRandom();
  console.log("\n=============================================");
  console.log("🆕 BRAND NEW ADMIN WALLET GENERATED locally");
  console.log("=============================================");
  console.log("Address:", newAdminWallet.address);
  console.log("Private Key:", newAdminWallet.privateKey);
  console.log("Mnemonic:", newAdminWallet.mnemonic.phrase);
  console.log("=============================================\n");

  // 4. Connect to the AssetNFT contract as the Default Admin
  const AssetNFT = await ethers.getContractAt("AssetNFT", contractAddress,
  defaultAdminWallet);

  // 5. Calculate Role Identifiers
  // DEFAULT_ADMIN_ROLE is purely 0x0000...
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
  // MANAGER_ROLE is keccak256("MANAGER_ROLE")
  const MANAGER_ROLE = ethers.id("MANAGER_ROLE");

  // 6. Grant the Roles
  console.log(`Granting DEFAULT_ADMIN_ROLE to ${newAdminWallet.address}...`);
  let tx1 = await AssetNFT.grantRole(DEFAULT_ADMIN_ROLE, newAdminWallet.address);
  await tx1.wait();

  console.log(`Granting MANAGER_ROLE to ${newAdminWallet.address}...`);
  let tx2 = await AssetNFT.grantRole(MANAGER_ROLE, newAdminWallet.address);
  await tx2.wait();

  // 7. Fund the new wallet with some local ETH so it can perform transactions
  console.log(`Funding the new admin wallet with 10 local ETH...`);
  let tx3 = await defaultAdminWallet.sendTransaction({
    to: newAdminWallet.address,
    value: ethers.parseEther("10.0")
  });
  await tx3.wait();

  console.log("\n✅ Success! The new wallet is now an on-chain Admin and is fully funded.");
  console.log("You can import its private key or mnemonic into the LexCorp frontend modal.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });