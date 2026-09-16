const hre = require("hardhat");

async function main() {
  const deployment = require("../deployments/localhost.json");
  const [manager] = await hre.ethers.getSigners();

  const contract = await hre.ethers.getContractAt("AssetNFT", deployment.address, manager);

  const tokenId = Math.floor(Math.random() * 100000) + 1000;
  const serialNumber = `BEL-TEST-${tokenId}`;
  const tx = await contract.mint(
    manager.address,
    tokenId,
    serialNumber,
    `did:ethr:31337:${manager.address.toLowerCase()}`
  );
  await tx.wait();

  console.log(`Minted ${serialNumber} (tokenId: ${tokenId})!`);
}

main().catch(console.error);