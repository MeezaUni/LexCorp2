const hre = require('hardhat');

async function main() {
  const deployment = require('../deployments/localhost.json');
  const [deployer] = await hre.ethers.getSigners();
  const contract = await hre.ethers.getContractAt('AssetNFT', deployment.address, deployer);
  const managerRole = await contract.MANAGER_ROLE();
  const managerAddresses = (process.env.MANAGER_ADDRESSES || process.env.ROLE_ADDRESSES || '')
    .split(',')
    .map((address) => address.trim())
    .filter(Boolean);

  if (managerAddresses.length === 0) {
    console.log('No runtime role addresses configured; keeping deployment roles unchanged.');
    return;
  }

  for (const address of managerAddresses) {
    if (!hre.ethers.isAddress(address)) throw new Error(`Invalid manager address: ${address}`);
    if (!(await contract.hasRole(managerRole, address))) {
      const tx = await contract.grantRole(managerRole, address);
      await tx.wait();
      console.log(`Granted MANAGER_ROLE to ${address}`);
    } else {
      console.log(`MANAGER_ROLE already granted to ${address}`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
