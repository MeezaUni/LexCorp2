const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  const recipient = process.env.FUND_RECIPIENT;
  const amount = process.env.FUND_AMOUNT || "10"; // in ETH

  if (!recipient || !hre.ethers.isAddress(recipient)) {
    throw new Error("Set FUND_RECIPIENT to a valid wallet address");
  }

  console.log(`Funding ${recipient} with ${amount} ETH from ${deployer.address}...`);

  const tx = await deployer.sendTransaction({
    to: recipient,
    value: hre.ethers.parseEther(amount)
  });

  await tx.wait();
  console.log(`✓ Funded! Tx: ${tx.hash}`);

  // Check balance
  const balance = await hre.ethers.provider.getBalance(recipient);
  console.log(`New balance: ${hre.ethers.formatEther(balance)} ETH`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
