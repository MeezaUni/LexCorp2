const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  const recipient = process.env.FUND_RECIPIENT || "0x95ea9708BCf136d710A4b8e76FE20F895ecA003A";
  const amount = process.env.FUND_AMOUNT || "1000"; // in ETH

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
