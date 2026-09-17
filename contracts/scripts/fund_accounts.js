const hre = require("hardhat");

async function main() {
  const [funder] = await hre.ethers.getSigners();
  const targets = (process.env.FUND_RECIPIENTS || process.env.FUND_RECIPIENT || "")
    .split(",")
    .map((address) => address.trim())
    .filter(Boolean);
  const amount = process.env.FUND_AMOUNT || "10";

  if (targets.length === 0) {
    throw new Error("Set FUND_RECIPIENT or FUND_RECIPIENTS to one or more wallet addresses");
  }

  for (const target of targets) {
    if (!hre.ethers.isAddress(target)) {
      throw new Error(`Invalid funding recipient: ${target}`);
    }
    console.log(`Funding ${target} with ${amount} ETH...`);
    const tx = await funder.sendTransaction({
      to: target,
      value: hre.ethers.parseEther(amount),
    });
    await tx.wait();
    console.log(`Funded! Tx: ${tx.hash}`);
  }
}

main().catch(console.error);
