async function main() {
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);
    console.log("Account balance:", (await deployer.getBalance()).toString());

    const Token = await ethers.getContractFactory("MyToken");
    const token = await Token.deploy("MyToken", "MTK");

    await token.deployed();
    console.log("Token deployed to:", token.address);
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });

