module.exports = {
  solidity: {
    compilers: [
      {
        version: "0.8.20",
      },
      {
        version: "0.8.9",
      },
      // Add other versions as needed
    ],
  },
  networks: {
    local: {
      url: 'http://127.0.0.1:8545',
    },
  },
};
