require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24", // OpenZeppelin v5 uyumu için yukseltildi
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true, // Karmaşık kontratların derlenmesini kolaylaştırır
      evmVersion: "cancun" // mcopy hatasi için
    },
  },
  networks: {
    // Yerel geliştirme ağı (Codespaces/Local)
    hardhat: {
      chainId: 31337,
    },
    //MetaMask ve Deploy betiği için localhost ağ tanımı
    localhost: {
      url: "http://127.0.0.1:8545", 
      chainId: 31337,
    },
    // public tesnet
    "base-sepolia": {
      url: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
      accounts: process.env.DEPLOYER_PRIVATE_KEY
        ? [process.env.DEPLOYER_PRIVATE_KEY]
        : [],
      chainId: 84532,
    },
    // Base Mainnet Ayarları
    base: {
      url: process.env.BASE_RPC_URL || "https://mainnet.base.org",
      accounts: process.env.DEPLOYER_PRIVATE_KEY
        ? [process.env.DEPLOYER_PRIVATE_KEY]
        : [],
      chainId: 8453,
    },
  },
  etherscan: {
    apiKey: {
      "base-sepolia": process.env.BASESCAN_API_KEY || "",
      base:           process.env.BASESCAN_API_KEY || "",
    },
    customChains: [
      {
        network: "base-sepolia",
        chainId: 84532,
        urls: {
          apiURL:   "https://api-sepolia.basescan.org/api",
          browserURL: "https://sepolia.basescan.org",
        },
      },
      {
        network: "base",
        chainId: 8453,
        urls: {
          apiURL:   "https://api.basescan.org/api",
          browserURL: "https://basescan.org",
        },
      },
    ],
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
    coinmarketcap: process.env.CMC_API_KEY,
  },
  paths: {
    sources:   "./src",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },
};
