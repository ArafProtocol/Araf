/**
 * ArafEscrow Deploy Script (Network-Aware Testnet + Mainnet Safe Sürüm)
 *
 * Deploy sonrası token support doğrulaması zincir üstünde teyit edilir.
 * Ownership, yalnızca tüm desteklenen tokenlar başarıyla aktif ve doğrulanmışsa devredilir.
 * Network seçimi NODE_ENV ile değil, gerçek Hardhat network adı ve chainId ile yapılır.
 *
 * Kullanım:
 *   npx hardhat run scripts/deploy.js --network localhost
 *   npx hardhat run scripts/deploy.js --network base-sepolia
 *   npx hardhat run scripts/deploy.js --network base
 */
const hre = require("hardhat");
const { ethers } = hre;
const fs = require("fs");
const path = require("path");

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const NETWORK_CONFIG = {
  hardhat: {
    displayName: "Hardhat Local",
    expectedChainId: 31337,
    tokenStrategy: "mock",
    autoWriteFrontendEnv: true,
    frontendAllowedChainId: 31337,
  },
  localhost: {
    displayName: "Localhost",
    expectedChainId: 31337,
    tokenStrategy: "mock",
    autoWriteFrontendEnv: true,
    frontendAllowedChainId: 31337,
  },
  "base-sepolia": {
    displayName: "Base Sepolia",
    expectedChainId: 84532,
    tokenStrategy: "mock-usdt-official-usdc",
    usdcEnv: "BASE_SEPOLIA_USDC_ADDRESS",
    autoWriteFrontendEnv: true,
    frontendAllowedChainId: 84532,
  },
  base: {
    displayName: "Base Mainnet",
    expectedChainId: 8453,
    tokenStrategy: "env",
    usdtEnv: "MAINNET_USDT_ADDRESS",
    usdcEnv: "MAINNET_USDC_ADDRESS",
    autoWriteFrontendEnv: false,
    frontendAllowedChainId: 8453,
  },
};

function requireEnvAddress(name) {
  const value = process.env[name];
  if (!value || value === ZERO_ADDRESS) {
    throw new Error(`❌ ${name} .env'de zorunlu ve geçerli bir adres olmalı.`);
  }
  return ethers.getAddress(value);
}

function resolveDeploymentConfig(networkName) {
  const config = NETWORK_CONFIG[networkName];
  if (!config) {
    throw new Error(
      `❌ Desteklenmeyen network: ${networkName}. Desteklenenler: ${Object.keys(NETWORK_CONFIG).join(", ")}`
    );
  }
  return { networkName, ...config };
}

async function assertExpectedNetwork(config) {
  const providerNetwork = await ethers.provider.getNetwork();
  const actualChainId = Number(providerNetwork.chainId);

  if (actualChainId !== config.expectedChainId) {
    throw new Error(
      `❌ Network güvenlik kontrolü başarısız. Script '${config.networkName}' bekliyordu ` +
      `(chainId=${config.expectedChainId}), provider ise chainId=${actualChainId} döndürdü.`
    );
  }
}

function upsertEnvLine(content, key, value) {
  const line = `${key}=${value}`;
  const pattern = new RegExp(`^${key}=.*$`, "m");
  if (pattern.test(content)) {
    return content.replace(pattern, line);
  }
  const needsTrailingNewline = content.length > 0 && !content.endsWith("\n");
  return `${content}${needsTrailingNewline ? "\n" : ""}${line}\n`;
}

async function deployMockToken(symbol) {
  console.log(`\n⏳ MockERC20 (${symbol}) deploy ediliyor...`);
  const MockERC20 = await ethers.getContractFactory("MockERC20");
  const token = await MockERC20.deploy(`Mock ${symbol}`, symbol, 6);
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();
  console.log(`✅ Mock${symbol} deploy edildi:`, tokenAddress);
  return tokenAddress;
}

async function enableAndVerifySupportedToken(escrow, tokenAddress, symbol) {
  const setTx = await escrow.setSupportedToken(tokenAddress, true);
  await setTx.wait();

  const isSupported = await escrow.supportedTokens(tokenAddress);
  if (!isSupported) {
    throw new Error(`❌ ${symbol} desteklenen token olarak zincir üstünde doğrulanamadı: ${tokenAddress}`);
  }

  console.log(`✅ ${symbol} desteklenen token listesine eklendi ve zincir üstünde doğrulandı:`, tokenAddress);
  return { symbol, address: tokenAddress, isSupported };
}

async function resolveTokenConfig(config) {
  if (config.tokenStrategy === "mock") {
    const usdtAddress = await deployMockToken("USDT");
    const usdcAddress = await deployMockToken("USDC");

    return { usdtAddress, usdcAddress };
  }

  if (config.tokenStrategy === "mock-usdt-official-usdc") {
    const usdtAddress = await deployMockToken("USDT");
    const usdcAddress = requireEnvAddress(config.usdcEnv);

    console.log(`\n⏳ ${config.displayName} resmi USDC adresi ENV'den alındı...`);
    console.log(`✅ ${config.usdcEnv}:`, usdcAddress);

    return { usdtAddress, usdcAddress };
  }

  const usdtAddress = requireEnvAddress(config.usdtEnv);
  const usdcAddress = requireEnvAddress(config.usdcEnv);

  console.log(`\n⏳ ${config.displayName} token adresleri ENV'den alındı...`);
  console.log(`✅ ${config.usdtEnv}:`, usdtAddress);
  console.log(`✅ ${config.usdcEnv}:`, usdcAddress);

  return { usdtAddress, usdcAddress };
}

function syncFrontendEnv({ escrowAddress, usdtAddress, usdcAddress, allowedChainId }) {
  const frontendEnvPath = path.resolve(__dirname, "../../frontend/.env");
  const exampleEnvPath = path.resolve(__dirname, "../../frontend/.env.example");

  if (!fs.existsSync(frontendEnvPath) && fs.existsSync(exampleEnvPath)) {
    fs.copyFileSync(exampleEnvPath, frontendEnvPath);
    console.log("📝 .env.example'dan yeni frontend/.env oluşturuldu.");
  }

  if (!fs.existsSync(frontendEnvPath)) {
    console.log("ℹ️ frontend/.env bulunamadı; auto-write atlandı.");
    return;
  }

  let envContent = fs.readFileSync(frontendEnvPath, "utf8");

  const codespaceName = process.env.CODESPACE_NAME;
  if (codespaceName) {
    const apiUrl = `https://${codespaceName}-4000.app.github.dev`;
    envContent = upsertEnvLine(envContent, "VITE_API_URL", apiUrl);
  }

  envContent = upsertEnvLine(envContent, "VITE_ESCROW_ADDRESS", escrowAddress);
  envContent = upsertEnvLine(envContent, "VITE_USDT_ADDRESS", usdtAddress);
  envContent = upsertEnvLine(envContent, "VITE_USDC_ADDRESS", usdcAddress);
  envContent = upsertEnvLine(envContent, "VITE_ALLOWED_CHAIN_ID", String(allowedChainId));

  fs.writeFileSync(frontendEnvPath, envContent);
  console.log("✅ frontend/.env dosyası deploy çıktısına göre güncellendi.");
}

async function main() {
  const config = resolveDeploymentConfig(hre.network.name);
  await assertExpectedNetwork(config);

  const [deployer] = await ethers.getSigners();
  console.log("🚀 Deploy eden cüzdan:", deployer.address);
  console.log("🌍 Network:", config.displayName, `(${config.networkName})`);
  console.log("🔗 Beklenen chainId:", config.expectedChainId);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("💰 Bakiye:", ethers.formatEther(balance), "ETH\n");

  // ── Treasury & Owner ──────────────────────────────────────────────────────
  const treasuryAddress = requireEnvAddress("TREASURY_ADDRESS");
  console.log("🏦 Treasury & Son Owner adresi:", treasuryAddress);

  // ── 1. Escrow Kontratı Deploy ─────────────────────────────────────────────
  console.log("\n⏳ ArafEscrow deploy ediliyor...");
  const ArafEscrow = await ethers.getContractFactory("ArafEscrow");
  const escrow = await ArafEscrow.deploy(treasuryAddress);
  await escrow.waitForDeployment();

  const address = await escrow.getAddress();
  console.log("✅ ArafEscrow deploy edildi:", address);

  // ── ABI Kopyalama ─────────────────────────────────────────────────────────
  try {
    const artifactPath = path.resolve(__dirname, "../artifacts/src/ArafEscrow.sol/ArafEscrow.json");
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    const abiDestDir = path.resolve(__dirname, "../../frontend/src/abi");
    const abiDestPath = path.join(abiDestDir, "ArafEscrow.json");

    fs.mkdirSync(abiDestDir, { recursive: true });
    fs.writeFileSync(abiDestPath, JSON.stringify(artifact.abi, null, 2));
    console.log("✅ ABI frontend'e kopyalandı.");
  } catch (err) {
    console.warn("⚠ ABI kopyalanamadı (Önemli Değil, Hardcoded ABI kullanıyoruz):", err.message);
  }

  // ── 2. Supported Token Kurulumu (Ownership devrinden ÖNCE) ───────────────
  const { usdtAddress, usdcAddress } = await resolveTokenConfig(config);
  const tokenSupportChecks = [];

  tokenSupportChecks.push(await enableAndVerifySupportedToken(escrow, usdtAddress, "USDT"));
  tokenSupportChecks.push(await enableAndVerifySupportedToken(escrow, usdcAddress, "USDC"));

  const allTokenSupportVerified = tokenSupportChecks.every((check) => check.isSupported);
  if (!allTokenSupportVerified) {
    throw new Error("❌ Token support doğrulaması tamamlanmadı; ownership devri iptal edildi.");
  }

  // ── 3. Ownership Devri ────────────────────────────────────────────────────
  console.log("\n🔒 Ownership devrediliyor →", treasuryAddress);
  const tx = await escrow.transferOwnership(treasuryAddress);
  await tx.wait();
  console.log("✅ Ownership başarıyla devredildi!");

  // ── 4. FE .env Auto-write ─────────────────────────────────────────────────
  if (config.autoWriteFrontendEnv) {
    syncFrontendEnv({
      escrowAddress: address,
      usdtAddress,
      usdcAddress,
      allowedChainId: config.frontendAllowedChainId,
    });
  } else {
    console.log(`ℹ️ ${config.displayName} için frontend/.env auto-write atlandı.`);
  }

  // ── 5. Sonuçlar ve completion koşulu ──────────────────────────────────────
  if (!allTokenSupportVerified) {
    throw new Error("❌ deployment complete koşulu sağlanmadı: token support doğrulaması başarısız.");
  }

  console.log("\n🎉 DEPLOYMENT COMPLETE (token support zincir üstünde doğrulandı) 🎉");
  console.log("--------------------------------------------------");
  console.log(`VITE_ESCROW_ADDRESS=${address}`);
  console.log(`VITE_USDT_ADDRESS=${usdtAddress}`);
  console.log(`VITE_USDC_ADDRESS=${usdcAddress}`);
  console.log(`VITE_ALLOWED_CHAIN_ID=${config.frontendAllowedChainId}`);
  console.log("--------------------------------------------------");
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { resolveDeploymentConfig };
