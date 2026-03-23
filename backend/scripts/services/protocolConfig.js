"use strict";

/**
 * Protocol Config Service — On-Chain Parametre Yükleyici
 *
 * Felsefe: "Kod Kanundur"
 *   - Protokolün temel ekonomik parametreleri (teminatlar, süreler vb.)
 *     backend'de hard-code EDİLMEZ.
 *   - Bu servis, sunucu başlangıcında ArafEscrow kontratına bağlanır,
 *     tüm public constant'ları okur ve bunları bir yapılandırma nesnesi
 *     olarak belleğe yükler.
 *   - Bu sayede, kontrat her zaman "gerçeğin tek kaynağı" olur.
 *     Kontrat güncellendiğinde, backend otomatik olarak yeni kuralları benimser.
 *
 * Fix (felsefeye sadık): Kontrat adresi tanımsızsa hard-code fallback YOK.
 *   Config yüklenemezse protocolConfig = null olarak kalır.
 *   getConfig() çağıran endpoint'ler CONFIG_UNAVAILABLE hatası alır ve 503 döner.
 *   Bu, geliştirici hatalarını erkenden yakalar ve "hayalet config" riskini önler.
 *
 * Fix: Redis cache TTL ortama göre ayarlandı.
 *   Production: 7 gün (bond değerleri nadiren değişir)
 *   Development/Testnet: 1 saat (sık deploy döngüsü için)
 */

const { ethers } = require("ethers");
const logger     = require("../utils/logger");
const { getRedisClient } = require("../config/redis");

const CONFIG_CACHE_KEY = "cache:protocol_config:v1";

// Ortama göre cache TTL
const CONFIG_CACHE_TTL = process.env.NODE_ENV === "production"
  ? 7 * 24 * 3600  // Production: 7 gün
  : 3600;          // Development/Testnet: 1 saat

// Sadece public constant'ları okumak için minimal ABI
const CONFIG_ABI = [
  "function MAKER_BOND_TIER0_BPS() view returns (uint256)",
  "function MAKER_BOND_TIER1_BPS() view returns (uint256)",
  "function MAKER_BOND_TIER2_BPS() view returns (uint256)",
  "function MAKER_BOND_TIER3_BPS() view returns (uint256)",
  "function MAKER_BOND_TIER4_BPS() view returns (uint256)",
  "function TAKER_BOND_TIER0_BPS() view returns (uint256)",
  "function TAKER_BOND_TIER1_BPS() view returns (uint256)",
  "function TAKER_BOND_TIER2_BPS() view returns (uint256)",
  "function TAKER_BOND_TIER3_BPS() view returns (uint256)",
  "function TAKER_BOND_TIER4_BPS() view returns (uint256)",
];

let protocolConfig = null;

async function loadProtocolConfig() {
  // Önce Redis önbelleğini kontrol et
  const redis = getRedisClient();
  try {
    const cachedConfig = await redis.get(CONFIG_CACHE_KEY);
    if (cachedConfig) {
      protocolConfig = JSON.parse(cachedConfig);
      logger.info("[Config] Protokol parametreleri Redis önbelleğinden yüklendi.");
      return protocolConfig;
    }
  } catch (err) {
    logger.warn(`[Config] Redis önbellek okuma hatası, devam ediliyor: ${err.message}`);
  }

  const rpcUrl          = process.env.BASE_RPC_URL;
  const contractAddress = process.env.ARAF_ESCROW_ADDRESS;

  // Bu, geliştiriciyi "önce deploy et" adımını atlamaktan korur.
  if (!contractAddress || contractAddress === "0x0000000000000000000000000000000000000000") {
    logger.warn(
      "[Config] ⚠ ARAF_ESCROW_ADDRESS tanımsız — server CONFIG_UNAVAILABLE modunda başlıyor.\n" +
      "[Config]   Bond doğrulaması gerektiren tüm endpoint'ler 503 döner.\n" +
      "[Config]   Çözüm: npx hardhat node && npx hardhat run scripts/deploy.js --network localhost\n" +
      "[Config]   Ardından .env dosyasına ARAF_ESCROW_ADDRESS adresini ekle."
    );
    protocolConfig = null;
    return null;
  }

  if (!rpcUrl) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("[Config] CRITICAL: BASE_RPC_URL production'da zorunludur.");
    }
    logger.warn(
      "[Config] ⚠ BASE_RPC_URL tanımsız — server CONFIG_UNAVAILABLE modunda başlıyor.\n" +
      "[Config]   Çözüm: .env dosyasına BASE_RPC_URL ekle."
    );
    protocolConfig = null;
    return null;
  }

  logger.info("[Config] Protokol parametreleri on-chain'den yükleniyor...");

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(contractAddress, CONFIG_ABI, provider);

  const bpsToPercent = (bps) => Number(bps) / 100;

  const [
    makerT0, makerT1, makerT2, makerT3, makerT4,
    takerT0, takerT1, takerT2, takerT3, takerT4,
  ] = await Promise.all([
    contract.MAKER_BOND_TIER0_BPS(), contract.MAKER_BOND_TIER1_BPS(),
    contract.MAKER_BOND_TIER2_BPS(), contract.MAKER_BOND_TIER3_BPS(),
    contract.MAKER_BOND_TIER4_BPS(),
    contract.TAKER_BOND_TIER0_BPS(), contract.TAKER_BOND_TIER1_BPS(),
    contract.TAKER_BOND_TIER2_BPS(), contract.TAKER_BOND_TIER3_BPS(),
    contract.TAKER_BOND_TIER4_BPS(),
  ]);

  protocolConfig = {
    bondMap: {
      0: { maker: bpsToPercent(makerT0), taker: bpsToPercent(takerT0), makerBps: Number(makerT0), takerBps: Number(takerT0) },
      1: { maker: bpsToPercent(makerT1), taker: bpsToPercent(takerT1), makerBps: Number(makerT1), takerBps: Number(takerT1) },
      2: { maker: bpsToPercent(makerT2), taker: bpsToPercent(takerT2), makerBps: Number(makerT2), takerBps: Number(takerT2) },
      3: { maker: bpsToPercent(makerT3), taker: bpsToPercent(takerT3), makerBps: Number(makerT3), takerBps: Number(takerT3) },
      4: { maker: bpsToPercent(makerT4), taker: bpsToPercent(takerT4), makerBps: Number(makerT4), takerBps: Number(takerT4) },
    },
  };

  try {
    await redis.setEx(CONFIG_CACHE_KEY, CONFIG_CACHE_TTL, JSON.stringify(protocolConfig));
    logger.info(
      `[Config] On-chain parametreler başarıyla yüklendi ve Redis'e kaydedildi (TTL: ${CONFIG_CACHE_TTL}s).`
    );
  } catch (err) {
    logger.warn(`[Config] Redis yazma hatası (config yüklendi ama cache'lenemedi): ${err.message}`);
  }

  return protocolConfig;
}

/**
 * Yüklenmiş config'i döner.
 * Config yoksa CONFIG_UNAVAILABLE hatasıyla fırlatır — çağıran route 503 dönmeli.
 *
 * Kullanım (route'larda):
 *   try {
 *     const config = getConfig();
 *   } catch (err) {
 *     if (err.code === 'CONFIG_UNAVAILABLE') return res.status(503).json({ error: err.message });
 *     throw err;
 *   }
 */
const getConfig = () => {
  if (!protocolConfig) {
    const err = new Error(
      "Protocol config not loaded. " +
      "Ensure ARAF_ESCROW_ADDRESS and BASE_RPC_URL are set, then restart the server."
    );
    err.code = "CONFIG_UNAVAILABLE";
    throw err;
  }
  return protocolConfig;
};

module.exports = { loadProtocolConfig, getConfig };
