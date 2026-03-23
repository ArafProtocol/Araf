"use strict";

/**
 * Reputation Decay Job — Periyodik İtibar Temizleme Görevi
 *
 * Felsefe: "Kod Kanundur"
 * - Bu görev, "Temiz Sayfa" kuralını uygulamak için on-chain `decayReputation`
 * fonksiyonunu tetikler.
 * - Sorumluluklar nettir:
 * - Off-chain (bu dosya): Kimin itibarının temizlenmesi gerektiğini bulur.
 * - On-chain (kontrat): İtibarı temizler.
 *
 * Çalışma Prensibi:
 * 1. Her 24 saatte bir çalışır (`app.js` tarafından tetiklenir).
 * 2. MongoDB'de, son yasağının üzerinden 180 günden fazla geçmiş ve hala
 * `consecutive_bans` değeri olan kullanıcıları bulur.
 * 3. Her uygun kullanıcı için, bir relayer (yönetici cüzdanı) aracılığıyla
 * on-chain `decayReputation(wallet)` fonksiyonunu çağırır.
 * 4. `ReputationUpdated` eventi, `eventListener` tarafından yakalanır ve
 * MongoDB'deki `reputation_cache` otomatik olarak güncellenir.
 */

const { ethers } = require("ethers");
const User       = require("../models/User");
const logger     = require("../utils/logger");

// Sadece decayReputation fonksiyonunu çağırmak için minimal ABI
const DECAY_ABI = [
  "function decayReputation(address _wallet)",
];

let relayerWallet = null;
let decayContract = null;

function getRelayer() {
  if (relayerWallet) return relayerWallet;

  const rpcUrl = process.env.BASE_RPC_URL;
  const privateKey = process.env.RELAYER_PRIVATE_KEY;

  if (!rpcUrl || !privateKey) {
    logger.error("[DecayJob] RELAYER_PRIVATE_KEY veya RPC URL tanımsız. Görev çalıştırılamıyor.");
    return null;
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  relayerWallet = new ethers.Wallet(privateKey, provider);
  logger.info(`[DecayJob] Relayer cüzdanı yüklendi: ${relayerWallet.address}`);
  return relayerWallet;
}

function getDecayContract() {
  if (decayContract) return decayContract;

  const contractAddress = process.env.ARAF_ESCROW_ADDRESS;
  const relayer = getRelayer();

  if (!contractAddress || !relayer) return null;

  decayContract = new ethers.Contract(contractAddress, DECAY_ABI, relayer);
  return decayContract;
}

async function runReputationDecay() {
  logger.info("[DecayJob] İtibar temizleme görevi başlatıldı...");

  const contract = getDecayContract();
  if (!contract) return;

  // Son yasağının üzerinden 180 gün geçmiş ve hala sıfırlanmamış
  // `consecutive_bans` değeri olan kullanıcıları bul.
  const oneHundredEightyDaysAgo = new Date(Date.now() - 180 * 24 * 3600 * 1000);
  
  const usersToClean = await User.find({
    "banned_until": { $lt: oneHundredEightyDaysAgo },
    "consecutive_bans": { $gt: 0 },
  }).limit(50); // Gas maliyetlerini kontrol altında tutmak için bir seferde en fazla 50 kullanıcı

  if (usersToClean.length === 0) {
    logger.info("[DecayJob] Temizlenecek itibara sahip kullanıcı bulunamadı.");
    return;
  }

  logger.info(`[DecayJob] ${usersToClean.length} kullanıcının itibarı on-chain'de temizlenecek...`);

  for (const user of usersToClean) {
    try {
      const tx = await contract.decayReputation(user.wallet_address);
      logger.info(`[DecayJob] ${user.wallet_address} için on-chain temizleme işlemi gönderildi. Tx: ${tx.hash}`);
    } catch (err) {
      // Hata revert mesajını logla (örn: "180-day clean period not elapsed")
      logger.error(`[DecayJob] ${user.wallet_address} için itibar temizleme başarısız: ${err.reason || err.message}`);
    }
  }
}

module.exports = { runReputationDecay };
