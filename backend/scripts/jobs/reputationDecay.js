"use strict";

/**
 * Reputation Decay Job — Periyodik İtibar Temizleme Görevi
 *
 * KRİT-13 Fix (v2): Stale DB mirror bağımlılığı kaldırıldı.
 *   ÖNCEKİ: Aday seçimi DB'deki banned_until / consecutive_bans alanlarına dayanıyordu.
 *   Sorun: Bu alanlar stale kalabildiğinde decay adayı yanlış seçiliyor veya kaçıyordu.
 *   ŞİMDİ: DB yalnızca aday havuzu için kullanılıyor; nihai karar on-chain
 *   reputation() verisine göre veriliyor (bannedUntil + consecutiveBans).
 *
 * Bu görev:
 * 1. Her 24 saatte bir çalışır (app.js tarafından tetiklenir)
 * 2. Uygun kullanıcıları bulur
 * 3. Relayer cüzdanı üzerinden on-chain decayReputation() fonksiyonunu çağırır
 * 4. ReputationUpdated eventi eventListener tarafından yakalanır → MongoDB senkronize
 */

const { ethers } = require("ethers");
const User       = require("../models/User");
const logger     = require("../utils/logger");

// [TR] Sadece decayReputation fonksiyonunu çağırmak için minimal ABI
const DECAY_ABI = [
  "function decayReputation(address _wallet)",
  "function reputation(address) view returns (uint256 successfulTrades, uint256 failedDisputes, uint256 bannedUntil, uint256 consecutiveBans)",
];

let relayerWallet = null;
let decayContract = null;

function getRelayer() {
  if (relayerWallet) return relayerWallet;

  const rpcUrl     = process.env.BASE_RPC_URL;
  const privateKey = process.env.RELAYER_PRIVATE_KEY;

  if (!rpcUrl || !privateKey) {
    logger.error("[DecayJob] RELAYER_PRIVATE_KEY veya RPC URL tanımsız. Görev çalıştırılamıyor.");
    return null;
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  relayerWallet  = new ethers.Wallet(privateKey, provider);
  logger.info(`[DecayJob] Relayer cüzdanı yüklendi: ${relayerWallet.address}`);
  return relayerWallet;
}

function getDecayContract() {
  if (decayContract) return decayContract;

  const contractAddress = process.env.ARAF_ESCROW_ADDRESS;
  const relayer         = getRelayer();
  if (!contractAddress || !relayer) return null;

  decayContract = new ethers.Contract(contractAddress, DECAY_ABI, relayer);
  return decayContract;
}

async function runReputationDecay() {
  logger.info("[DecayJob] İtibar temizleme görevi başlatıldı...");

  const contract = getDecayContract();
  if (!contract) return;

  const oneHundredEightyDaysAgo = new Date(Date.now() - 180 * 24 * 3600 * 1000);

  // [TR] Stale mirror riskini azaltmak için adayları geniş havuzdan al, nihai kararı on-chain ver.
  // [EN] Reduce stale mirror risk: pick a broad candidate pool, decide eligibility on-chain.
  const candidates = await User.find({ is_banned: false })
    .select("wallet_address")
    .limit(200);

  const usersToClean = [];
  for (const user of candidates) {
    try {
      const rep = await contract.reputation(user.wallet_address);
      const bannedUntil = Number(rep.bannedUntil);
      const consecutiveBans = Number(rep.consecutiveBans);
      if (!bannedUntil || consecutiveBans <= 0) continue;
      if (new Date(bannedUntil * 1000) < oneHundredEightyDaysAgo) {
        usersToClean.push(user);
      }
      if (usersToClean.length >= 50) break;
    } catch (err) {
      logger.warn(`[DecayJob] reputation() okunamadı: ${user.wallet_address} err=${err.message}`);
    }
  }

  if (usersToClean.length === 0) {
    logger.info("[DecayJob] Temizlenecek itibara sahip kullanıcı bulunamadı.");
    return;
  }

  logger.info(`[DecayJob] ${usersToClean.length} kullanıcının itibarı on-chain'de temizlenecek...`);

  for (const user of usersToClean) {
    try {
      const tx = await contract.decayReputation(user.wallet_address);
      logger.info(
        `[DecayJob] ${user.wallet_address} için on-chain temizleme işlemi gönderildi. Tx: ${tx.hash}`
      );
    } catch (err) {
      // [TR] "180-day clean period not elapsed" gibi kontrat revert mesajlarını logla
      logger.error(
        `[DecayJob] ${user.wallet_address} için itibar temizleme başarısız: ${err.reason || err.message}`
      );
    }
  }
}

module.exports = { runReputationDecay };
