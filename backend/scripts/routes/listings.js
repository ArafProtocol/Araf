"use strict";

/**
 * Listings Route — Pazar Yeri CRUD
 **/

const express = require("express");
const Joi     = require("joi");
const router  = express.Router();

const { requireAuth }                                = require("../middleware/auth");
const { listingsReadLimiter, listingsWriteLimiter }  = require("../middleware/rateLimiter");
const { Listing, Trade }                             = require("../models/Trade");
const logger                                         = require("../utils/logger");
const { getConfig }                                  = require("../services/protocolConfig");

// On-chain tier doğrulama için ethers ve kontrat ABI
const { ethers } = require("ethers");
const REPUTATION_ABI = [
  "function getReputation(address _wallet) view returns (uint256 successful, uint256 failed, uint256 bannedUntil, uint256 consecutiveBans, uint8 effectiveTier)",
];

// RPC Provider Cache Mekanizması
let _cachedListingsProvider = null;
function _getListingsProvider() {
  if (!_cachedListingsProvider) {
    _cachedListingsProvider = new ethers.JsonRpcProvider(process.env.BASE_RPC_URL);
  }
  return _cachedListingsProvider;
}

/**
 * Kullanıcının on-chain efektif tier'ını sorgular.
 * Kontrat view fonksiyonu çağrısı — gas ücreti yok.
 */
async function _getOnChainEffectiveTier(walletAddress) {
  const contractAddress = process.env.ARAF_ESCROW_ADDRESS;

  if (!process.env.BASE_RPC_URL || !contractAddress || contractAddress === "0x0000000000000000000000000000000000000000") {
    // Development'ta kontrat yoksa → tier kontrolü atla, 4 (en yüksek) döndür
    logger.warn("[Listings] On-chain tier kontrolü atlanıyor — kontrat adresi tanımsız (development).");
    return 4;
  }

  try {
    const provider = _getListingsProvider(); // Cache kullanılıyor
    const contract = new ethers.Contract(contractAddress, REPUTATION_ABI, provider);
    const rep = await contract.getReputation(walletAddress);
    return Number(rep.effectiveTier);
  } catch (err) {
    logger.error(`[Listings] On-chain tier sorgusu başarısız: ${err.message}. Güvenli varsayılan (0) kullanılıyor.`);
    return 0; // Hata durumunda en kısıtlayıcı değeri döndür — güvenlik öncelikli
  }
}

// ─── GET /api/listings/config ─────────────────────────────────────────────────
// Frontend bond oranlarını buradan okur.
router.get("/config", async (req, res, next) => {
  try {
    const config = getConfig();
    return res.json({ bondMap: config.bondMap });
  } catch (err) {
    if (err.code === 'CONFIG_UNAVAILABLE') {
      return res.status(503).json({ error: err.message });
    }
    next(err);
  }
});

// ─── GET /api/listings ────────────────────────────────────────────────────────
router.get("/", listingsReadLimiter, async (req, res, next) => {
  try {
    const schema = Joi.object({
      fiat:   Joi.string().valid("TRY", "USD", "EUR").optional(),
      amount: Joi.number().positive().optional(),
      tier:   Joi.number().valid(0, 1, 2, 3, 4).optional(),
      page:   Joi.number().integer().min(1).default(1),
      limit:  Joi.number().integer().min(1).max(50).default(20),
    });

    const { error, value } = schema.validate(req.query);
    if (error) return res.status(400).json({ error: error.message });

    const filter = { status: "OPEN" };
    if (value.fiat)   filter.fiat_currency = value.fiat;
    if (value.tier !== undefined) filter["tier_rules.required_tier"] = value.tier;
    if (value.amount) {
      filter["limits.min"] = { $lte: value.amount };
      filter["limits.max"] = { $gte: value.amount };
    }

    const skip     = (value.page - 1) * value.limit;
    const listings = await Listing.find(filter)
      .sort({ exchange_rate: 1 })
      .skip(skip)
      .limit(value.limit)
      .lean();

    const total = await Listing.countDocuments(filter);
    return res.json({ listings, total, page: value.page, limit: value.limit });
  } catch (err) { next(err); }
});

// ─── POST /api/listings ───────────────────────────────────────────────────────
router.post("/", requireAuth, listingsWriteLimiter, async (req, res, next) => {
  try {
    const schema = Joi.object({
      crypto_asset:      Joi.string().valid("USDT", "USDC").required(),
      fiat_currency:     Joi.string().valid("TRY", "USD", "EUR").required(),
      exchange_rate:     Joi.number().positive().required(),
      limits:            Joi.object({
        min: Joi.number().positive().required(),
        max: Joi.number().positive().required(),
      }).required(),
      tier:              Joi.number().valid(0, 1, 2, 3, 4).required(),
      token_address:     Joi.string().pattern(/^0x[a-fA-F0-9]{40}$/).required(),
      onchain_escrow_id: Joi.number().optional(),
    });

    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    if (value.limits.max <= value.limits.min) {
      return res.status(400).json({ error: "limits.max, limits.min'den büyük olmalı" });
    }

    // Tier başına kripto limiti backend'de de kontrol ediliyor.
    // Kaynak: ArafEscrow.sol sabitleri (TIER_MAX_AMOUNT_TIER0..3)
    // NOT: limits.max fiat cinsinden gelir (örn: 49500 TRY)
    // exchange_rate = 1 USDT karşılığı fiat tutarı. limits.max / exchange_rate = max USDT.
    const TIER_MAX_CRYPTO = { 0: 150, 1: 1500, 2: 7500, 3: 30000 };
    const tierMax = TIER_MAX_CRYPTO[value.tier];
    if (tierMax !== undefined) {
      const cryptoEquivalent = value.limits.max / value.exchange_rate;
      if (cryptoEquivalent > tierMax) {
        return res.status(400).json({
          error: `Tier ${value.tier} için maksimum kripto limiti ${tierMax} USDT/USDC. ` +
                 `Max limit kripto karşılığı: ${cryptoEquivalent.toFixed(2)}`,
        });
      }
    }

    //  Kontratın view fonksiyonuyla kullanıcının efektif tier'ını doğrula.
    const effectiveTier = await _getOnChainEffectiveTier(req.wallet);
    if (value.tier > effectiveTier) {
      logger.warn(`[Listings] Tier reddedildi: wallet=${req.wallet} istenen=${value.tier} efektif=${effectiveTier}`);
      return res.status(403).json({
        error: `İtibarınız Tier ${value.tier} ilanı için yeterli değil. Efektif tier'ınız: ${effectiveTier}`,
      });
    }

    const config = getConfig();
    const bonds = config.bondMap[value.tier];

    const listing = await Listing.create({
      maker_address:     req.wallet,
      crypto_asset:      value.crypto_asset,
      fiat_currency:     value.fiat_currency,
      exchange_rate:     value.exchange_rate,
      limits:            value.limits,
      tier_rules: {
        required_tier:  value.tier,
        maker_bond_pct: bonds.maker,
        taker_bond_pct: bonds.taker,
      },
      token_address:     value.token_address,
      onchain_escrow_id: value.onchain_escrow_id || null,
    });

    logger.info(`[Listings] Yeni ilan: maker=${req.wallet} tier=${value.tier} asset=${value.crypto_asset}`);
    return res.status(201).json({ listing });
  } catch (err) { next(err); }
});

// ─── DELETE /api/listings/:id ─────────────────────────────────────────────────
router.delete("/:id", requireAuth, async (req, res, next) => {
  try {
    if (!/^[a-fA-F0-9]{24}$/.test(req.params.id)) {
      return res.status(400).json({ error: "Geçersiz ilan ID formatı" });
    }

    const listing = await Listing.findById(req.params.id);
    if (!listing) return res.status(404).json({ error: "İlan bulunamadı" });

    if (listing.maker_address !== req.wallet) {
      logger.warn(`[Listings] Yetkisiz silme: caller=${req.wallet} maker=${listing.maker_address}`);
      return res.status(403).json({ error: "Bu ilan sana ait değil" });
    }

    if (listing.onchain_escrow_id) {
      const activeTrade = await Trade.findOne({ onchain_escrow_id: listing.onchain_escrow_id });
      if (activeTrade && activeTrade.status !== "OPEN") {
        logger.warn(`[Listings] Aktif işlem varken silme engellendi: id=${req.params.id} trade_status=${activeTrade.status}`);
        return res.status(409).json({ error: "Bu ilana bağlı aktif bir işlem varken ilan silinemez." });
      }
    }

    if (listing.status === "DELETED") {
      return res.status(409).json({ error: "İlan zaten silinmiş" });
    }

    listing.status = "DELETED";
    await listing.save();

    logger.info(`[Listings] Silindi: id=${req.params.id} maker=${req.wallet}`);
    return res.json({ success: true });
  } catch (err) { next(err); }
});

module.exports = router;
