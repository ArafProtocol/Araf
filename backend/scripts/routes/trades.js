"use strict";

const express = require("express");
const Joi     = require("joi");
const crypto  = require("crypto");
const router  = express.Router();

const { requireAuth, requireSessionWalletMatch } = require("../middleware/auth");
const { tradesLimiter } = require("../middleware/rateLimiter");
const { Trade }         = require("../models/Trade");
const logger            = require("../utils/logger");

const SAFE_TRADE_PROJECTION = [
  "_id",
  "onchain_escrow_id",
  "listing_id",
  "maker_address",
  "taker_address",
  "status",
  "tier",
  "financials",
  "timers",
  "cancel_proposal.proposed_by",
  "cancel_proposal.proposed_at",
  "cancel_proposal.approved_by",
  "cancel_proposal.deadline",
  "cancel_proposal.maker_signed",
  "cancel_proposal.taker_signed",
  "evidence.ipfs_receipt_hash",
  "evidence.receipt_timestamp",
  "chargeback_ack.acknowledged",
  "chargeback_ack.acknowledged_at",
].join(" ");

/**
 * KRİT-12 Fix: EIP-712 Deadline Ezilmesi (Deadlock) Kapatıldı.
 *   ÖNCEKİ: propose-cancel endpoint'i gelen deadline değerini doğrudan
 *   trade.cancel_proposal.deadline'a yazıyordu.
 *   Kötü niyetli Taker farklı deadline ile endpoint'i tekrar çağırarak
 *   Maker'ın imzasını geçersiz kılıyor ve iptal sürecini sonsuza kilitleyebiliyordu.
 *   ŞİMDİ: Deadline ilk teklif sırasında bir kez set ediliyor.
 *   İkinci tarafın gönderdiği deadline, ilk teklifle EŞLEŞMELİ — farklıysa ret.
 *
 * ORTA-12 Fix: Proxy Arkasında Geçersiz IP Hash Kapatıldı.
 *   ÖNCEKİ: req.ip doğrudan kullanılıyordu. Proxy arkasında Load Balancer IP'si
 *   geliyordu — tüm kullanıcılar için aynı ip_hash → hukuki kanıt geçersiz.
 *   ŞİMDİ: X-Forwarded-For header kontrolü eklendi. app.js'de trust proxy aktif
 *   olduğunda (KRİT-05 Fix) req.ip zaten doğru IP'yi döndürür.
 *   Ekstra güvence için gerçek IP belirleme fonksiyonu eklendi.
 *
 * ORTA-14 Fix: Chargeback-Ack Race Condition (Idempotency Bypass) Kapatıldı.
 *   ÖNCEKİ: findOne kontrolü + ayrı save() → aynı anda iki istek gelirse
 *   her ikisi de acknowledged: false okuyabilir ve iki kayıt yazılabilirdi.
 *   ŞİMDİ: findOneAndUpdate tek atomik sorguyla hem kontrol hem güncelleme yapıyor.
 *   acknowledged: false koşulu filtreye eklendi — sadece ilk istek başarılı olur.
 */

// ─── GET /api/trades/my ───────────────────────────────────────────────────────
router.get("/my", requireAuth, tradesLimiter, async (req, res, next) => {
  try {
    const trades = await Trade.find({
      $or: [{ maker_address: req.wallet }, { taker_address: req.wallet }],
      status: { $nin: ["RESOLVED", "CANCELED", "BURNED"] },
    }).select(SAFE_TRADE_PROJECTION).sort({ created_at: -1 }).lean();
    return res.json({ trades });
  } catch (err) { next(err); }
});

// ─── GET /api/trades/history ──────────────────────────────────────────────────
router.get("/history", requireAuth, tradesLimiter, async (req, res, next) => {
  try {
    const schema = Joi.object({
      page:  Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(50).default(10),
    });
    const { error, value } = schema.validate(req.query);
    if (error) return res.status(400).json({ error: error.message });

    const filter = {
      $or:    [{ maker_address: req.wallet }, { taker_address: req.wallet }],
      status: { $in: ["RESOLVED", "CANCELED", "BURNED"] },
    };
    const skip   = (value.page - 1) * value.limit;
    const trades = await Trade.find(filter)
      .select(SAFE_TRADE_PROJECTION)
      .sort({ "timers.resolved_at": -1 })
      .skip(skip).limit(value.limit).lean();
    const total  = await Trade.countDocuments(filter);

    return res.json({ trades, total, page: value.page, limit: value.limit });
  } catch (err) { next(err); }
});

// ─── GET /api/trades/by-escrow/:onchainId ────────────────────────────────────
// [TR] GET /:id'den ÖNCE tanımlanmalı — yoksa Express yanlış route'a gider
router.get("/by-escrow/:onchainId", requireAuth, tradesLimiter, async (req, res, next) => {
  try {
    const onchainId = Number(req.params.onchainId);
    if (!Number.isInteger(onchainId) || onchainId <= 0) {
      return res.status(400).json({ error: "Geçersiz on-chain ID formatı." });
    }
    const trade = await Trade.findOne({ onchain_escrow_id: onchainId })
      .select("_id onchain_escrow_id maker_address taker_address status")
      .lean();
    if (!trade) return res.status(404).json({ error: "Trade bulunamadı." });
    if (trade.maker_address !== req.wallet && trade.taker_address !== req.wallet) {
      return res.status(403).json({ error: "Erişim reddedildi." });
    }
    return res.json({ trade });
  } catch (err) { next(err); }
});

// ─── GET /api/trades/:id ──────────────────────────────────────────────────────
router.get("/:id", requireAuth, tradesLimiter, async (req, res, next) => {
  try {
    const trade = await Trade.findById(req.params.id)
      .select(SAFE_TRADE_PROJECTION)
      .lean();
    if (!trade) return res.status(404).json({ error: "İşlem bulunamadı." });
    if (trade.maker_address !== req.wallet && trade.taker_address !== req.wallet) {
      return res.status(403).json({ error: "Erişim reddedildi." });
    }
    return res.json({ trade });
  } catch (err) { next(err); }
});

// ─── POST /api/trades/propose-cancel ─────────────────────────────────────────
router.post("/propose-cancel", requireAuth, requireSessionWalletMatch, tradesLimiter, async (req, res, next) => {
  try {
    const schema = Joi.object({
      tradeId:   Joi.string().length(24).hex().required(),
      signature: Joi.string().pattern(/^0x[a-fA-F0-9]+$/).required(),
      deadline:  Joi.number().integer().required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    // [TR] Deadline sunucu tarafında da doğrulanıyor
    const now = Math.floor(Date.now() / 1000);
    const MAX_DEADLINE_SECONDS = 7 * 24 * 60 * 60;
    if (value.deadline <= now) {
      return res.status(400).json({ error: "Deadline geçmiş bir zamana ayarlanamaz." });
    }
    if (value.deadline > now + MAX_DEADLINE_SECONDS) {
      return res.status(400).json({ error: "Deadline çok uzak. Maksimum 7 gün sonrası kabul edilir." });
    }

    const trade = await Trade.findById(value.tradeId);
    if (!trade) return res.status(404).json({ error: "İşlem bulunamadı." });

    const isMaker = trade.maker_address === req.wallet;
    const isTaker = trade.taker_address === req.wallet;
    if (!isMaker && !isTaker) return res.status(403).json({ error: "Bu işlemin tarafı değilsin." });

    // KRİT-12 Fix: Deadline sabitleme — ilk teklifte set et, sonra EŞLEŞMESİ gerekiyor
    const existingDeadline = trade.cancel_proposal.deadline;
    if (existingDeadline) {
      // [TR] İkinci taraf farklı bir deadline ile gelirse ret
      const existingTs = Math.floor(new Date(existingDeadline).getTime() / 1000);
      if (Math.abs(existingTs - value.deadline) > 60) { // 60sn tolerans (blok zaman farkı)
        logger.warn(
          `[Trades] Deadline manipülasyon denemesi: ` +
          `mevcut=${existingTs} gelen=${value.deadline} wallet=${req.wallet}`
        );
        return res.status(400).json({
          error: "Deadline mevcut teklifle uyuşmuyor. Manipülasyon girişimi tespit edildi.",
        });
      }
    } else {
      // [TR] İlk teklif — deadline'ı set et
      trade.cancel_proposal.deadline = new Date(value.deadline * 1000);
    }

    // ORTA-01 Fix: proposed_by sadece ilk teklifte set ediliyor
    if (!trade.cancel_proposal.proposed_by) {
      trade.cancel_proposal.proposed_by = req.wallet;
    }
    // [TR] İkinci tarafın onayı ayrı alanda tutuluyor (audit trail korunuyor)
    if (!trade.cancel_proposal.approved_by && trade.cancel_proposal.proposed_by !== req.wallet) {
      trade.cancel_proposal.approved_by = req.wallet;
    }

    if (isMaker) {
      trade.cancel_proposal.maker_signed    = true;
      trade.cancel_proposal.maker_signature = value.signature;
    } else {
      trade.cancel_proposal.taker_signed    = true;
      trade.cancel_proposal.taker_signature = value.signature;
    }

    await trade.save();

    const bothSigned = trade.cancel_proposal.maker_signed && trade.cancel_proposal.taker_signed;
    return res.json({
      success: true,
      bothSigned,
      message: bothSigned
        ? "Her iki taraf imzaladı. Kontrata gönderilebilir."
        : "Teklifin kaydedildi. Karşı tarafın imzası bekleniyor.",
    });
  } catch (err) { next(err); }
});

// ─── POST /api/trades/:id/chargeback-ack ─────────────────────────────────────
// [TR] Bu endpoint yalnızca audit/log içindir. On-chain release akışına veto uygulamaz.
//      Başarısızlığı kontrat çağrısını engelleyecek bir protocol gate olarak kullanılmamalıdır.

/**
 * ORTA-12 Fix: Gerçek IP belirleme fonksiyonu.
 * app.js'de trust proxy aktif olduğunda req.ip doğru IP'yi döndürür.
 * Bu fonksiyon ek güvence katmanı sağlar.
 */
function _getRealIP(req) {
  // [TR] trust proxy aktifse req.ip zaten doğru — bu sadece ekstra güvence
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && process.env.NODE_ENV === 'production') {
    // [TR] En soldaki IP gerçek istemcidir (en sağdaki proxy'dir)
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || "unknown";
}

router.post("/:id/chargeback-ack", requireAuth, requireSessionWalletMatch, tradesLimiter, async (req, res, next) => {
  try {
    if (!/^[a-fA-F0-9]{24}$/.test(req.params.id)) {
      return res.status(400).json({ error: "Geçersiz trade ID formatı." });
    }

    // ORTA-14 Fix: findOneAndUpdate ile atomik kontrol + güncelleme
    // ÖNCEKİ: findOne + ayrı save() = race condition
    // ŞİMDİ: Tek sorgu — acknowledged: false koşulu filtrede
    const rawIp  = _getRealIP(req);
    const ipHash = crypto.createHash("sha256").update(rawIp).digest("hex");

    const updatedTrade = await Trade.findOneAndUpdate(
      {
        _id:            req.params.id,
        maker_address:  req.wallet,
        status:         { $in: ["PAID", "CHALLENGED"] },
        // ORTA-14 Fix: Sadece henüz onaylanmamışsa güncelle
        "chargeback_ack.acknowledged": { $ne: true },
      },
      {
        $set: {
          "chargeback_ack.acknowledged":    true,
          "chargeback_ack.acknowledged_by": req.wallet,
          "chargeback_ack.acknowledged_at": new Date(),
          "chargeback_ack.ip_hash":         ipHash,
        },
      },
      { new: true }
    );

    if (!updatedTrade) {
      // [TR] Güncelleme yapılamadıysa nedeni anla
      const existing = await Trade.findById(req.params.id).select("maker_address status chargeback_ack").lean();
      if (!existing)                                  return res.status(404).json({ error: "İşlem bulunamadı." });
      if (existing.maker_address !== req.wallet)      return res.status(403).json({ error: "Bu işlem için yetkiniz yok." });
      if (existing.chargeback_ack?.acknowledged)      return res.status(409).json({ error: "Bu işlem için onay zaten kaydedildi.", acknowledged_at: existing.chargeback_ack.acknowledged_at });
      return res.status(400).json({ error: `Chargeback onayı bu durumda yapılamaz (mevcut: ${existing.status}).` });
    }

    logger.info(`[ChargebackAck] Kaydedildi: maker=${req.wallet} trade=${req.params.id}`);
    return res.status(201).json({
      success:         true,
      acknowledged_at: updatedTrade.chargeback_ack.acknowledged_at,
      message:         "Ters ibraz riski onayı kaydedildi.",
    });
  } catch (err) { next(err); }
});

module.exports = router;
