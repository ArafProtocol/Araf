"use strict";

/**
 * PII Route — IBAN Fetch (En Yüksek Güvenlik Seviyeli Endpoint)
 *
 * ORTA-07 Fix: PII Token 15 Dakikalık Hayalet Erişim Kapatıldı.
 *   ÖNCEKİ: GET /:tradeId sadece requirePIIToken kontrolüne güveniyordu.
 *   Token alındıktan sonra işlem iptal edilse bile token 15 dk geçerliydi.
 *   ŞİMDİ: Şifre çözme öncesinde anlık statü kontrolü yapılıyor.
 *   Trade LOCKED, PAID veya CHALLENGED değilse erişim reddediliyor.
 *
 * ORTA-08 Fix: taker-name CANCELED/RESOLVED Sonrası Erişim Kapatıldı.
 *   ÖNCEKİ: Sadece LOCKED/PAID/CHALLENGED kontrol ediliyordu.
 *   İşlem bittikten sonra Maker hâlâ Taker ismini görebiliyordu (GDPR/KVKK ihlali).
 *   ŞİMDİ: Aynı allowedStates listesi her iki endpoint'te de uygulanıyor.
 *
 * BACK-05 Fix: PII Token İhracı Log Sızıntısı Azaltıldı.
 *   ÖNCEKİ: Her token isteği logger.info ile tam tradeId ve wallet bilgisiyle loglanıyordu.
 *   ŞİMDİ: Hassas detaylar logdan çıkarıldı — sadece erişim sayısı izleniyor.
 */

const express = require("express");
const router  = express.Router();

const { requireAuth, requirePIIToken } = require("../middleware/auth");
const { piiLimiter }                   = require("../middleware/rateLimiter");
const { Trade }                        = require("../models/Trade");
const User                             = require("../models/User");
const { decryptPII, decryptField }     = require("../services/encryption");
const { issuePIIToken }                = require("../services/siwe");
const logger                           = require("../utils/logger");

// [TR] PII erişimine izin verilen trade durumları
const ALLOWED_TRADE_STATES = ["LOCKED", "PAID", "CHALLENGED"];

// ─── GET /api/pii/my ─────────────────────────────────────────────────────────
router.get("/my", requireAuth, piiLimiter, async (req, res, next) => {
  try {
    const user = await User.findOne({ wallet_address: req.wallet })
      .select("pii_data").lean();

    if (!user || !user.pii_data) return res.json({ pii: null });

    const decrypted = await decryptPII(user.pii_data, req.wallet);
    // BACK-05 Fix: Wallet'ın tamamını loglamak yerine kısaltılmış versiyonunu kullan
    logger.info(`[PII] /my accessed: wallet=${req.wallet.slice(0, 10)}...`);
    return res.json({ pii: decrypted });
  } catch (err) { next(err); }
});

// ─── GET /api/pii/taker-name/:onchainId ──────────────────────────────────────
router.get("/taker-name/:onchainId", requireAuth, piiLimiter, async (req, res, next) => {
  try {
    const onchainId = Number(req.params.onchainId);
    if (!Number.isInteger(onchainId) || onchainId <= 0) {
      return res.status(400).json({ error: "Geçersiz on-chain ID formatı." });
    }

    const trade = await Trade.findOne({ onchain_escrow_id: onchainId })
      .select("maker_address taker_address status pii_snapshot").lean();

    if (!trade) return res.status(404).json({ error: "Trade bulunamadı." });

    if (trade.maker_address !== req.wallet) {
      logger.warn(`[PII] Yetkisiz taker-name erişimi: caller=${req.wallet.slice(0, 10)}...`);
      return res.status(403).json({ error: "Yalnızca satıcı (maker) alıcının ismini görebilir." });
    }

    // ORTA-08 Fix: İşlem bittikten sonra erişim kesilebiliyor
    if (!ALLOWED_TRADE_STATES.includes(trade.status)) {
      return res.status(400).json({
        error: `Taker bilgisi ${trade.status} durumunda alınamaz. Erişim sadece aktif işlemlerde geçerlidir.`,
      });
    }

    if (!trade.taker_address) return res.json({ bankOwner: null });

    // [TR] Öncelik: LOCKED anında alınan snapshot (stabil referans)
    // [EN] Priority: snapshot captured at LOCKED (stable reference)
    let bankOwner = null;
    if (trade.pii_snapshot?.taker_bankOwner_enc) {
      bankOwner = await decryptField(trade.pii_snapshot.taker_bankOwner_enc, trade.taker_address);
    } else {
      const takerUser = await User.findOne({ wallet_address: trade.taker_address })
        .select("pii_data").lean();
      if (takerUser?.pii_data?.bankOwner_enc) {
        const decrypted = await decryptPII(takerUser.pii_data, trade.taker_address);
        bankOwner = decrypted.bankOwner;
      }
    }

    // BACK-05 Fix: Tam adresler yerine kısaltılmış log
    logger.info(`[PII] taker-name accessed: onchain=#${onchainId}`);
    return res.json({ bankOwner });
  } catch (err) { next(err); }
});

// ─── POST /api/pii/request-token/:tradeId ────────────────────────────────────
router.post(
  "/request-token/:tradeId",
  requireAuth,
  piiLimiter,
  async (req, res, next) => {
    try {
      const { tradeId }   = req.params;
      const callerWallet  = req.wallet;

      if (!/^[a-fA-F0-9]{24}$/.test(tradeId)) {
        return res.status(400).json({ error: "Geçersiz tradeId formatı." });
      }

      const trade = await Trade.findById(tradeId).lean();
      if (!trade) return res.status(404).json({ error: "Trade bulunamadı." });

      if (trade.taker_address !== callerWallet) {
        logger.warn(`[PII] Yetkisiz token talebi: trade=${tradeId.slice(0, 8)}...`);
        return res.status(403).json({ error: "Yalnızca taker PII token talep edebilir." });
      }

      if (!ALLOWED_TRADE_STATES.includes(trade.status)) {
        return res.status(400).json({ error: `PII token ${trade.status} durumunda alınamaz.` });
      }

      const piiToken = issuePIIToken(callerWallet, tradeId);

      // BACK-05 Fix: Sadece sayısal iz — wallet/tradeId detayı log'a yazılmıyor
      logger.info(`[PII] Token issued (onchain=#${trade.onchain_escrow_id})`);
      return res.json({ piiToken });
    } catch (err) { next(err); }
  }
);

// ─── GET /api/pii/:tradeId ────────────────────────────────────────────────────
router.get(
  "/:tradeId",
  requirePIIToken,
  piiLimiter,
  async (req, res, next) => {
    try {
      const { tradeId }  = req.params;
      const callerWallet = req.wallet;
      if (!/^[a-fA-F0-9]{24}$/.test(tradeId)) {
        return res.status(400).json({ error: "Geçersiz tradeId formatı." });
      }

      const trade = await Trade.findById(tradeId)
        .select("maker_address status taker_address pii_snapshot").lean();

      if (!trade) return res.status(404).json({ error: "Trade bulunamadı." });

      if (trade.taker_address !== callerWallet) {
        return res.status(403).json({ error: "Yetkisiz erişim." });
      }

      // ORTA-07 Fix: Anlık statü kontrolü — iptal edilmiş işlemde IBAN görüntülenemiyor
      if (!ALLOWED_TRADE_STATES.includes(trade.status)) {
        return res.status(403).json({
          error: `İşlem artık aktif değil (${trade.status}). PII erişimi kaldırıldı.`,
        });
      }

      // [TR] Öncelik snapshot verisinde; yoksa legacy user.pii_data fallback
      // [EN] Prefer snapshot data; fallback to legacy user.pii_data when missing
      let bankOwner = null;
      let iban      = null;
      let telegram  = null;
      if (trade.pii_snapshot?.maker_bankOwner_enc || trade.pii_snapshot?.maker_iban_enc) {
        if (trade.pii_snapshot?.maker_bankOwner_enc) {
          bankOwner = await decryptField(trade.pii_snapshot.maker_bankOwner_enc, trade.maker_address);
        }
        if (trade.pii_snapshot?.maker_iban_enc) {
          iban = await decryptField(trade.pii_snapshot.maker_iban_enc, trade.maker_address);
        }
      } else {
        const makerUser = await User.findOne({ wallet_address: trade.maker_address })
          .select("pii_data").lean();
        if (!makerUser || !makerUser.pii_data) {
          return res.status(404).json({ error: "Satıcı ödeme bilgilerini henüz girmemiş." });
        }
        const decrypted = await decryptPII(makerUser.pii_data, trade.maker_address);
        bankOwner = decrypted.bankOwner;
        iban      = decrypted.iban;
        telegram  = decrypted.telegram;
      }

      // BACK-05 Fix: Log'a şifresi çözülmüş veri yazılmıyor — sadece erişim kaydı
      logger.info(`[PII] Accessed: trade=${tradeId.slice(0, 8)}...`);

      // [TR] Hassas veri yanıtlarında ara katman cache'lerini devre dışı bırak.
      res.set("Cache-Control", "no-store, max-age=0");
      res.set("Pragma", "no-cache");

      return res.json({
        bankOwner,
        iban,
        telegram,
        notice:    "Bu bilgiler şifreli kanaldan iletildi. Blockchain'e veya loglara kaydedilmez.",
      });
    } catch (err) {
      if (err.message?.includes("Unsupported state") || err.message?.includes("Invalid auth tag")) {
        logger.error(`[PII] Şifre çözme hatası: trade=${req.params.tradeId.slice(0, 8)}...`);
        return res.status(500).json({ error: "Şifre çözme başarısız. Lütfen daha sonra tekrar deneyin." });
      }
      next(err);
    }
  }
);

module.exports = router;
