"use strict";

const express = require("express");
const Joi     = require("joi");
const router  = express.Router();

const { authLimiter }                        = require("../middleware/rateLimiter");
const { requireAuth }                        = require("../middleware/auth");
const {
  generateNonce,
  verifySiweSignature,
  issueJWT,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
} = require("../services/siwe");
const { encryptPII }                         = require("../services/encryption");
const User                                   = require("../models/User");
const logger                                 = require("../utils/logger");

/**
 * httpOnly + Secure + SameSite=Strict cookie olarak set edilir.
 *
 * Development'ta Secure=false (http://localhost kullanıldığı için).
 * Production'da Secure=true zorunlu.
 */
const COOKIE_OPTIONS_BASE = {
  httpOnly: true,
  sameSite: "strict",
  path:     "/",
};

function _getJwtCookieOptions() {
  return {
    ...COOKIE_OPTIONS_BASE,
    secure: process.env.NODE_ENV === "production",
    maxAge: 15 * 60 * 1000, // 15 dakika (JWT_EXPIRES_IN ile senkron)
  };
}

function _getRefreshCookieOptions() {
  return {
    ...COOKIE_OPTIONS_BASE,
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 gün (REFRESH_TOKEN_TTL ile senkron)
    path:   "/api/auth", // Refresh token sadece auth endpoint'lerine gönderilsin
  };
}

/**
 * GET /api/auth/nonce?wallet=0x...
 * Frontend MetaMask imzalamadan önce nonce'u çeker.
 * Nonce Redis'te 5 dakika yaşar — tek kullanımlık.
 *
 * Frontend loginWithSIWE fonksiyonu siweDomain'i kullanarak SIWE mesajı oluşturur.
 */
router.get("/nonce", authLimiter, async (req, res, next) => {
  try {
    const { wallet } = req.query;
    if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      return res.status(400).json({ error: "Geçerli bir Ethereum adresi gir" });
    }
    const nonce = await generateNonce(wallet.toLowerCase());
    // frontend SIWE mesajında kullanır
    const siweDomain = process.env.SIWE_DOMAIN || "localhost";
    return res.json({ nonce, siweDomain });
  } catch (err) { next(err); }
});

/**
 * POST /api/auth/verify
 * Body: { message, signature }
 * SIWE imzasını doğrular, JWT döner.
 *
 * Token'lar artık response body'de DEĞİL, httpOnly cookie'de.
 * Frontend sadece { wallet, profile } alır — token'lara erişemez (XSS koruması).
 */
router.post("/verify", authLimiter, async (req, res, next) => {
  try {
    const schema = Joi.object({
      message:   Joi.string().max(2000).required(),
      signature: Joi.string().pattern(/^0x[a-fA-F0-9]{130}$/).required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    const wallet = await verifySiweSignature(value.message, value.signature);

    const user = await User.findOneAndUpdate(
      { wallet_address: wallet },
      { $set: { last_login: new Date() }, $setOnInsert: { wallet_address: wallet } },
      { upsert: true, new: true }
    );

    if (user.checkBanExpiry()) await user.save();

    const token        = issueJWT(wallet);
    const refreshToken = await issueRefreshToken(wallet);

    //  httpOnly cookie olarak set et
    res.cookie("araf_jwt",     token,        _getJwtCookieOptions());
    res.cookie("araf_refresh", refreshToken, _getRefreshCookieOptions());

    logger.info(`[Auth] Giriş başarılı: ${wallet}`);

    //  Token'lar body'de döndürülmüyor — sadece wallet ve profil
    return res.json({ wallet, profile: user.toPublicProfile() });
  } catch (err) {
    logger.warn(`[Auth] SIWE başarısız: ${err.message}`);
    return res.status(401).json({ error: `Kimlik doğrulama başarısız: ${err.message}` });
  }
});

/**
 * POST /api/auth/refresh
 *
 * Wallet adresi de cookie'deki JWT'den çözümleniyor (expired olsa bile sub claim okunabilir).
 */
router.post("/refresh", authLimiter, async (req, res, next) => {
  try {
    // Refresh token cookie'den okunur
    const refreshToken = req.cookies?.araf_refresh;
    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token bulunamadı." });
    }

    // Wallet adresini expired JWT'den çözümle (verify skip — sadece decode)
    // VEYA body'den al (geriye uyumluluk)
    let wallet = req.body?.wallet;
    if (!wallet) {
      const jwt = req.cookies?.araf_jwt;
      if (jwt) {
        try {
          // JWT expired olsa bile payload okunabilir (verify etmeden decode)
          const parts = jwt.split(".");
          if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
            wallet = payload.sub;
          }
        } catch { /* ignore decode errors */ }
      }
    }

    if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      return res.status(400).json({ error: "Wallet adresi belirlenemedi." });
    }

    const result = await rotateRefreshToken(
      wallet.toLowerCase(),
      refreshToken
    );

    // Yeni token'ları cookie olarak set et
    res.cookie("araf_jwt",     result.token,        _getJwtCookieOptions());
    res.cookie("araf_refresh", result.refreshToken, _getRefreshCookieOptions());

    logger.info(`[Auth] Token yenilendi: ${wallet}`);
    return res.json({ wallet: wallet.toLowerCase() });
  } catch (err) {
    logger.warn(`[Auth] Refresh başarısız: ${err.message}`);
    // Başarısız refresh'te cookie'leri temizle
    res.clearCookie("araf_jwt",     { ...COOKIE_OPTIONS_BASE, path: "/" });
    res.clearCookie("araf_refresh", { ...COOKIE_OPTIONS_BASE, path: "/api/auth" });
    return res.status(401).json({ error: err.message });
  }
});

/**
 * POST /api/auth/logout
 * revokeRefreshToken Redis'ten ve Cookie'leri de temizle.
 */
router.post("/logout", requireAuth, async (req, res, next) => {
  try {
    await revokeRefreshToken(req.wallet);

    // AUDIT FIX F-01: httpOnly cookie'leri temizle
    res.clearCookie("araf_jwt",     { ...COOKIE_OPTIONS_BASE, path: "/" });
    res.clearCookie("araf_refresh", { ...COOKIE_OPTIONS_BASE, path: "/api/auth" });

    logger.info(`[Auth] Çıkış: ${req.wallet}`);
    return res.json({ success: true, message: "Oturum kapatıldı." });
  } catch (err) { next(err); }
});

/**
 * GET /api/auth/me
 * Frontend sayfa yüklendiğinde cookie'deki JWT'nin geçerli olup olmadığını kontrol eder.
 * Geçerliyse wallet adresini döndürür → frontend isAuthenticated = true yapabilir.
 */
router.get("/me", requireAuth, (req, res) => {
  return res.json({ wallet: req.wallet, authenticated: true });
});

/**
 * PUT /api/auth/profile
 * Kullanıcının IBAN ve Telegram bilgisini günceller.
 * Veriler veritabanına YAZILMADAN önce AES-256 ile şifrelenir.
 *
 */
router.put("/profile", requireAuth, async (req, res, next) => {
  try {
    const schema = Joi.object({
      bankOwner: Joi.string().max(100).allow("").optional(),
      iban:      Joi.string().max(34).allow("").optional(),
      telegram:  Joi.string().max(50).allow("").optional(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    const encrypted = await encryptPII(value, req.wallet);

    await User.findOneAndUpdate(
      { wallet_address: req.wallet },
      {
        $set: {
          "pii_data.bankOwner_enc": encrypted.bankOwner_enc,
          "pii_data.iban_enc":      encrypted.iban_enc,
          "pii_data.telegram_enc":  encrypted.telegram_enc,
        },
      }
    );

    logger.info(`[Auth] Profil güncellendi: ${req.wallet}`);
    return res.json({ success: true, message: "Profil bilgilerin güncellendi." });
  } catch (err) { next(err); }
});

module.exports = router;
