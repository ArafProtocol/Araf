"use strict";
/*## auth.js hardening

This PR updates `backend/scripts/routes/auth.js` to preserve the existing auth safety improvements while adding strict wallet/session authority checks to `/api/auth/me`.

### Existing fixes that remain

This file already contained several important protections, and they remain in place:

- auth cookies continue to use `SameSite=Lax` for Web3 redirect compatibility
- `/profile` remains protected by `authLimiter` to prevent crypto-heavy abuse
- logout still blacklists the current JWT before clearing cookies
- nonce, refresh, and SIWE verification flows still rely on the hardened `siwe.js` service behavior

### Previous behavior

`GET /api/auth/me` only checked whether the cookie JWT was valid and then returned:

- `wallet`
- `authenticated: true`

That meant the endpoint behaved like a session presence check, but not a strict wallet authority check.

In practice, if the connected wallet changed on the frontend, `/me` could still return a valid session for the old wallet unless another layer explicitly caught the mismatch.

### New behavior

`/api/auth/me` now becomes strict when the frontend sends `x-wallet-address`.

New behavior:

- the cookie JWT wallet remains authoritative
- if `x-wallet-address` is present, it is normalized and compared against `req.wallet`
- if the connected wallet does not match the authenticated wallet:
  - auth cookies are cleared
  - refresh token family is revoked
  - the endpoint returns `409 SESSION_WALLET_MISMATCH`

If there is no mismatch, `/me` continues to return the authenticated wallet as before.

### Effect

This closes the gap between:

- “a valid cookie session exists”
and
- “that session actually belongs to the wallet currently connected in the UI”

It makes `/api/auth/me` part of the wallet/session authority boundary instead of only a passive auth check.

### Scope

Only `backend/scripts/routes/auth.js` was targeted here. */
const express = require("express");
const Joi = require("joi");
const router = express.Router();

const { authLimiter } = require("../middleware/rateLimiter");
const { requireAuth, requireSessionWalletMatch } = require("../middleware/auth");
const {
  generateNonce,
  verifySiweSignature,
  getSiweConfig,
  issueJWT,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  blacklistJWT,
} = require("../services/siwe");
const { encryptPII } = require("../services/encryption");
const User = require("../models/User");
const logger = require("../utils/logger");

const COOKIE_OPTIONS_BASE = {
  httpOnly: true,
  sameSite: "lax",
  path: "/",
};

function _getJwtCookieOptions() {
  return {
    ...COOKIE_OPTIONS_BASE,
    secure: process.env.NODE_ENV === "production",
    maxAge: 15 * 60 * 1000,
  };
}

function _getRefreshCookieOptions() {
  return {
    ...COOKIE_OPTIONS_BASE,
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/api/auth",
  };
}

/**
 * GET /api/auth/nonce?wallet=0x...
 * Nonce üretir ve SIWE config bilgisini döndürür.
 */
router.get("/nonce", authLimiter, async (req, res, next) => {
  try {
    const { wallet } = req.query;

    if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      return res.status(400).json({ error: "Geçerli bir Ethereum adresi gir." });
    }

    const nonce = await generateNonce(wallet.toLowerCase());
    const { domain: siweDomain, uri: siweUri } = getSiweConfig();

    return res.json({ nonce, siweDomain, siweUri });
  } catch (err) {
    if (/SIWE_/.test(err.message)) {
      return res.status(503).json({ error: err.message });
    }
    next(err);
  }
});

/**
 * POST /api/auth/verify
 * SIWE imzasını doğrular, JWT ve refresh token'ı httpOnly cookie olarak set eder.
 */
router.post("/verify", authLimiter, async (req, res) => {
  try {
    const schema = Joi.object({
      message: Joi.string().max(2000).required(),
      signature: Joi.string().pattern(/^0x[a-fA-F0-9]{130}$/).required(),
    });

    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    const wallet = await verifySiweSignature(value.message, value.signature);

    const user = await User.findOneAndUpdate(
      { wallet_address: wallet },
      { $set: { last_login: new Date() }, $setOnInsert: { wallet_address: wallet } },
      { upsert: true, new: true }
    );

    await user.checkBanExpiry();

    const token = issueJWT(wallet);
    const refreshToken = await issueRefreshToken(wallet);

    res.cookie("araf_jwt", token, _getJwtCookieOptions());
    res.cookie("araf_refresh", refreshToken, _getRefreshCookieOptions());

    logger.info(`[Auth] Giriş başarılı: ${wallet}`);
    
    // [EKLE] Token'ı Farcaster (Frame v2) istemcisinin alabilmesi için body'de dön
    const isFarcaster = req.headers["x-farcaster-mode"] === "true";
    
    return res.json({ 
      wallet, 
      token: isFarcaster ? token : undefined, 
      profile: user.toPublicProfile() 
    });
  } catch (err) {
    logger.warn(`[Auth] SIWE başarısız: ${err.message}`);
    return res.status(401).json({ error: `Kimlik doğrulama başarısız: ${err.message}` });
  }
});

/**
 * POST /api/auth/refresh
 * Refresh token ile yeni JWT ve yeni refresh token üretir.
 */
router.post("/refresh", authLimiter, async (req, res) => {
  try {
    const refreshToken = req.cookies?.araf_refresh;
    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token bulunamadı." });
    }

    let wallet = req.body?.wallet;

    if (!wallet) {
      const jwtCookie = req.cookies?.araf_jwt;
      if (jwtCookie) {
        try {
          const parts = jwtCookie.split(".");
          if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
            wallet = payload.sub;
          }
        } catch {
          // decode hatası durumunda wallet null kalır
        }
      }
    }

    if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      return res.status(400).json({ error: "Wallet adresi belirlenemedi." });
    }

    const result = await rotateRefreshToken(wallet.toLowerCase(), refreshToken);

    res.cookie("araf_jwt", result.token, _getJwtCookieOptions());
    res.cookie("araf_refresh", result.refreshToken, _getRefreshCookieOptions());

    logger.info(`[Auth] Token yenilendi: ${wallet}`);
    return res.json({ wallet: wallet.toLowerCase() });
  } catch (err) {
    logger.warn(`[Auth] Refresh başarısız: ${err.message}`);
    res.clearCookie("araf_jwt", { ...COOKIE_OPTIONS_BASE, path: "/" });
    res.clearCookie("araf_refresh", { ...COOKIE_OPTIONS_BASE, path: "/api/auth" });
    return res.status(401).json({ error: err.message });
  }
});

/**
 * POST /api/auth/logout
 * Aktif JWT'yi blacklist'e alır, refresh token ailesini iptal eder ve cookie'leri temizler.
 */
router.post("/logout", requireAuth, async (req, res, next) => {
  try {
    const currentJWT = req.cookies?.araf_jwt;
    if (currentJWT) {
      await blacklistJWT(currentJWT);
    }

    await revokeRefreshToken(req.wallet);

    res.clearCookie("araf_jwt", { ...COOKIE_OPTIONS_BASE, path: "/" });
    res.clearCookie("araf_refresh", { ...COOKIE_OPTIONS_BASE, path: "/api/auth" });

    logger.info(`[Auth] Çıkış yapıldı: ${req.wallet}`);
    return res.json({ success: true, message: "Oturum kapatıldı." });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/auth/me
 * Cookie'deki JWT geçerliyse wallet adresini döndürür.
 * Bağlı cüzdan header ile gelmişse, cookie wallet ile birebir eşleşmesi gerekir.
 */
router.get("/me", requireAuth, async (req, res) => {
  const headerWalletRaw = req.headers["x-wallet-address"];

  if (headerWalletRaw) {
    const headerWallet = headerWalletRaw.trim().toLowerCase();

    if (/^0x[a-f0-9]{40}$/.test(headerWallet) && headerWallet !== req.wallet) {
      logger.warn(
        `[Auth] /me wallet mismatch: cookie=${req.wallet} header=${headerWallet} — session geçersiz`
      );

      res.clearCookie("araf_jwt", { ...COOKIE_OPTIONS_BASE, path: "/" });
      res.clearCookie("araf_refresh", { ...COOKIE_OPTIONS_BASE, path: "/api/auth" });

      try {
        await revokeRefreshToken(req.wallet);
      } catch (_) {
        // revoke hatası mismatch cevabını engellemez
      }

      return res.status(409).json({
        error: "Oturum cüzdanı aktif bağlı cüzdanla eşleşmiyor.",
        code: "SESSION_WALLET_MISMATCH",
      });
    }
  }

  return res.json({ wallet: req.wallet, authenticated: true });
});

/**
 * PUT /api/auth/profile
 * PII alanlarını şifreleyerek kullanıcının profilini günceller.
 */
router.put("/profile", requireAuth, requireSessionWalletMatch, authLimiter, async (req, res, next) => {
  try {
    const normalizedBody = {
      bankOwner:
        typeof req.body?.bankOwner === "string"
          ? req.body.bankOwner.trim().replace(/\s+/g, " ")
          : req.body?.bankOwner,
      iban:
        typeof req.body?.iban === "string"
          ? req.body.iban.replace(/\s+/g, "").toUpperCase()
          : req.body?.iban,
      telegram:
        typeof req.body?.telegram === "string"
          ? req.body.telegram.trim().replace(/^@+/, "")
          : req.body?.telegram,
    };

    const schema = Joi.object({
      bankOwner: Joi.string()
        .min(2)
        .max(100)
        .pattern(/^[a-zA-ZğüşöçİĞÜŞÖÇ\s]+$/, "geçerli isim karakterleri")
        .allow("")
        .optional()
        .messages({
          "string.pattern.name": "Banka sahibi adı sadece harf içerebilir.",
        }),
      iban: Joi.string()
        .pattern(/^TR\d{24}$/, "TR IBAN formatı")
        .allow("")
        .optional()
        .messages({
          "string.pattern.name": "IBAN formatı geçersiz. Örnek: TR330006100519786457841326",
        }),
      telegram: Joi.string()
        .max(50)
        .pattern(/^[a-zA-Z0-9_]{5,}$/, "Telegram kullanıcı adı")
        .allow("")
        .optional(),
    });

    const { error, value } = schema.validate(normalizedBody);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    const encrypted = await encryptPII(value, req.wallet);

    await User.findOneAndUpdate(
      { wallet_address: req.wallet },
      {
        $set: {
          "pii_data.bankOwner_enc": encrypted.bankOwner_enc,
          "pii_data.iban_enc": encrypted.iban_enc,
          "pii_data.telegram_enc": encrypted.telegram_enc,
        },
      }
    );

    logger.info(`[Auth] Profil güncellendi: ${req.wallet}`);
    return res.json({ success: true, message: "Profil bilgilerin güncellendi." });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
