// ─── middleware/errorHandler.js ───────────────────────────────────────────────
"use strict";

const logger = require("../utils/logger");

// [TR] Loglanmadan önce temizlenecek PII alanları
// [EN] PII field names to scrub before logging
const PII_FIELD_NAMES = new Set([
  'bankOwner', 'bankOwner_enc',
  'iban', 'iban_enc',
  'telegram', 'telegram_enc',
  'password', 'token', 'refreshToken', 'signature',
]);

/**
 * req.body'den PII alanlarını temizler.
 * Log dosyasına IBAN ve isim bilgisi yazılmasını önler.
 *
 * ORTA-09 Fix: errorHandler.js Plaintext PII Log Sızıntısı kapatıldı..
 *    Bilinen PII alanları [REDACTED] ile değiştiriliyor.
 */
function scrubBody(body) {
  if (!body || typeof body !== 'object') return {};
  const clean = {};
  for (const [key, value] of Object.entries(body)) {
    if (PII_FIELD_NAMES.has(key)) {
      clean[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      clean[key] = scrubBody(value); // nested obje
    } else {
      clean[key] = value;
    }
  }
  return clean;
}

/**
 * Global Error Handler — Merkezi Hata Yönetimi
 *
 * ORTA-09 Fix: Üretimde AND geliştirmede req.body PII scrub edildi.
 *
 * Ek Fix: Eksik fallback response kapatıldı.
 *   ŞİMDİ: Fonksiyon sonunda her zaman yanıt dönen fallback eklendi.
 */
function globalErrorHandler(err, req, res, next) {
  // [TR] Yanıt zaten gönderildiyse Express'in varsayılan hata işleyicisine devret
  if (res.headersSent) {
    return next(err);
  }

  // 1. Hata Detaylarını Hazırla — PII scrub edilmiş body ile
  const errorDetails = {
    message:   err.message,
    path:      req.path,
    method:    req.method,
    ip:        req.ip,
    wallet:    req.wallet || "anon",
    // ORTA-09 Fix: Her ortamda scrub — plaintext PII loglanmaz
    body:      scrubBody(req.body),
    stack:     process.env.NODE_ENV !== "production" ? err.stack : undefined,
    timestamp: new Date().toISOString(),
  };

  logger.error("[SERVER ERROR]", errorDetails);

  // 2. Mongoose Validation Hataları
  if (err.name === "ValidationError") {
    const messages = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({ error: "Doğrulama başarısız.", details: messages });
  }

  // 3. Mongoose Duplicate Key
  if (err.code === 11000) {
    return res.status(409).json({
      error:   "Duplicate entry",
      message: "Bu veri zaten mevcut.",
    });
  }

  // 4. JWT Hataları
  if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
    return res.status(401).json({
      error:   "Geçersiz veya süresi dolmuş token.",
      message: "Lütfen yeniden giriş yapın.",
    });
  }

  // 5. İstemci hataları (özel statusCode ile fırlatılanlar)
  if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
    return res.status(err.statusCode).json({
      error: err.message || "İstek hatası.",
    });
  }

  // 6. Fallback — Tüm diğer beklenmeyen hatalar
  // [TR] Eklendi: Önceki kodda bu fallback yoktu → istek asılı kalıyordu!
  return res.status(500).json({
    error:   "Internal server error",
    message: "Sunucu tarafında beklenmedik bir sorun oluştu.",
  });
}

module.exports = { globalErrorHandler };
