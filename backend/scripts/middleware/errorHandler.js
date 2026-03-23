// ─── middleware/errorHandler.js ───────────────────────────────────────────────
"use strict";

const logger = require("../utils/logger");

/**
 * Global Error Handler - Merkezi Hata Yönetimi
 * [TR] Uygulama genelindeki tüm hataları yakalar, loglar ve istemciye uygun formatta döner.
 * [EN] Catches all application-wide errors, logs them, and returns them in proper format.
 */
function globalErrorHandler(err, req, res, next) {
  // 1. Hata Detaylarını Hazırla (Loglama için)
  const errorDetails = {
    message: err.message,
    path: req.path,
    method: req.method,
    // [TR] İzlenebilirlik için IP ve Cüzdan bilgisi eklendi (Hata avını kolaylaştırır)
    ip: req.ip,
    wallet: req.wallet || "anon",
    // Sadece test ortamında body ve stack trace'i logla (Güvenlik için)
    body: process.env.NODE_ENV !== "production" ? req.body : {},
    stack: process.env.NODE_ENV !== "production" ? err.stack : "Stack trace hidden",
    timestamp: new Date().toISOString()
  };

  // 2. Merkezi Logger ile Dosyaya ve Konsola Yazdır
  // Bu satır sayesinde 'araf_full_stack.log.txt' dosyasına tüm detaylar düşer.
  logger.error(`[SERVER ERROR]`, errorDetails);

  // 3. Özel Hata Tiplerini Yönet
  
  // Mongoose Validation Hataları
  if (err.name === "ValidationError") {
    const messages = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ 
      error: "Validation failed", 
      details: messages 
    });
  }

  // Mongoose Duplicate Key (Aynı veriden iki tane ekleme)
  if (err.code === 11000) {
    return res.status(409).json({ 
      error: "Duplicate entry",
      message: "Bu veri zaten mevcut." 
    });
  }

  // JWT (Kimlik Doğrulama) Hataları
  if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
    return res.status(401).json({ 
      error: "Invalid or expired token",
      message: "Oturum süresi dolmuş veya geçersiz." 
    });
  }

  // 4. Genel Sunucu Hatası (İç yapıyı dışarı sızdırmaz)
  return res.status(500).json({ 
    error: "Internal server error",
    message: "Sunucu tarafında beklenmedik bir sorun oluştu. Lütfen log dosyasını kontrol edin." 
  });
}

module.exports = { globalErrorHandler };
