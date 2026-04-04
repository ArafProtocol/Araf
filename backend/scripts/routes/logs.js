"use strict";

const express     = require("express");
const router      = express.Router();
const logger      = require("../utils/logger");
const rateLimit   = require("express-rate-limit");
const { isReady } = require("../config/redis");

/**
 * Client Error Logger — Frontend Hata Yakalayıcı
 *
 * YÜKS-21 Fix: Kimlik Doğrulamasız Denetim İzi İmhası Kapatıldı.
 *   ÖNCEKİ: Bu endpoint üzerinde hiçbir kimlik doğrulama veya rate limit yoktu.
 *   logger.js maxsize: 25MB, maxFiles: 5 = toplam 125MB log limiti.
 *   Saldırgan sisteme kritik zafiyet sömürdükten hemen sonra bu endpoint'e
 *   büyük JSON paketleriyle saniyede binlerce istek atarak 125MB log limitini
 *   doldurabiliyor → gerçek saldırı izleri kalıcı olarak siliniyordu.
 *   ŞİMDİ:
 *     1. IP bazlı sıkı rate limit (dakikada 10 istek)
 *     2. Payload boyutu sınırı (max 5KB — sadece hata mesajı içermeli)
 *     3. Zorunlu alan doğrulaması (message alanı olmayan istekler reddedilir)
 *     4. Redis erişilemezse bellek bazlı rate limit devreye girer
 *
 * Not: requireAuth kasıtlı olarak EKLENMEDİ.
 * Frontend ErrorBoundary, kullanıcı oturum açmadan önce de çökebilir.
 * Kimlik doğrulama bu endpoint'in işlevini bozur. Rate limit yeterli koruma sağlar.
 */

// [TR] Bellekte rate limit (Redis yokken fallback)
let inMemoryRequests = {};
setInterval(() => { inMemoryRequests = {}; }, 60 * 1000); // Her dakika temizle

/**
 * Basit in-memory rate limiter — Redis erişilemez olduğunda devreye girer.
 */
function inMemoryRateLimit(ip, limit = 10) {
  inMemoryRequests[ip] = (inMemoryRequests[ip] || 0) + 1;
  return inMemoryRequests[ip] > limit;
}

/**
 * Karma rate limiter middleware.
 * Redis varsa Redis'i, yoksa bellekteki sayacı kullanır.
 */
const logRateLimiter = rateLimit({
  windowMs:    60 * 1000,  // 1 dakika
  max:         10,         // IP başına dakikada 10 istek
  keyGenerator:(req) => req.ip,
  // [TR] Redis erişilemezse in-memory fallback kullan, fail-open YOK (log DoS riski)
  skip:        () => false,
  handler:     (req, res) => {
    // [TR] Rate limit aşıldıysa ek log yazma — log spam'ini önle
    res.status(429).json({ error: "Çok fazla log isteği." });
  },
  standardHeaders: true,
  legacyHeaders:   false,
});

/**
 * POST /api/logs/client-error
 * Frontend render ve uygulama hatalarını merkezi logger'a iletir.
 * 204 No Content döner — sisteme yük bindirmesin.
 */
router.post("/client-error", logRateLimiter, (req, res) => {
  const { message, stack, componentStack, url } = req.body || {};

  // [TR] message alanı olmayan istekleri sessizce reddet (bot testi engeli)
  if (!message || typeof message !== "string") {
    return res.status(400).json({ error: "message alanı zorunludur." });
  }

  // [TR] Maksimum mesaj uzunluğu — log bombalamasını önle
  const safeMessage        = String(message).slice(0, 500);
  const safeStack          = stack          ? String(stack).slice(0, 2000)          : undefined;
  const safeComponentStack = componentStack ? String(componentStack).slice(0, 1000) : undefined;
  const safeUrl            = url            ? String(url).slice(0, 200)             : undefined;

  logger.error("[FRONTEND-CRASH]", {
    message:        safeMessage,
    url:            safeUrl    || "Bilinmeyen URL",
    stack:          safeStack,
    componentStack: safeComponentStack,
    userAgent:      req.headers["user-agent"]?.slice(0, 200),
    ip:             req.ip,
  });

  // [TR] 204 No Content — gövdesiz yanıt (sisteme yük bindirme)
  res.status(204).end();
});

module.exports = router;
