// ─── config/db.js ─────────────────────────────────────────────────────────────
"use strict";

const mongoose = require("mongoose");
const logger   = require("../utils/logger");

let isConnected = false;

/**
 * MongoDB bağlantısını kurar.
 *
 * ALT-01 Fix: maxPoolSize 10 → 100 olarak güncellendi.
 *   maxPoolSize: 100 — worker + API trafiğini kaldıracak kapasitede.
 *   (Gereksinimlere göre ayarlanabilir; production'da 50-200 arası önerilir.)
 *
 * ALT-04 Fix: socketTimeoutMS proxy süresiyle uyumlu hale getirildi.
 *   ŞİMDİ: socketTimeoutMS: 20000 — proxy zaman aşımının (30sn) altında.
 *
 * ALT-05 Fix: Disconnected event'inde Fail-Fast stratejisi.
 *   Disconnected'da process.exit(1) — PM2/Docker container'ı temiz başlatır.
 */
async function connectDB() {
  if (isConnected) return;

  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI ortam değişkeni zorunludur.");

  await mongoose.connect(uri, {
    // ALT-01 Fix: Worker + API trafiğini kaldıracak bağlantı havuzu
    maxPoolSize:              100,
    // ALT-04 Fix: Proxy zaman aşımı (30sn) altında soket zaman aşımı
    socketTimeoutMS:          20_000,
    serverSelectionTimeoutMS:  5_000,
  });

  isConnected = true;
  // [TR] Kimlik bilgilerini loglamaktan kaçın (@ işaretinden sonrasını al)
  logger.info(`[DB] MongoDB bağlantısı kuruldu: ${uri.split("@").pop()}`);

  mongoose.connection.on("error", (err) => {
    logger.error(`[DB] Bağlantı hatası: ${err.message}`);
  });

  // ALT-05 Fix: Bağlantı koptuğunda Fail-Fast — temiz yeniden başlatma
  mongoose.connection.on("disconnected", () => {
    logger.error("[DB] MongoDB bağlantısı koptu — süreç sonlandırılıyor (Fail-Fast).");
    logger.error("[DB] PM2 veya Docker bu süreci otomatik yeniden başlatmalı.");
    process.exit(1);
  });
}

module.exports = { connectDB };
