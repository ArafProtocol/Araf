"use strict";

const { createLogger, format, transports } = require("winston");
const path = require("path");
const fs   = require("fs");

/**
 * ORTA-18 Fix: Log Dizini Traversal Riski Kapatıldı.
 *   ÖNCEKİ: Log dosyası ../../araf_full_stack.log.txt — proje KÖK dizininde.
 *   Nginx veya web sunucusu yanlış yapılandırılırsa bu dosya internet üzerinden
 *   erişilebilir hale gelebiliyordu. Stack trace ve cüzdan adresleri açığa çıkıyordu.
 *   ŞİMDİ: Log dosyası backend/logs/ altında (web root'tan izole).
 *   Dizin yoksa otomatik oluşturulur.
 *   Production'da mutlaka /var/log/araf/ gibi sistem dizini kullanılmalı.
 *
 * Kullanım önerisi (production):
 *   LOG_DIR=/var/log/araf ortam değişkeni ile özel dizin belirlenebilir.
 */

// [TR] Log dizini — production'da ortam değişkeniyle özelleştirilebilir
const logDir = process.env.LOG_DIR
  ? path.resolve(process.env.LOG_DIR)
  : path.join(__dirname, "../../logs"); // backend/logs/

// [TR] Log dizini yoksa oluştur
if (!fs.existsSync(logDir)) {
  try {
    fs.mkdirSync(logDir, { recursive: true });
  } catch (err) {
    // [TR] Dizin oluşturulamazsa sadece konsol kullan
    console.error("[Logger] Log dizini oluşturulamadı:", err.message);
  }
}

const logFilePath = path.join(logDir, "araf.log");

const logger = createLogger({
  // [TR] Production'da 'info', test/dev'de 'debug'
  level: process.env.NODE_ENV === "production" ? "info" : "debug",

  format: format.combine(
    format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    format.errors({ stack: true }),
    format.json(),
    format.printf(({ timestamp, level, message, stack, ...meta }) => {
      const metaString = Object.keys(meta).length ? JSON.stringify(meta) : "";
      return `${timestamp} [${level.toUpperCase()}]: ${message} ${metaString}${stack ? `\n${stack}` : ""}`;
    })
  ),

  transports: [
    // [TR] Terminale renkli çıktı
    new transports.Console({
      format: format.combine(format.colorize(), format.simple()),
    }),

    // [TR] Dosyaya yapılandırılmış kayıt
    // ORTA-18 Fix: Artık web root'tan izole logs/ dizinine yazıyor
    ...(fs.existsSync(logDir) ? [
      new transports.File({
        filename: logFilePath,
        level:    "debug",
        maxsize:  26_214_400, // 25MB dolunca yeni dosyaya geç
        maxFiles: 5,
      }),
    ] : []),
  ],
});

module.exports = logger;
