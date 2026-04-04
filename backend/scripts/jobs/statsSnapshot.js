"use strict";

/**
 * Stats Snapshot Job — Günlük İstatistik Anlık Görüntüsü Alma Görevi
 *
 * Bu görev, her 24 saatte bir çalışarak güncel protokol istatistiklerini
 * hesaplar ve `historical_stats` koleksiyonuna kaydeder.
 *
 * app.js tarafından periyodik olarak tetiklenir.
 */

const { Trade, Listing } = require("../models/Trade");
const HistoricalStat     = require("../models/HistoricalStat");
const logger             = require("../utils/logger");

// Yeni versiyon MongoDB aggregation kullanarak DB seviyesinde hesaplama yapar.
async function computeCurrentStats() {
  // Paralel aggregation çağrıları — her biri kendi pipeline'ında
  const [resolvedAgg, burnedAgg, activeListings] = await Promise.all([
    // RESOLVED trade'lerin toplam hacmi, sayısı ve ortalama süresi
    Trade.aggregate([
      { $match: { status: "RESOLVED" } },
      { $group: {
        _id: null,
        totalVolume: { $sum: "$financials.crypto_amount_num" },
        count:       { $sum: 1 },
        totalDurationMs: {
          $sum: {
            $cond: {
              if: { $and: [
                { $ne: ["$timers.locked_at", null] },
                { $ne: ["$timers.resolved_at", null] },
              ]},
              then: { $subtract: ["$timers.resolved_at", "$timers.locked_at"] },
              else: 0,
            },
          },
        },
      }},
    ]),
    // BURNED trade'lerin toplam eriyen miktarı
    Trade.aggregate([
      { $match: { status: "BURNED" } },
      { $group: {
        _id: null,
        totalDecayed: { $sum: "$financials.total_decayed_num" },
      }},
    ]),
    // Aktif ilan sayısı
    Listing.countDocuments({ status: "OPEN" }),
  ]);

  const resolved = resolvedAgg[0] || { totalVolume: 0, count: 0, totalDurationMs: 0 };
  const burned   = burnedAgg[0]   || { totalDecayed: 0 };

  const avgTradeHours = resolved.count > 0
    ? parseFloat((resolved.totalDurationMs / resolved.count / (1000 * 3600)).toFixed(1))
    : null;

  return {
    total_volume_usdt: resolved.totalVolume,
    completed_trades:  resolved.count,
    active_listings:   activeListings,
    burned_bonds_usdt: burned.totalDecayed,
    avg_trade_hours:   avgTradeHours,
  };
}

/**
 * İstatistikleri hesaplar ve `historical_stats` koleksiyonuna kaydeder/günceller.
 * Görev idempotenttir; aynı gün içinde birden çok kez çalıştırılsa bile
 * sadece tek bir kayıt oluşturur/günceller.
 */
async function runStatsSnapshot() {
  logger.info("[Job:StatsSnapshot] Günlük istatistik anlık görüntüsü oluşturuluyor...");
  try {
    const stats = await computeCurrentStats();

    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    await HistoricalStat.findOneAndUpdate(
      { date: today },
      { $set: stats },
      { upsert: true, new: true }
    );

    logger.info(
      `[Job:StatsSnapshot] Anlık görüntü kaydedildi: date=${today}, ` +
      `volume=${stats.total_volume_usdt.toFixed(2)}, trades=${stats.completed_trades}`
    );
  } catch (err) {
    logger.error(`[Job:StatsSnapshot] Görev başarısız oldu: ${err.message}`, { stack: err.stack });
  }
}

module.exports = {
  runStatsSnapshot,
  computeCurrentStats,
};
