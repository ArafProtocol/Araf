"use strict";

/**
 * DLQ Processor — Dead Letter Queue Monitor + Re-drive Worker
 *
 * Başarısız event'ler eventListener tarafından Redis DLQ'ya rPush ile yazılır.
 * Bu processor entry'leri yeniden sürer (re-drive), başarılı olanları siler,
 * başarısızları exponential backoff ile kuyrukta tutar.
 */

const { getRedisClient } = require("../config/redis");
const eventWorker        = require("./eventListener");
const logger             = require("../utils/logger");

const DLQ_KEY              = "worker:dlq";
const DLQ_ARCHIVE_KEY      = "worker:dlq:archive"; // İnceleme için arşiv (7 gün TTL)
const ALERT_THRESHOLD      = 5;
const MAX_DLQ_SIZE         = 100;
const BATCH_SIZE           = 10;
const MAX_REDRIVE_ATTEMPTS = 10;
const BASE_BACKOFF_MS      = 30_000;
const ALERT_COOLDOWN_MS    = 10 * 60 * 1000;

let _lastAlertTimestamp = 0;
let _redriveSuccess     = 0;
let _redriveFailure     = 0;

function getRetrySuccessRate() {
  const total = _redriveSuccess + _redriveFailure;
  if (!total) return 100;
  return Math.round((_redriveSuccess / total) * 100);
}

function getBackoffMs(attempt) {
  return Math.min(BASE_BACKOFF_MS * (2 ** Math.max(attempt - 1, 0)), 30 * 60 * 1000);
}

function parseEntry(raw) {
  const entry = JSON.parse(raw);
  return {
    ...entry,
    attempt: Number(entry.attempt || 0),
    next_retry_at: entry.next_retry_at || new Date(0).toISOString(),
    first_seen_at: entry.first_seen_at || new Date().toISOString(),
  };
}

function isReady(entry, now) {
  const dueAt = new Date(entry.next_retry_at).getTime();
  if (Number.isNaN(dueAt)) return true;
  return dueAt <= now;
}

function toRaw(entry) {
  return JSON.stringify(entry);
}

async function archiveOverflow(redis, length) {
  if (length <= MAX_DLQ_SIZE) return;

  const overflow = length - MAX_DLQ_SIZE;
  const oldEntries = await redis.lRange(DLQ_KEY, 0, overflow - 1);
  if (oldEntries.length === 0) return;

  const multi = redis.multi();
  for (const entry of oldEntries) {
    multi.lPush(DLQ_ARCHIVE_KEY, entry);
  }
  multi.lTrim(DLQ_ARCHIVE_KEY, 0, 999);
  multi.expire(DLQ_ARCHIVE_KEY, 7 * 24 * 3600);
  multi.lTrim(DLQ_KEY, overflow, -1);
  await multi.exec();

  logger.info(`[DLQ] ${oldEntries.length} eski entry arşive taşındı, DLQ ${MAX_DLQ_SIZE}'a kırpıldı.`);
}

async function processDLQ() {
  try {
    const redis  = getRedisClient();
    let length   = await redis.lLen(DLQ_KEY);

    if (length === 0) {
      logger.debug("[DLQ] Kuyruk temiz.");
      return;
    }

    await archiveOverflow(redis, length);
    length = await redis.lLen(DLQ_KEY);

    const now = Date.now();
    const entries = await redis.lRange(DLQ_KEY, 0, BATCH_SIZE - 1);

    let poisonCount = 0;

    for (const raw of entries) {
      let entry;
      try {
        entry = parseEntry(raw);
      } catch {
        logger.error(`[DLQ] Ham entry parse edilemedi: ${raw}`);
        await redis.lRem(DLQ_KEY, 1, raw);
        continue;
      }

      if (!isReady(entry, now)) {
        continue;
      }

      const idempotencyKey = entry.idempotencyKey || `${entry.txHash}:${entry.logIndex ?? -1}`;
      logger.warn(
        `[DLQ] Re-drive başlıyor event=${entry.eventName} key=${idempotencyKey} ` +
        `attempt=${entry.attempt} queue_depth=${length}`
      );

      const result = await eventWorker.reDriveEvent(entry);

      if (result.success) {
        _redriveSuccess += 1;
        await redis.lRem(DLQ_KEY, 1, raw);
        logger.info(
          `[DLQ][Metrics] re-drive success event=${entry.eventName} key=${idempotencyKey} ` +
          `retry_success_rate=${getRetrySuccessRate()}%`
        );
        continue;
      }

      _redriveFailure += 1;
      const nextAttempt = entry.attempt + 1;
      const backoffMs = getBackoffMs(nextAttempt);
      const nextRetryAt = new Date(Date.now() + backoffMs).toISOString();

      const updated = {
        ...entry,
        attempt: nextAttempt,
        next_retry_at: nextRetryAt,
        last_error: result.error || entry.last_error || "Re-drive sırasında hata",
      };

      await redis.lRem(DLQ_KEY, 1, raw);
      await redis.rPush(DLQ_KEY, toRaw(updated));

      if (nextAttempt >= MAX_REDRIVE_ATTEMPTS) {
        poisonCount += 1;
        logger.error(
          `[DLQ][Metrics] poison_event_count=1 event=${entry.eventName} key=${idempotencyKey} ` +
          `attempt=${nextAttempt}`
        );
      }

      logger.warn(
        `[DLQ] Re-drive başarısız event=${entry.eventName} key=${idempotencyKey} ` +
        `next_retry_at=${nextRetryAt} retry_success_rate=${getRetrySuccessRate()}%`
      );
    }

    const newDepth = await redis.lLen(DLQ_KEY);
    logger.info(`[DLQ][Metrics] queue_depth=${newDepth} retry_success_rate=${getRetrySuccessRate()}% poison_event_count=${poisonCount}`);

    if (newDepth >= ALERT_THRESHOLD) {
      const nowMs = Date.now();
      if (nowMs - _lastAlertTimestamp >= ALERT_COOLDOWN_MS) {
        _lastAlertTimestamp = nowMs;
        logger.error(`[DLQ] ⚠ KRİTİK: DLQ'da ${newDepth} event birikti! Manuel müdahale gerekebilir.`);
      }
    }
  } catch (err) {
    logger.error(`[DLQ] Processor hatası: ${err.message}`, { stack: err.stack });
  }
}

module.exports = { processDLQ };
