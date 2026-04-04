"use strict";

const { Trade } = require("../models/Trade");
const logger = require("../utils/logger");

async function runReceiptCleanup(now = new Date()) {
  try {
    const result = await Trade.updateMany(
      {
        "evidence.receipt_delete_at": { $lte: now },
        $or: [
          { "evidence.receipt_encrypted": { $ne: null } },
          { "evidence.receipt_timestamp": { $ne: null } },
        ],
      },
      {
        $set: {
          "evidence.receipt_encrypted": null,
          "evidence.receipt_timestamp": null,
        },
      }
    );

    if (result.modifiedCount > 0) {
      logger.info(`[Job:ReceiptCleanup] ${result.modifiedCount} trade kaydında dekont payload temizlendi.`);
    }
    return result.modifiedCount;
  } catch (err) {
    logger.error(`[Job:ReceiptCleanup] Temizlik başarısız: ${err.message}`);
    return 0;
  }
}

async function runPIISnapshotCleanup(now = new Date()) {
  try {
    const result = await Trade.updateMany(
      {
        "pii_snapshot.snapshot_delete_at": { $lte: now },
        $or: [
          { "pii_snapshot.maker_bankOwner_enc": { $ne: null } },
          { "pii_snapshot.maker_iban_enc": { $ne: null } },
          { "pii_snapshot.taker_bankOwner_enc": { $ne: null } },
        ],
      },
      {
        $set: {
          "pii_snapshot.maker_bankOwner_enc": null,
          "pii_snapshot.maker_iban_enc": null,
          "pii_snapshot.taker_bankOwner_enc": null,
          "pii_snapshot.captured_at": null,
        },
      }
    );

    if (result.modifiedCount > 0) {
      logger.info(`[Job:PIISnapshotCleanup] ${result.modifiedCount} trade kaydında snapshot PII temizlendi.`);
    }
    return result.modifiedCount;
  } catch (err) {
    logger.error(`[Job:PIISnapshotCleanup] Temizlik başarısız: ${err.message}`);
    return 0;
  }
}

module.exports = {
  runReceiptCleanup,
  runPIISnapshotCleanup,
};
