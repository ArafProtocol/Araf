// ─── config/db.js ─────────────────────────────────────────────────────────────
"use strict";

const mongoose = require("mongoose");
const logger   = require("../utils/logger");

let isConnected = false;

async function connectDB() {
  if (isConnected) return;

  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI environment variable is required");

  await mongoose.connect(uri, {
    maxPoolSize:      10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS:  45000,
  });

  isConnected = true;
  logger.info(`[DB] Connected to MongoDB: ${uri.split("@").pop()}`); // Hide credentials
  mongoose.connection.on("error", (err) => logger.error(`[DB] Error: ${err}`));
  mongoose.connection.on("disconnected", () => {
    isConnected = false;
    logger.warn("[DB] Disconnected from MongoDB");
  });
}

module.exports = { connectDB };
