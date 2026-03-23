"use strict";

const mongoose = require("mongoose");

// ═══════════════════════════════════════════════════════════════════════════════
// LISTING MODEL — Pazar Yeri Vitrini
// ═══════════════════════════════════════════════════════════════════════════════

const listingSchema = new mongoose.Schema(
  {
    maker_address: {
      type:     String,
      required: true,
      lowercase: true,
      match:    /^0x[a-fA-F0-9]{40}$/,
      index:    true,
    },
    crypto_asset: {
      type:     String,
      required: true,
      enum:     ["USDT", "USDC"],
    },
    fiat_currency: {
      type:     String,
      required: true,
      enum:     ["TRY", "USD", "EUR"],
    },
    exchange_rate: {
      type:     Number,
      required: true,
      min:      0,
    },
    limits: {
      min: { type: Number, required: true, min: 0 },
      max: { type: Number, required: true, min: 0 },
    },
    tier_rules: {
      required_tier:   { type: Number, enum: [0, 1, 2, 3, 4], required: true },
      maker_bond_pct:  { type: Number, required: true },
      taker_bond_pct:  { type: Number, required: true },
    },
    status: {
      type:    String,
      enum:    ["OPEN", "PAUSED", "COMPLETED", "DELETED"],
      default: "OPEN",
      index:   true,
    },
    onchain_escrow_id: {
      type:    Number,
      default: null,
    },
    token_address: {
      type:    String,
      lowercase: true,
      default: null,
    },
  },
  {
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" },
    versionKey: false,
  }
);

listingSchema.index({ status: 1, fiat_currency: 1, "limits.min": 1, "limits.max": 1 });
listingSchema.index({ maker_address: 1, status: 1 });
listingSchema.index({ "tier_rules.required_tier": 1, status: 1 });

listingSchema.pre("save", function (next) {
  if (this.limits.max <= this.limits.min) {
    return next(new Error("limits.max must be greater than limits.min"));
  }
  next();
});

// ═══════════════════════════════════════════════════════════════════════════════
// TRADE MODEL — Aktif İşlemler ve Araf Odası
// ═══════════════════════════════════════════════════════════════════════════════

const tradeSchema = new mongoose.Schema(
  {
    onchain_escrow_id: {
      type:   Number,
      unique: true,
      sparse: true,
    },

    listing_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref:  "Listing",
    },

    maker_address: {
      type:      String,
      required:  true,
      lowercase: true,
      match:     /^0x[a-fA-F0-9]{40}$/,
    },
    taker_address: {
      type:      String,
      lowercase: true,
      match:     /^0x[a-fA-F0-9]{40}$/,
      default:   null,
    },

    financials: {
      crypto_amount:  { type: Number, required: true },
      fiat_amount:    { type: Number, default: null },
      exchange_rate:  { type: Number, required: true },
      crypto_asset:   { type: String, enum: ["USDT", "USDC"], required: true },
      fiat_currency:  { type: String, enum: ["TRY", "USD", "EUR"], required: true },
      total_decayed:  { type: Number, default: 0 },
    },

    status: {
      type:    String,
      enum:    ["OPEN", "LOCKED", "PAID", "CHALLENGED", "RESOLVED", "CANCELED", "BURNED"],
      default: "OPEN",
      index:   true,
    },

    timers: {
      locked_at:           { type: Date, default: null },
      paid_at:             { type: Date, default: null },
      challenged_at:       { type: Date, default: null },
      resolved_at:         { type: Date, default: null },
      last_decay_at:       { type: Date, default: null },
      pinged_at:           { type: Date, default: null },
      challenge_pinged_at: { type: Date, default: null },
    },

    pinged_by_taker:           { type: Boolean, default: false },
    challenge_pinged_by_maker: { type: Boolean, default: false },

    evidence: {
      // [TR] Kontrata giden hash: SHA-256(encrypted_data).
      //      "ipfs" prefix'i tarihsel — gerçek IPFS kullanılmıyor.
      //      Dekont public IPFS'e yüklenmez; backend'de AES-256-GCM ile şifrelenir.
      // [EN] Hash sent to contract: SHA-256(encrypted_data).
      //      "ipfs" prefix is historical — real IPFS is not used.
      //      Receipt is NOT on public IPFS; encrypted AES-256-GCM on backend.
      ipfs_receipt_hash: { type: String, default: null },

      // [TR] AES-256-GCM şifreli dekont verisi (base64 → encryptField → hex).
      //      encryption.js encryptField() ile taker wallet DEK'i kullanılarak şifrelenir.
      //      RESOLVED/CANCELED → 24 saat, CHALLENGED/BURNED → 30 gün sonra null'a çekilir.
      // [EN] AES-256-GCM encrypted receipt data (base64 → encryptField → hex).
      //      Encrypted via encryption.js encryptField() using taker wallet DEK.
      //      Set to null 24h after RESOLVED/CANCELED, 30d after CHALLENGED/BURNED.
      receipt_encrypted: { type: String, default: null },

      receipt_timestamp: { type: Date, default: null },

      // [TR] Şifreli verinin silineceği tarih.
      //      eventListener, trade sonuçlandığında bu alanı set eder.
      //      Silinme: cleanupReceipts job'u bu alana göre receipt_encrypted'ı null'lar.
      // [EN] Date when encrypted data must be deleted.
      //      Set by eventListener when trade concludes.
      //      Cleanup: cleanupReceipts job nulls receipt_encrypted based on this field.
      receipt_delete_at: { type: Date, default: null },
    },

    cancel_proposal: {
      proposed_by:     { type: String, lowercase: true, default: null },
      maker_signed:    { type: Boolean, default: false },
      taker_signed:    { type: Boolean, default: false },
      maker_signature: { type: String, default: null },
      taker_signature: { type: String, default: null },
      deadline:        { type: Date,   default: null },
    },

    chargeback_ack: {
      acknowledged:    { type: Boolean, default: false },
      acknowledged_by: { type: String,  lowercase: true, default: null },
      acknowledged_at: { type: Date,    default: null },
      ip_hash:         { type: String,  default: null },
    },

    tier: { type: Number, enum: [0, 1, 2, 3, 4], required: true },
  },
  {
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" },
    versionKey: false,
  }
);

// ── Indexes ───────────────────────────────────────────────────────────────────
tradeSchema.index({ maker_address: 1, status: 1 });
tradeSchema.index({ taker_address: 1, status: 1 });
tradeSchema.index({ onchain_escrow_id: 1 });

// [TR] Trade'leri 1 yıl sonra sil — GDPR uyumu
// [EN] Delete trades after 1 year — GDPR compliance
tradeSchema.index(
  { "timers.resolved_at": 1 },
  {
    expireAfterSeconds: 365 * 24 * 3600,
    partialFilterExpression: { status: { $in: ["RESOLVED", "CANCELED", "BURNED"] } },
  }
);

// [TR] receipt_delete_at dolunca temizlenecek trade'leri bulmak için sparse index.
//      MongoDB TTL dokümanı siler, field'ı değil — cleanup job bu index'i kullanır.
// [EN] Sparse index to find trades with expired receipts for cleanup.
//      MongoDB TTL deletes documents, not fields — cleanup job uses this index.
tradeSchema.index({ "evidence.receipt_delete_at": 1 }, { sparse: true });

// ── Virtuals ─────────────────────────────────────────────────────────────────
tradeSchema.virtual("isInGracePeriod").get(function () {
  if (this.status !== "CHALLENGED" || !this.timers.challenged_at) return false;
  return Date.now() - this.timers.challenged_at.getTime() < 48 * 3600 * 1000;
});

tradeSchema.virtual("isInBleedingPhase").get(function () {
  if (this.status !== "CHALLENGED" || !this.timers.challenged_at) return false;
  return Date.now() - this.timers.challenged_at.getTime() >= 48 * 3600 * 1000;
});

module.exports = {
  Listing: mongoose.model("Listing", listingSchema),
  Trade:   mongoose.model("Trade",   tradeSchema),
};
