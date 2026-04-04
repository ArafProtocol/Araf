"use strict";

const mongoose = require("mongoose");

/**
 * User Model
 *
 * KRİT-11 Fix: checkBanExpiry artık veritabanına kaydediyor.
 *   ÖNCEKİ: this.is_banned = false yapılıp await this.save() ÇAĞRILMIYORDU.
 *   Sadece bellekteki nesne değişiyordu — DB'de kullanıcı sonsuza kadar
 *   "yasaklı" kalıyordu. Kullanıcı oturum boyunca girebilir gibi görünse de
 *   sayfa her yenilendiğinde tekrar banlı görünüyordu.
 *   ŞİMDİ: Fonksiyon async yapıldı, DB güncellemesi yapıldı.
 *   auth.js içinde `if (await user.checkBanExpiry())` şeklinde çağrılmalı.
 *
 * Güvenlik tasarımı:
 *   - pii_data alanları AES-256-GCM şifreli (asla plaintext saklanmaz)
 *   - reputation_cache sadece görüntüleme amaçlı; yetkilendirmede KULLANILMAZ
 *   - Nonce'lar burada değil Redis'te saklanır (TTL ile)
 */
const userSchema = new mongoose.Schema(
  {
    wallet_address: {
      type:       String,
      required:   true,
      unique:     true,
      lowercase:  true,
      match:      /^0x[a-fA-F0-9]{40}$/,
      index:      true,
    },

    // ── Şifreli PII (AES-256-GCM) ────────────────────────────────────────────
    // Ham değerler ASLA saklanmaz. Service katmanında şifrelenerek kaydedilir.
    pii_data: {
      bankOwner_enc: { type: String, default: null },
      iban_enc:      { type: String, default: null },
      telegram_enc:  { type: String, default: null },
    },

    // ── İtibar Önbelleği (sadece görüntüleme — YETKİLENDİRMEDE KULLANILMAZ) ──
    // Gerçek itibar on-chain'de yaşar. Bu önbellek hızlı UI render içindir.
    reputation_cache: {
      success_rate:    { type: Number, default: 100, min: 0, max: 100 },
      total_trades:    { type: Number, default: 0,   min: 0 },
      failed_disputes: { type: Number, default: 0,   min: 0 },
      // [TR] Ağırlıklı başarısızlık puanı — 'burned' gibi ciddi olaylar daha yüksek puana sahip
      failure_score:   { type: Number, default: 0,   min: 0 },
    },

    // [TR] Başarısızlıkların zamanla etkisini yitirmesi için geçmiş kaydı
    // [EN] Historical record for failure decay over time
    // Örnek: [{ type: 'burned', score: 50, date: '...', tradeId: 123 }]
    reputation_history: {
      type:    [mongoose.Schema.Types.Mixed],
      default: [],
    },

    // ── Ban Durumu (on-chain yansıması — event listener tarafından güncellenir) ──
    is_banned:    { type: Boolean, default: false },
    banned_until: { type: Date,    default: null  },

    // [TR] H-03: Consecutive ban takibi — kontrat ile senkronize.
    // Bu alanlar display/cache amaçlıdır; otoriter değer on-chain'dir.
    consecutive_bans: { type: Number, default: 0, min: 0 },
    max_allowed_tier: { type: Number, default: 4, min: 0, max: 4 },

    // ── Aktivite ──────────────────────────────────────────────────────────────
    last_login: { type: Date, default: null },
  },
  {
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" },
    versionKey: false,
  }
);

// ── Index'ler ─────────────────────────────────────────────────────────────────
userSchema.index({ wallet_address: 1 });
userSchema.index({ is_banned: 1 });
// [TR] TTL index: 2 yıl hareketsiz kullanıcıyı sil (GDPR uyumu)
userSchema.index({ last_login: 1 }, { expireAfterSeconds: 2 * 365 * 24 * 3600 });

// ── Metodlar ──────────────────────────────────────────────────────────────────

/**
 * Public profil döndürür — PII veya şifreli alanlar içermez.
 * Fail-safe: Sadece açıkça belirlenen alanlar döner.
 * Gelecekte eklenen yeni alanların yanlışlıkla sızmasını önler.
 */
userSchema.methods.toPublicProfile = function () {
  return {
    wallet_address: this.wallet_address,
    reputation_cache: {
      success_rate:    this.reputation_cache.success_rate,
      total_trades:    this.reputation_cache.total_trades,
      failed_disputes: this.reputation_cache.failed_disputes,
      failure_score:   this.reputation_cache.failure_score,
    },
    is_banned:        this.is_banned,
    consecutive_bans: this.consecutive_bans,
    max_allowed_tier: this.max_allowed_tier,
    created_at:       this.created_at,
  };
};

/**
 * KRİT-11 Fix: Ban süresinin dolup dolmadığını kontrol eder ve DB'ye kaydeder.
 *
 * ÖNCEKİ: Senkron, save() yoktu → DB'de ban sonsuza kalıyordu.
 * ŞİMDİ: Async, ban kalkınca hem bellekte hem DB'de güncelleniyor.
 *
 * Kullanım (auth.js'te):
 *   if (await user.checkBanExpiry()) {
 *     // Ban kalktı, bilgi ver
 *   }
 *
 * @returns {Promise<boolean>} Ban kalktıysa true
 */
userSchema.methods.checkBanExpiry = async function () {
  if (this.is_banned && this.banned_until && new Date() > this.banned_until) {
    this.is_banned    = false;
    this.banned_until = null;
    // KRİT-11 Fix: Değişikliği veritabanına kaydet
    await this.save();
    return true; // Ban kalktı
  }
  return false;
};

module.exports = mongoose.model("User", userSchema);
