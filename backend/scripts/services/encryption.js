"use strict";

/**
 * ArafEncryption — Envelope Encryption for PII (IBAN, Name, Telegram)
 *
 * Architecture:
 *   Master Key (env/KMS) → derives unique Data Encryption Key (DEK) per wallet
 *   DEK is NEVER stored. Re-derived on demand using HKDF.
 *   Encrypted data format: iv (12 bytes) + authTag (16 bytes) + ciphertext
 *
 *  Production'da KMS entegrasyonu zorunlu hale getirildi.
 * _getMasterKey() artık KMS_PROVIDER ortam değişkenine göre:
 *   - "aws"   → AWS KMS Decrypt API ile master key çözülür
 *   - "vault" → HashiCorp Vault Transit Engine'den master key alınır
 *   - "env"   → Sadece development'ta .env'den okunur (production'da engellenir)
 *
 * Fix: HKDF implementasyonu Node.js native crypto.hkdf() ile değiştirildi. Önceki implementasyon iki zincirlenmiş HMAC kullanıyordu (RFC 5869 uyumlu değil).
 * Mevcut şifreli veriler yeniden şifreleme gerektirir — migration planı yapılmalı.
 */

const crypto = require("crypto");
const { promisify } = require("util");
const logger = require("../utils/logger");

const ALGORITHM  = "aes-256-gcm";
const IV_LENGTH  = 12;    // GCM recommended
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;    // 256-bit

// Node.js native hkdf — callback tabanlı, promisify ile async kullanılır
const hkdfAsync = promisify(crypto.hkdf);

//  Master Key çözümleme cache'i
// KMS çağrıları her encrypt/decrypt'te yapılmasın diye bellek içi cache.
// Uygulama restart'ında otomatik temizlenir.
let _masterKeyCache = null;

/**
 *
 * Production'da master key'in .env'de plaintext durmaması için
 * KMS_PROVIDER ortam değişkeni kontrol edilir:
 *
 *   KMS_PROVIDER=env   → .env'den oku (SADECE development)
 *   KMS_PROVIDER=aws   → AWS KMS ile şifreli key'i çöz (production önerilir)
 *   KMS_PROVIDER=vault → HashiCorp Vault Transit Engine (alternatif production)
 *
 * @returns {Promise<Buffer>} 32-byte master key
 */
async function _getMasterKey() {
  // Cache varsa tekrar KMS'e gitme
  if (_masterKeyCache) return _masterKeyCache;

  const provider = (process.env.KMS_PROVIDER || "env").toLowerCase();

  // ENV Provider (Sadece Development)
  if (provider === "env") {
    // Production'da .env'den master key okunmasını engelle
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "SEC-01 BLOCKER: Production'da KMS_PROVIDER='env' kullanılamaz! " +
        "AWS KMS veya HashiCorp Vault kullanın. " +
        "Detay: .env'deki MASTER_ENCRYPTION_KEY sunucu ele geçirildiğinde tüm PII'ları açığa çıkarır."
      );
    }
    const hex = process.env.MASTER_ENCRYPTION_KEY;
    if (!hex || hex.length < 64) {
      throw new Error("MASTER_ENCRYPTION_KEY is missing or too short (need 32 bytes / 64 hex chars)");
    }
    _masterKeyCache = Buffer.from(hex.slice(0, 64), "hex");
    logger.warn("[Encryption] ⚠ Master key .env'den okunuyor — sadece development için!");
    return _masterKeyCache;
  }

  // ── AWS KMS Provider ─────────────────────────────────────────────────────
  // AWS KMS Envelope Encryption:
  //   1. KMS'te bir CMK (Customer Master Key) oluşturun
  //   2. CMK ile bir data key oluşturun: aws kms generate-data-key --key-id <CMK_ARN>
  //   3. Şifreli data key'i (CiphertextBlob) base64 olarak .env'e koyun
  //   4. Runtime'da KMS Decrypt API ile plaintext key'i alın
  //
  // .env'de gerekli değişkenler:
  //   KMS_PROVIDER=aws
  //   AWS_KMS_KEY_ARN=arn:aws:kms:eu-west-1:123456789:key/xxx-xxx-xxx
  //   AWS_ENCRYPTED_DATA_KEY=<base64-encoded CiphertextBlob>
  //   AWS_REGION=eu-west-1
  if (provider === "aws") {
    try {
      // Lazy import — sadece aws provider seçildiğinde yüklenir
      const { KMSClient, DecryptCommand } = require("@aws-sdk/client-kms");

      const region       = process.env.AWS_REGION || "eu-west-1";
      const encryptedKey = process.env.AWS_ENCRYPTED_DATA_KEY;

      if (!encryptedKey) {
        throw new Error("AWS_ENCRYPTED_DATA_KEY .env'de tanımlı değil");
      }

      const kms = new KMSClient({ region });
      const command = new DecryptCommand({
        CiphertextBlob: Buffer.from(encryptedKey, "base64"),
      });

      const response = await kms.send(command);
      _masterKeyCache = Buffer.from(response.Plaintext);

      logger.info("[Encryption] ✅ Master key AWS KMS'ten başarıyla çözüldü.");
      return _masterKeyCache;
    } catch (err) {
      throw new Error(`AWS KMS master key çözme hatası: ${err.message}`);
    }
  }

  // ── HashiCorp Vault Provider ─────────────────────────────────────────────
  // Vault Transit Secret Engine:
  //   1. Vault'ta transit engine enable edin: vault secrets enable transit
  //   2. Bir key oluşturun: vault write -f transit/keys/araf-master-key
  //   3. Data key oluşturun: vault write transit/datakey/plaintext/araf-master-key
  //   4. Plaintext (base64) key'i döner — bunu runtime'da her seferinde çağırın
  //
  // .env'de gerekli değişkenler:
  //   KMS_PROVIDER=vault
  //   VAULT_ADDR=https://vault.araf.xyz:8200
  //   VAULT_TOKEN=<vault-token>
  //   VAULT_KEY_NAME=araf-master-key
  if (provider === "vault") {
    try {
      const https     = require("https");
      const vaultAddr = process.env.VAULT_ADDR;
      const vaultToken= process.env.VAULT_TOKEN;
      const keyName   = process.env.VAULT_KEY_NAME || "araf-master-key";

      if (!vaultAddr || !vaultToken) {
        throw new Error("VAULT_ADDR ve VAULT_TOKEN .env'de tanımlı olmalı");
      }

      // Vault Transit: datakey endpoint'inden yeni plaintext key al
      const url = `${vaultAddr}/v1/transit/datakey/plaintext/${keyName}`;
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "X-Vault-Token": vaultToken,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        throw new Error(`Vault HTTP ${response.status}: ${await response.text()}`);
      }

      const data = await response.json();
      _masterKeyCache = Buffer.from(data.data.plaintext, "base64").slice(0, KEY_LENGTH);

      logger.info("[Encryption] ✅ Master key HashiCorp Vault'tan başarıyla alındı.");
      return _masterKeyCache;
    } catch (err) {
      throw new Error(`Vault master key alma hatası: ${err.message}`);
    }
  }

  throw new Error(`Bilinmeyen KMS_PROVIDER: "${provider}". Geçerli değerler: env, aws, vault`);
}

/**
 * Derives a wallet-specific DEK using HKDF (RFC 5869, SHA-256).
 * Same wallet always gets the same DEK — deterministic but unique per wallet.
 *
 * Fix: Node.js native crypto.hkdf() kullanılıyor (RFC 5869 tam uyumlu).
 * Önceki iki HMAC zinciri yerini aldı.
 *
 * @param {string} walletAddress - lowercase Ethereum address
 * @returns {Promise<Buffer>} 32-byte DEK
 */
async function _deriveDataKey(walletAddress) {
  // SEC-01 Fix: _getMasterKey artık async — KMS çağrıları için await gerekli
  const masterKey = await _getMasterKey();
  const salt      = Buffer.alloc(32, 0); // deterministic salt (wallet adresi info'da)
  const info      = Buffer.from(`araf-pii-${walletAddress.toLowerCase()}`);

  const dek = await hkdfAsync("sha256", masterKey, salt, info, KEY_LENGTH);
  return Buffer.from(dek);
}

/**
 * Encrypts a plaintext string for a specific wallet.
 *
 * @param {string} plaintext     - Data to encrypt (IBAN, name, etc.)
 * @param {string} walletAddress - lowercase Ethereum address (used for key derivation)
 * @returns {Promise<string>}    - Hex-encoded: iv + authTag + ciphertext
 */
async function encryptField(plaintext, walletAddress) {
  const dek = await _deriveDataKey(walletAddress);
  const iv  = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag       = cipher.getAuthTag();

  // Format: iv (12) + authTag (16) + ciphertext
  return Buffer.concat([iv, tag, encrypted]).toString("hex");
}

/**
 * Decrypts a hex-encoded ciphertext for a specific wallet.
 *
 * @param {string} cipherHex     - Hex string from encryptField()
 * @param {string} walletAddress - Must match the wallet used during encryption
 * @returns {Promise<string>}    - Original plaintext
 */
async function decryptField(cipherHex, walletAddress) {
  const dek  = await _deriveDataKey(walletAddress);
  const data = Buffer.from(cipherHex, "hex");

  const iv         = data.slice(0, IV_LENGTH);
  const tag        = data.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.slice(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(tag);

  return decipher.update(ciphertext) + decipher.final("utf8");
}

/**
 * Encrypts all PII fields for a user.
 *
 * @param {{ bankOwner: string, iban: string, telegram?: string }} rawPII
 * @param {string} walletAddress
 * @returns {Promise<{ bankOwner_enc: string, iban_enc: string, telegram_enc: string|null }>}
 */
async function encryptPII(rawPII, walletAddress) {
  const addr = walletAddress.toLowerCase();
  return {
    bankOwner_enc: rawPII.bankOwner ? await encryptField(rawPII.bankOwner, addr) : null,
    iban_enc:      rawPII.iban      ? await encryptField(rawPII.iban,      addr) : null,
    telegram_enc:  rawPII.telegram  ? await encryptField(rawPII.telegram,  addr) : null,
  };
}

/**
 * Decrypts all PII fields for a user.
 *
 * @param {{ bankOwner_enc: string, iban_enc: string, telegram_enc?: string }} encPII
 * @param {string} walletAddress
 * @returns {Promise<{ bankOwner: string, iban: string, telegram: string|null }>}
 */
async function decryptPII(encPII, walletAddress) {
  const addr = walletAddress.toLowerCase();
  return {
    bankOwner: encPII.bankOwner_enc ? await decryptField(encPII.bankOwner_enc, addr) : null,
    iban:      encPII.iban_enc      ? await decryptField(encPII.iban_enc,      addr) : null,
    telegram:  encPII.telegram_enc  ? await decryptField(encPII.telegram_enc,  addr) : null,
  };
}

/**
 * Graceful shutdown veya key rotation sırasında çağrılabilir.
 */
function clearMasterKeyCache() {
  if (_masterKeyCache) {
    // Hassas veriyi bellekten temizle (zero-fill)
    _masterKeyCache.fill(0);
    _masterKeyCache = null;
    logger.info("[Encryption] Master key cache temizlendi.");
  }
}

module.exports = { encryptPII, decryptPII, encryptField, decryptField, clearMasterKeyCache };
