"use strict";

/**
 * SIWE (Sign-In with Ethereum) Authentication Service
 *
 * Flow:
 * 1. Frontend: GET /api/auth/nonce?address=0x...  -> receives nonce
 * 2. Frontend: Signs SIWE message with MetaMask
 * 3. Frontend: POST /api/auth/verify { message, signature }
 * 4. Backend:  Verifies signature -> issues JWT (15min) + refresh token
 *
 * Security:
 * - Nonce stored in Redis with 5-minute TTL (NOT MongoDB)
 * - Nonce invalidated immediately after use (prevents replay)
 * - JWT is short-lived (15 min); trade-scoped PII tokens even shorter
 */

const { SiweMessage }   = require("siwe");
const jwt               = require("jsonwebtoken");
const crypto            = require("crypto");
const { getRedisClient } = require("../config/redis");
const logger            = require("../utils/logger");

const JWT_SECRET      = process.env.JWT_SECRET;
const JWT_EXPIRES     = process.env.JWT_EXPIRES_IN      || "15m";
const PII_EXPIRES     = process.env.PII_TOKEN_EXPIRES_IN || "15m";
const NONCE_TTL_SECS  = 5 * 60; // 5 minutes

// Refresh token ayarları
const REFRESH_TOKEN_TTL_SECS = 7 * 24 * 60 * 60; // 7 gün
const REFRESH_TOKEN_PREFIX   = "refresh:";
const REFRESH_FAMILY_PREFIX = "family:";

//JWT_SECRET Entropy Doğrulaması
function _shannonEntropy(str) {
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const KNOWN_PLACEHOLDERS = [
  "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_MIN_64_CHARS",
  "your-secret-here",
  "supersecretkey",
  "changeme",
];

if (!JWT_SECRET) {
  throw new Error("SEC-02 BLOCKER: JWT_SECRET tanımlı değil! .env dosyasını kontrol edin.");
}
if (JWT_SECRET.length < 64) {
  throw new Error(
    `SEC-02 BLOCKER: JWT_SECRET çok kısa (${JWT_SECRET.length} karakter). ` +
    "Minimum 64 karakter (512-bit) gerekli. " +
    "Üretmek için: node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
  );
}
if (KNOWN_PLACEHOLDERS.some(p => JWT_SECRET.includes(p))) {
  throw new Error(
    "SEC-02 BLOCKER: JWT_SECRET hâlâ placeholder değer içeriyor! " +
    "Gerçek bir rastgele secret ile değiştirin."
  );
}
const entropy = _shannonEntropy(JWT_SECRET);
if (entropy < 3.5) {
  throw new Error(
    `SEC-02 BLOCKER: JWT_SECRET entropy çok düşük (${entropy.toFixed(2)}). ` +
    "Rastgele üretilmiş bir secret kullanın: " +
    "node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
  );
}
logger.info(`[Auth] JWT_SECRET doğrulandı: ${JWT_SECRET.length} karakter, entropy: ${entropy.toFixed(2)} bit`);

// Redis SCAN yardımcısı
/**
 * Redis KEYS yerine SCAN kullanarak pattern'a uyan anahtarları toplar.
 * KEYS O(N) bloklaması yapar ve production'da diğer işlemleri durdurabilir.
 * SCAN ise kursor tabanlıdır ve Redis'i bloklamaz.
 *
 * @param {object} redis  - Redis client instance
 * @param {string} pattern - SCAN pattern (örn: "family:0x...:")
 * @returns {Promise<string[]>} Eşleşen anahtarlar
 */
async function _scanKeys(redis, pattern) {
  const results = [];
  let cursor = 0;
  do {
    const reply = await redis.scan(cursor, { MATCH: pattern, COUNT: 100 });
    cursor = reply.cursor;
    results.push(...reply.keys);
  } while (cursor !== 0);
  return results;
}

// ─── Nonce Management (Redis) ─────────────────────────────────────────────────

async function generateNonce(walletAddress) {
  const redis  = getRedisClient();
  const nonce  = crypto.randomBytes(16).toString("hex");
  const key    = `nonce:${walletAddress.toLowerCase()}`;
  await redis.setEx(key, NONCE_TTL_SECS, nonce);
  logger.debug(`Nonce generated for ${walletAddress}`);
  return nonce;
}

async function consumeNonce(walletAddress) {
  const redis = getRedisClient();
  const key   = `nonce:${walletAddress.toLowerCase()}`;
  const nonce = await redis.getDel(key);
  return nonce;
}

// ─── SIWE Verification ────────────────────────────────────────────────────────

async function verifySiweSignature(messageStr, signature) {
  const message = new SiweMessage(messageStr);

  const expectedDomain = process.env.SIWE_DOMAIN || "localhost";
  if (message.domain !== expectedDomain) {
    throw new Error(`SIWE domain mismatch: expected ${expectedDomain}, got ${message.domain}`);
  }

  const storedNonce = await consumeNonce(message.address.toLowerCase());
  if (!storedNonce) {
    throw new Error("Nonce expired or not found");
  }
  if (message.nonce !== storedNonce) {
    throw new Error("Nonce mismatch");
  }

  const result = await message.verify({ signature });
  if (!result.success) {
    throw new Error("SIWE signature verification failed");
  }

  return message.address.toLowerCase();
}

// ─── JWT Token Management ─────────────────────────────────────────────────────

function issueJWT(walletAddress) {
  return jwt.sign(
    { sub: walletAddress.toLowerCase(), type: "auth" },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function issuePIIToken(walletAddress, tradeId) {
  return jwt.sign(
    { sub: walletAddress.toLowerCase(), type: "pii", tradeId },
    JWT_SECRET,
    { expiresIn: PII_EXPIRES }
  );
}

function verifyJWT(token) {
  return jwt.verify(token, JWT_SECRET);
}

// Refresh Token Management

async function issueRefreshToken(walletAddress, familyId = null) {
  const redis = getRedisClient();
  const token = crypto.randomBytes(32).toString("hex");
  const currentFamilyId = familyId || crypto.randomBytes(16).toString("hex");
  const familyKey = `${REFRESH_FAMILY_PREFIX}${walletAddress.toLowerCase()}:${currentFamilyId}`;
  const tokenKey = `${REFRESH_TOKEN_PREFIX}${token}`;

  const multi = redis.multi();
  multi.setEx(tokenKey, REFRESH_TOKEN_TTL_SECS, currentFamilyId);
  multi.sAdd(familyKey, token);
  multi.expire(familyKey, REFRESH_TOKEN_TTL_SECS);
  await multi.exec();
  
  logger.debug(`[Auth] Refresh token issued for ${walletAddress}`);
  return token;
}

async function rotateRefreshToken(walletAddress, refreshToken) {
  const redis = getRedisClient();
  const tokenKey = `${REFRESH_TOKEN_PREFIX}${refreshToken}`;

  const familyId = await redis.getDel(tokenKey);

  if (!familyId) {
    logger.warn(`[Auth] Geçersiz/kullanılmış refresh token denemesi: wallet=${walletAddress}. Tüm oturumlar sonlandırılıyor.`);
    
    const familyKeys = await _scanKeys(redis, `${REFRESH_FAMILY_PREFIX}${walletAddress.toLowerCase()}:*`);
    if (familyKeys.length > 0) {
      // Her ailedeki token'ları topla
      for (const familyKey of familyKeys) {
        const members = await redis.sMembers(familyKey);
        const multi = redis.multi();
        members.forEach(member => multi.del(`${REFRESH_TOKEN_PREFIX}${member}`));
        multi.del(familyKey);
        await multi.exec();
      }
    }
    throw new Error("Refresh token invalid or expired. Please login again.");
  }

  // Ailedeki diğer tüm token'ları sil (rotasyon)
  const familyKey = `${REFRESH_FAMILY_PREFIX}${walletAddress.toLowerCase()}:${familyId}`;
  const familyMembers = await redis.sMembers(familyKey);
  if (familyMembers.length > 0) {
    const multi = redis.multi();
    familyMembers.forEach(member => multi.del(`${REFRESH_TOKEN_PREFIX}${member}`));
    multi.del(familyKey);
    await multi.exec();
  }
  
  const newJWT          = issueJWT(walletAddress);
  const newRefreshToken = await issueRefreshToken(walletAddress, familyId);
  
  logger.info(`[Auth] Token rotated for ${walletAddress}`);
  return { token: newJWT, refreshToken: newRefreshToken };
}

/**
 * Bir cüzdanın tüm refresh token'larını iptal eder. Logout veya güvenlik ihlali durumunda kullanılır.
 * redis.keys() yerine _scanKeys() (SCAN tabanlı) kullanılıyor.
 *
 * @param {string} walletAddress
 */
async function revokeRefreshToken(walletAddress) {
  const redis = getRedisClient();
  const addr  = walletAddress.toLowerCase();

  // SCAN kullanarak bu cüzdana ait tüm aileleri bul
  const familyKeys = await _scanKeys(redis, `${REFRESH_FAMILY_PREFIX}${addr}:*`);

  if (familyKeys.length === 0) {
    logger.info(`[Auth] Revoke: ${addr} için aktif refresh token bulunamadı.`);
    return;
  }

  let deletedCount = 0;
  for (const familyKey of familyKeys) {
    const members = await redis.sMembers(familyKey);
    if (members.length > 0) {
      const multi = redis.multi();
      members.forEach(member => {
        multi.del(`${REFRESH_TOKEN_PREFIX}${member}`);
        deletedCount++;
      });
      multi.del(familyKey);
      await multi.exec();
    } else {
      await redis.del(familyKey);
    }
  }

  logger.info(`[Auth] Revoke: ${addr} için ${deletedCount} refresh token ve ${familyKeys.length} aile silindi.`);
}

module.exports = {
  generateNonce,
  consumeNonce,
  verifySiweSignature,
  issueJWT,
  issuePIIToken,
  verifyJWT,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
};
