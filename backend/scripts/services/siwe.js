"use strict";
/**
 * SIWE Authentication Service
 *
 ## siwe.js hardening

This PR updates `backend/scripts/services/siwe.js` to make nonce issuance safer and more authoritative under race conditions.

### Previous behavior
`generateNonce()` checked for an existing nonce, but after generating a new nonce it called Redis `SET NX` without verifying whether the write actually succeeded.

That created a race condition:

- two concurrent requests for the same wallet could both generate different nonces
- one request could lose the `NX` write
- but still return its own locally generated nonce
- Redis would contain a different nonce than the one returned to the client

This could break SIWE verification even when the user flow looked valid from the frontend.

### New behavior
`generateNonce()` now treats Redis as the source of truth:

- if a nonce already exists, it is reused
- if no nonce exists, a new nonce is generated and written with `SET NX`
- if `NX` fails, the function no longer returns the local nonce
- instead, it re-reads the actual nonce from Redis and returns that value
- if Redis still does not contain a nonce after the failed `NX`, the function throws a safe retry error

### Effect
This makes nonce issuance authoritative under concurrency and removes nonce drift between the app and Redis.*/
const { SiweMessage } = require("siwe");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { getRedisClient } = require("../config/redis");
const logger = require("../utils/logger");

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "15m";
const PII_EXPIRES = process.env.PII_TOKEN_EXPIRES_IN || "15m";
const NONCE_TTL_SECS = 5 * 60; // 5 dakika

// JWT blacklist TTL hesabı için kullanılır.
const JWT_EXPIRES_MS = 15 * 60 * 1000; // 15 dakika

const REFRESH_TOKEN_TTL_SECS = 7 * 24 * 60 * 60; // 7 gün
const REFRESH_TOKEN_PREFIX = "refresh:";
const REFRESH_FAMILY_PREFIX = "family:";
const JWT_BLACKLIST_PREFIX = "blacklist:jti:";

function getSiweConfig() {
  const domainRaw = process.env.SIWE_DOMAIN;
  const uriRaw = process.env.SIWE_URI;
  const isProduction = process.env.NODE_ENV === "production";

  if (isProduction) {
    if (!domainRaw) throw new Error("SIWE_DOMAIN production ortamında zorunludur.");
    if (!uriRaw) throw new Error("SIWE_URI production ortamında zorunludur.");

    if (domainRaw === "localhost") {
      throw new Error("SIWE_DOMAIN production'da localhost olamaz.");
    }

    let parsedUri;
    try {
      parsedUri = new URL(uriRaw);
    } catch {
      throw new Error("SIWE_URI geçerli bir URL olmalıdır.");
    }

    if (parsedUri.protocol !== "https:") {
      throw new Error("SIWE_URI production'da https olmalıdır.");
    }
    if (parsedUri.host !== domainRaw) {
      throw new Error(`SIWE config uyuşmazlığı: SIWE_URI host=${parsedUri.host}, SIWE_DOMAIN=${domainRaw}`);
    }
  }

  const domain = domainRaw || "localhost";
  const uri = uriRaw || `https://${domain}`;
  return { domain, uri };
}

// JWT secret kalite kontrolü
function _shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
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

if (!JWT_SECRET) throw new Error("SEC-02: JWT_SECRET tanımlı değil!");
if (JWT_SECRET.length < 64) {
  throw new Error(`SEC-02: JWT_SECRET çok kısa (${JWT_SECRET.length} karakter). Min 64 gerekli.`);
}
if (KNOWN_PLACEHOLDERS.some((p) => JWT_SECRET.includes(p))) {
  throw new Error("SEC-02: JWT_SECRET placeholder içeriyor!");
}
if (_shannonEntropy(JWT_SECRET) < 3.5) {
  throw new Error("SEC-02: JWT_SECRET entropy çok düşük.");
}

logger.info(
  `[Auth] JWT_SECRET doğrulandı: ${JWT_SECRET.length} karakter, entropy: ${_shannonEntropy(JWT_SECRET).toFixed(2)}`
);

// KEYS yerine SCAN kullanılır; Redis'i bloklamaz.
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

// Geçerli nonce varsa yeniden üretmeyiz.
// Yarış durumunda Redis'te gerçekten yaşayan nonce authoritative kabul edilir.
async function generateNonce(walletAddress) {
  const redis = getRedisClient();
  const key = `nonce:${walletAddress.toLowerCase()}`;

  const existing = await redis.get(key);
  if (existing) {
    logger.debug(`[Auth] Mevcut nonce kullanılıyor: ${walletAddress}`);
    return existing;
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  const setResult = await redis.set(key, nonce, { NX: true, EX: NONCE_TTL_SECS });

  if (setResult === null) {
    const racedNonce = await redis.get(key);

    if (!racedNonce) {
      throw new Error("Nonce üretilemedi. Lütfen tekrar deneyin.");
    }

    logger.debug(`[Auth] Nonce race condition çözüldü, mevcut nonce kullanılıyor: ${walletAddress}`);
    return racedNonce;
  }

  logger.debug(`[Auth] Yeni nonce üretildi: ${walletAddress}`);
  return nonce;
}

async function consumeNonce(walletAddress) {
  const redis = getRedisClient();
  const key = `nonce:${walletAddress.toLowerCase()}`;
  return redis.getDel(key);
}

async function verifySiweSignature(messageStr, signature) {
  const message = new SiweMessage(messageStr);
  const { domain: expectedDomain, uri: expectedUri } = getSiweConfig();

  if (message.domain !== expectedDomain) {
    throw new Error(`SIWE domain uyuşmazlığı: beklenen ${expectedDomain}, gelen ${message.domain}`);
  }

  let parsedIncoming = null;
  let parsedExpected = null;

  try {
    parsedIncoming = new URL(message.uri);
    parsedExpected = new URL(expectedUri);
  } catch {
    throw new Error("SIWE URI formatı geçersiz.");
  }

  if (parsedIncoming.origin !== parsedExpected.origin) {
    logger.warn(
      `[Auth] SIWE URI origin uyuşmazlığı: beklenen ${parsedExpected.origin}, gelen ${parsedIncoming.origin}`
    );
    throw new Error(`SIWE URI uyuşmazlığı: beklenen origin ${parsedExpected.origin}`);
  }

  const storedNonce = await consumeNonce(message.address.toLowerCase());
  if (!storedNonce) throw new Error("Nonce süresi dolmuş veya bulunamadı.");
  if (message.nonce !== storedNonce) throw new Error("Nonce uyuşmazlığı.");

  const result = await message.verify({ signature });
  if (!result.success) throw new Error("SIWE imza doğrulaması başarısız.");

  return message.address.toLowerCase();
}

function issueJWT(walletAddress) {
  const jti = crypto.randomBytes(16).toString("hex");
  return jwt.sign(
    { sub: walletAddress.toLowerCase(), type: "auth", jti },
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

async function isJWTBlacklisted(jti) {
  if (!jti) return false;

  try {
    const redis = getRedisClient();
    const val = await redis.get(`${JWT_BLACKLIST_PREFIX}${jti}`);
    return val !== null;
  } catch (err) {
    const failMode =
      process.env.JWT_BLACKLIST_FAIL_MODE ||
      (process.env.NODE_ENV === "production" ? "closed" : "open");

    logger.warn(`[Auth] JWT blacklist kontrolü yapılamadı (mode=${failMode}): ${err.message}`);
    return failMode === "closed";
  }
}

async function blacklistJWT(token) {
  try {
    const payload = jwt.decode(token);
    if (!payload?.jti) return;

    const redis = getRedisClient();
    const ttlSecs = Math.ceil(JWT_EXPIRES_MS / 1000);

    await redis.setEx(`${JWT_BLACKLIST_PREFIX}${payload.jti}`, ttlSecs, "1");
    logger.debug(`[Auth] JWT blacklist'e alındı: jti=${payload.jti}`);
  } catch (err) {
    logger.warn(`[Auth] JWT blacklist eklenemedi: ${err.message}`);
  }
}

// Refresh token değeri familyId ve wallet ile birlikte saklanır.
async function issueRefreshToken(walletAddress, familyId = null) {
  const redis = getRedisClient();
  const token = crypto.randomBytes(32).toString("hex");
  const currentFamilyId = familyId || crypto.randomBytes(16).toString("hex");
  const normalizedWallet = walletAddress.toLowerCase();
  const familyKey = `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:${currentFamilyId}`;
  const tokenKey = `${REFRESH_TOKEN_PREFIX}${token}`;

  const multi = redis.multi();
  multi.setEx(
    tokenKey,
    REFRESH_TOKEN_TTL_SECS,
    JSON.stringify({
      familyId: currentFamilyId,
      wallet: normalizedWallet,
    })
  );
  multi.sAdd(familyKey, token);
  multi.expire(familyKey, REFRESH_TOKEN_TTL_SECS);
  await multi.exec();

  logger.debug(`[Auth] Refresh token üretildi: ${walletAddress}`);
  return token;
}

// Normal rotasyonda yalnız ilgili aile temizlenir.
// Reuse şüphesinde aynı wallet'a ait aileler kapatılır.
async function rotateRefreshToken(walletAddress, refreshToken) {
  const redis = getRedisClient();
  const normalizedWallet = walletAddress.toLowerCase();
  const tokenKey = `${REFRESH_TOKEN_PREFIX}${refreshToken}`;

  const stored = await redis.getDel(tokenKey);

  if (!stored) {
    logger.warn(
      `[Auth] Geçersiz/kullanılmış token denemesi: wallet=${walletAddress}. Aile oturumları temizleniyor.`
    );

    const familyKeys = await _scanKeys(redis, `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:*`);
    for (const familyKey of familyKeys) {
      const members = await redis.sMembers(familyKey);
      const multi = redis.multi();
      members.forEach((m) => multi.del(`${REFRESH_TOKEN_PREFIX}${m}`));
      multi.del(familyKey);
      await multi.exec();
    }

    throw new Error("Refresh token geçersiz veya süresi dolmuş. Lütfen yeniden giriş yapın.");
  }

  let storedData;
  try {
    storedData = JSON.parse(stored);
  } catch {
    storedData = { familyId: stored, wallet: normalizedWallet };
  }

  if (storedData.wallet !== normalizedWallet) {
    logger.error(
      `[Auth] KRİTİK: Token/wallet uyuşmazlığı — muhtemel hijack girişimi! ` +
      `token_wallet=${storedData.wallet} istek_wallet=${walletAddress}`
    );
    throw new Error("Token/wallet uyuşmazlığı. Güvenlik ihlali tespit edildi.");
  }

  const { familyId } = storedData;
  const familyKey = `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:${familyId}`;
  const familyMembers = await redis.sMembers(familyKey);

  if (familyMembers.length > 0) {
    const multi = redis.multi();
    familyMembers.forEach((m) => multi.del(`${REFRESH_TOKEN_PREFIX}${m}`));
    multi.del(familyKey);
    await multi.exec();
  }

  const newJWT = issueJWT(walletAddress);
  const newRefreshToken = await issueRefreshToken(walletAddress, familyId);

  logger.info(`[Auth] Token rotasyonu tamamlandı: ${walletAddress}`);
  return { token: newJWT, refreshToken: newRefreshToken };
}

async function revokeRefreshToken(walletAddress) {
  const redis = getRedisClient();
  const addr = walletAddress.toLowerCase();

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
      members.forEach((m) => {
        multi.del(`${REFRESH_TOKEN_PREFIX}${m}`);
        deletedCount++;
      });
      multi.del(familyKey);
      await multi.exec();
    } else {
      await redis.del(familyKey);
    }
  }

  logger.info(`[Auth] Revoke: ${addr} → ${deletedCount} token, ${familyKeys.length} aile silindi.`);
}

module.exports = {
  getSiweConfig,
  generateNonce,
  consumeNonce,
  verifySiweSignature,
  issueJWT,
  issuePIIToken,
  verifyJWT,
  isJWTBlacklisted,
  blacklistJWT,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
};
