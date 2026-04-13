'use strict'

const { SiweMessage } = require('siwe')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { getRedisClient } = require('../config/redis')
const logger = require('../utils/logger')

const JWT_SECRET = process.env.JWT_SECRET
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '15m'
const FRAME_TOKEN_EXPIRES = process.env.FRAME_TOKEN_EXPIRES_IN || '5m'
const PII_EXPIRES = process.env.PII_TOKEN_EXPIRES_IN || '15m'
const NONCE_TTL_SECS = 5 * 60
const JWT_BLACKLIST_PREFIX = 'blacklist:jti:'
const REFRESH_TOKEN_PREFIX = 'refresh:'
const REFRESH_FAMILY_PREFIX = 'family:'
const REFRESH_TOKEN_TTL_SECS = 7 * 24 * 60 * 60

if (!JWT_SECRET || JWT_SECRET.length < 64) {
  throw new Error('JWT_SECRET tanımlı değil veya çok kısa.')
}

function getSiweConfig() {
  const domainRaw = process.env.SIWE_DOMAIN
  const uriRaw = process.env.SIWE_URI
  const isProduction = process.env.NODE_ENV === 'production'

  if (isProduction) {
    if (!domainRaw) throw new Error('SIWE_DOMAIN production ortamında zorunludur.')
    if (!uriRaw) throw new Error('SIWE_URI production ortamında zorunludur.')
    const parsedUri = new URL(uriRaw)
    if (parsedUri.protocol !== 'https:') {
      throw new Error("SIWE_URI production'da https olmalıdır.")
    }
    if (parsedUri.host !== domainRaw) {
      throw new Error('SIWE_DOMAIN ve SIWE_URI host uyuşmuyor.')
    }
  }

  const domain = domainRaw || 'localhost'
  const uri = uriRaw || `http://${domain}`
  return { domain, uri }
}

async function scanKeys(redis, pattern) {
  const keys = []
  let cursor = 0
  do {
    const reply = await redis.scan(cursor, { MATCH: pattern, COUNT: 100 })
    cursor = reply.cursor
    keys.push(...reply.keys)
  } while (cursor !== 0)
  return keys
}

async function generateNonce(walletAddress) {
  const redis = getRedisClient()
  const key = `nonce:${walletAddress.toLowerCase()}`
  const existing = await redis.get(key)
  if (existing) return existing

  const nonce = crypto.randomBytes(16).toString('hex')
  const setResult = await redis.set(key, nonce, { NX: true, EX: NONCE_TTL_SECS })
  if (setResult === null) {
    const racedNonce = await redis.get(key)
    if (!racedNonce) throw new Error('Nonce üretilemedi. Lütfen tekrar deneyin.')
    return racedNonce
  }
  return nonce
}

async function consumeNonce(walletAddress) {
  const redis = getRedisClient()
  return redis.getDel(`nonce:${walletAddress.toLowerCase()}`)
}

async function verifySiweSignature(messageStr, signature) {
  const message = new SiweMessage(messageStr)
  const { domain: expectedDomain, uri: expectedUri } = getSiweConfig()

  if (message.domain !== expectedDomain) {
    throw new Error('SIWE domain uyuşmazlığı.')
  }

  const incoming = new URL(message.uri)
  const expected = new URL(expectedUri)
  if (incoming.origin !== expected.origin) {
    throw new Error('SIWE URI origin uyuşmazlığı.')
  }

  const storedNonce = await consumeNonce(message.address.toLowerCase())
  if (!storedNonce) throw new Error('Nonce süresi dolmuş veya bulunamadı.')
  if (message.nonce !== storedNonce) throw new Error('Nonce uyuşmazlığı.')

  const result = await message.verify({ signature })
  if (!result.success) throw new Error('SIWE imza doğrulaması başarısız.')

  return message.address.toLowerCase()
}

function signToken(payload, expiresIn) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn })
}

function issueJWT(walletAddress) {
  return signToken({ sub: walletAddress.toLowerCase(), type: 'auth', jti: crypto.randomBytes(16).toString('hex') }, JWT_EXPIRES)
}

function issueFrameToken(walletAddress) {
  return signToken({ sub: walletAddress.toLowerCase(), type: 'frame', jti: crypto.randomBytes(16).toString('hex') }, FRAME_TOKEN_EXPIRES)
}

function issuePIIToken(walletAddress, tradeId) {
  return signToken({ sub: walletAddress.toLowerCase(), type: 'pii', tradeId }, PII_EXPIRES)
}

function verifyJWT(token) {
  return jwt.verify(token, JWT_SECRET)
}

async function isJWTBlacklisted(jti) {
  if (!jti) return false
  try {
    const redis = getRedisClient()
    return (await redis.get(`${JWT_BLACKLIST_PREFIX}${jti}`)) !== null
  } catch (err) {
    logger.warn(`[Auth] JWT blacklist kontrolü yapılamadı: ${err.message}`)
    return process.env.NODE_ENV === 'production'
  }
}

async function blacklistJWT(token) {
  try {
    const payload = jwt.decode(token)
    if (!payload?.jti) return
    const redis = getRedisClient()
    await redis.setEx(`${JWT_BLACKLIST_PREFIX}${payload.jti}`, 15 * 60, '1')
  } catch (err) {
    logger.warn(`[Auth] JWT blacklist eklenemedi: ${err.message}`)
  }
}

async function issueRefreshToken(walletAddress, familyId = null) {
  const redis = getRedisClient()
  const token = crypto.randomBytes(32).toString('hex')
  const currentFamilyId = familyId || crypto.randomBytes(16).toString('hex')
  const normalizedWallet = walletAddress.toLowerCase()
  const familyKey = `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:${currentFamilyId}`
  const tokenKey = `${REFRESH_TOKEN_PREFIX}${token}`

  const multi = redis.multi()
  multi.setEx(tokenKey, REFRESH_TOKEN_TTL_SECS, JSON.stringify({ familyId: currentFamilyId, wallet: normalizedWallet }))
  multi.sAdd(familyKey, token)
  multi.expire(familyKey, REFRESH_TOKEN_TTL_SECS)
  await multi.exec()
  return token
}

async function rotateRefreshToken(walletAddress, refreshToken) {
  const redis = getRedisClient()
  const normalizedWallet = walletAddress.toLowerCase()
  const tokenKey = `${REFRESH_TOKEN_PREFIX}${refreshToken}`
  const stored = await redis.getDel(tokenKey)

  if (!stored) {
    const familyKeys = await scanKeys(redis, `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:*`)
    for (const familyKey of familyKeys) {
      const members = await redis.sMembers(familyKey)
      const multi = redis.multi()
      members.forEach((member) => multi.del(`${REFRESH_TOKEN_PREFIX}${member}`))
      multi.del(familyKey)
      await multi.exec()
    }
    throw new Error('Refresh token geçersiz veya süresi dolmuş. Lütfen yeniden giriş yapın.')
  }

  const parsed = JSON.parse(stored)
  if (parsed.wallet !== normalizedWallet) {
    throw new Error('Token ve wallet eşleşmiyor.')
  }

  const familyKey = `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:${parsed.familyId}`
  const familyMembers = await redis.sMembers(familyKey)
  if (familyMembers.length > 0) {
    const multi = redis.multi()
    familyMembers.forEach((member) => multi.del(`${REFRESH_TOKEN_PREFIX}${member}`))
    multi.del(familyKey)
    await multi.exec()
  }

  return {
    token: issueJWT(walletAddress),
    refreshToken: await issueRefreshToken(walletAddress, parsed.familyId),
  }
}

async function revokeRefreshToken(walletAddress) {
  const redis = getRedisClient()
  const normalizedWallet = walletAddress.toLowerCase()
  const familyKeys = await scanKeys(redis, `${REFRESH_FAMILY_PREFIX}${normalizedWallet}:*`)

  for (const familyKey of familyKeys) {
    const members = await redis.sMembers(familyKey)
    const multi = redis.multi()
    members.forEach((member) => multi.del(`${REFRESH_TOKEN_PREFIX}${member}`))
    multi.del(familyKey)
    await multi.exec()
  }
}

module.exports = {
  getSiweConfig,
  generateNonce,
  consumeNonce,
  verifySiweSignature,
  issueJWT,
  issueFrameToken,
  issuePIIToken,
  verifyJWT,
  isJWTBlacklisted,
  blacklistJWT,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
}
