'use strict'

const { verifyJWT, isJWTBlacklisted, revokeRefreshToken } = require('../services/siwe')
const logger = require('../utils/logger')

async function getTokenPayload(req) {
  const cookieToken = req.cookies?.araf_jwt
  if (cookieToken) {
    const payload = verifyJWT(cookieToken)
    if (payload.jti && (await isJWTBlacklisted(payload.jti))) {
      const err = new Error('Oturum geçersiz kılınmış. Lütfen yeniden giriş yapın.')
      err.statusCode = 401
      throw err
    }
    return { payload, source: 'cookie', rawToken: cookieToken }
  }

  const authHeader = req.headers.authorization
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const bearerToken = authHeader.slice(7)
    const payload = verifyJWT(bearerToken)
    if (payload.jti && (await isJWTBlacklisted(payload.jti))) {
      const err = new Error('Oturum geçersiz kılınmış. Lütfen yeniden giriş yapın.')
      err.statusCode = 401
      throw err
    }
    return { payload, source: 'bearer', rawToken: bearerToken }
  }

  const err = new Error('Oturum bulunamadı. Lütfen giriş yapın.')
  err.statusCode = 401
  throw err
}

function getPIITokenPayload(req) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    const err = new Error('PII Authorization header eksik.')
    err.statusCode = 401
    throw err
  }
  return verifyJWT(authHeader.slice(7))
}

async function requireAuth(req, res, next) {
  try {
    const { payload, source } = await getTokenPayload(req)

    if (source === 'cookie' && payload.type !== 'auth') {
      return res.status(403).json({ error: "Geçersiz cookie token tipi. 'auth' bekleniyordu." })
    }

    if (source === 'bearer' && payload.type !== 'frame') {
      return res.status(403).json({ error: "Geçersiz bearer token tipi. 'frame' bekleniyordu." })
    }

    req.wallet = payload.sub.toLowerCase()
    req.authSource = source
    req.authTokenType = payload.type
    next()
  } catch (err) {
    logger.warn(`[Auth] Token doğrulaması başarısız: ${err.message}`)
    return res.status(err.statusCode || 401).json({ error: err.message || 'Geçersiz veya süresi dolmuş token.' })
  }
}

async function requireSessionWalletMatch(req, res, next) {
  const headerWalletRaw = req.headers['x-wallet-address']

  if (!headerWalletRaw || typeof headerWalletRaw !== 'string') {
    return res.status(401).json({
      error: 'Aktif cüzdan bilgisi eksik. Güvenlik için yeniden giriş yapın.',
      code: 'SESSION_WALLET_HEADER_MISSING',
    })
  }

  const headerWallet = headerWalletRaw.trim().toLowerCase()
  if (!/^0x[a-f0-9]{40}$/.test(headerWallet)) {
    return res.status(400).json({
      error: 'Geçersiz cüzdan başlığı formatı.',
      code: 'SESSION_WALLET_HEADER_INVALID',
    })
  }

  if (!req.wallet || req.wallet !== headerWallet) {
    logger.warn(`[Auth] Session-wallet mismatch: token=${req.wallet || 'none'} header=${headerWallet}`)

    try {
      if (req.wallet) {
        await revokeRefreshToken(req.wallet)
      }
    } catch (revokeErr) {
      logger.warn(`[Auth] Mismatch revoke başarısız: ${revokeErr.message}`)
    }

    const cookieOpts = { httpOnly: true, sameSite: 'lax', path: '/' }
    res.clearCookie('araf_jwt', { ...cookieOpts })
    res.clearCookie('araf_refresh', { ...cookieOpts, path: '/api/auth' })

    return res.status(409).json({
      error: 'Oturum cüzdanı aktif bağlı cüzdanla eşleşmiyor. Lütfen yeniden giriş yapın.',
      code: 'SESSION_WALLET_MISMATCH',
    })
  }

  next()
}

function requirePIIToken(req, res, next) {
  try {
    if (!/^[a-fA-F0-9]{24}$/.test(req.params.tradeId || '')) {
      return res.status(400).json({ error: 'Geçersiz tradeId formatı.' })
    }

    const payload = getPIITokenPayload(req)
    if (payload.type !== 'pii') {
      return res.status(403).json({ error: "Geçersiz token tipi. 'pii' bekleniyordu." })
    }

    if (payload.tradeId !== req.params.tradeId) {
      logger.warn(`[GÜVENLİK] PII token manipülasyonu: caller=${payload.sub} token_trade=${payload.tradeId} requested_trade=${req.params.tradeId}`)
      return res.status(403).json({ error: 'Token bu işlem için geçerli değil.' })
    }

    req.wallet = payload.sub.toLowerCase()
    next()
  } catch (err) {
    logger.warn(`[PIIAuth] Token doğrulaması başarısız: ${err.message}`)
    return res.status(err.statusCode || 401).json({ error: err.message || 'Geçersiz PII token.' })
  }
}

module.exports = { requireAuth, requirePIIToken, requireSessionWalletMatch }
