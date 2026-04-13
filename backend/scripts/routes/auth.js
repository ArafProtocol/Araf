'use strict'

const express = require('express')
const Joi = require('joi')
const router = express.Router()

const { authLimiter } = require('../middleware/rateLimiter')
const { requireAuth, requireSessionWalletMatch } = require('../middleware/auth')
const {
  generateNonce,
  verifySiweSignature,
  getSiweConfig,
  issueJWT,
  issueFrameToken,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  blacklistJWT,
} = require('../services/siwe')
const { encryptPII } = require('../services/encryption')
const User = require('../models/User')
const logger = require('../utils/logger')

const COOKIE_OPTIONS_BASE = {
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
}

function getJwtCookieOptions() {
  return {
    ...COOKIE_OPTIONS_BASE,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 15 * 60 * 1000,
  }
}

function getRefreshCookieOptions() {
  return {
    ...COOKIE_OPTIONS_BASE,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/api/auth',
  }
}

router.get('/nonce', authLimiter, async (req, res, next) => {
  try {
    const { wallet } = req.query
    if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      return res.status(400).json({ error: 'Geçerli bir Ethereum adresi gir.' })
    }

    const nonce = await generateNonce(wallet.toLowerCase())
    const { domain: siweDomain, uri: siweUri } = getSiweConfig()
    return res.json({ nonce, siweDomain, siweUri })
  } catch (err) {
    if (/SIWE_/.test(err.message)) {
      return res.status(503).json({ error: err.message })
    }
    next(err)
  }
})

router.post('/verify', authLimiter, async (req, res) => {
  try {
    const schema = Joi.object({
      message: Joi.string().max(2000).required(),
      signature: Joi.string().pattern(/^0x[a-fA-F0-9]{130}$/).required(),
    })

    const { error, value } = schema.validate(req.body)
    if (error) {
      return res.status(400).json({ error: error.message })
    }

    const wallet = await verifySiweSignature(value.message, value.signature)

    const user = await User.findOneAndUpdate(
      { wallet_address: wallet },
      { $set: { last_login: new Date() }, $setOnInsert: { wallet_address: wallet } },
      { upsert: true, new: true },
    )

    await user.checkBanExpiry()

    const authToken = issueJWT(wallet)
    const frameToken = issueFrameToken(wallet)
    const refreshToken = await issueRefreshToken(wallet)

    res.cookie('araf_jwt', authToken, getJwtCookieOptions())
    res.cookie('araf_refresh', refreshToken, getRefreshCookieOptions())

    logger.info(`[Auth] Giriş başarılı: ${wallet}`)
    return res.json({
      wallet,
      token: frameToken,
      tokenType: 'frame',
      profile: user.toPublicProfile(),
    })
  } catch (err) {
    logger.warn(`[Auth] SIWE başarısız: ${err.message}`)
    return res.status(401).json({ error: `Kimlik doğrulama başarısız: ${err.message}` })
  }
})

router.post('/refresh', authLimiter, async (req, res) => {
  try {
    const refreshToken = req.cookies?.araf_refresh
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token bulunamadı.' })
    }

    let wallet = req.body?.wallet
    if (!wallet) {
      const jwtCookie = req.cookies?.araf_jwt
      if (jwtCookie) {
        try {
          const parts = jwtCookie.split('.')
          if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
            wallet = payload.sub
          }
        } catch {
          wallet = null
        }
      }
    }

    if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
      return res.status(400).json({ error: 'Wallet adresi belirlenemedi.' })
    }

    const result = await rotateRefreshToken(wallet.toLowerCase(), refreshToken)
    res.cookie('araf_jwt', result.token, getJwtCookieOptions())
    res.cookie('araf_refresh', result.refreshToken, getRefreshCookieOptions())

    logger.info(`[Auth] Token yenilendi: ${wallet}`)
    return res.json({ wallet: wallet.toLowerCase() })
  } catch (err) {
    logger.warn(`[Auth] Refresh başarısız: ${err.message}`)
    res.clearCookie('araf_jwt', { ...COOKIE_OPTIONS_BASE, path: '/' })
    res.clearCookie('araf_refresh', { ...COOKIE_OPTIONS_BASE, path: '/api/auth' })
    return res.status(401).json({ error: err.message })
  }
})

router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    const currentJWT = req.cookies?.araf_jwt
    if (currentJWT) {
      await blacklistJWT(currentJWT)
    }

    await revokeRefreshToken(req.wallet)

    res.clearCookie('araf_jwt', { ...COOKIE_OPTIONS_BASE, path: '/' })
    res.clearCookie('araf_refresh', { ...COOKIE_OPTIONS_BASE, path: '/api/auth' })

    logger.info(`[Auth] Çıkış yapıldı: ${req.wallet}`)
    return res.json({ success: true, message: 'Oturum kapatıldı.' })
  } catch (err) {
    next(err)
  }
})

router.get('/me', requireAuth, async (req, res) => {
  const headerWalletRaw = req.headers['x-wallet-address']

  if (headerWalletRaw) {
    const headerWallet = headerWalletRaw.trim().toLowerCase()
    if (/^0x[a-f0-9]{40}$/.test(headerWallet) && headerWallet !== req.wallet) {
      logger.warn(`[Auth] /me wallet mismatch: token=${req.wallet} header=${headerWallet}`)

      res.clearCookie('araf_jwt', { ...COOKIE_OPTIONS_BASE, path: '/' })
      res.clearCookie('araf_refresh', { ...COOKIE_OPTIONS_BASE, path: '/api/auth' })

      try {
        await revokeRefreshToken(req.wallet)
      } catch (_) {}

      return res.status(409).json({
        error: 'Oturum cüzdanı aktif bağlı cüzdanla eşleşmiyor.',
        code: 'SESSION_WALLET_MISMATCH',
      })
    }
  }

  return res.json({ wallet: req.wallet, authenticated: true, authSource: req.authSource, tokenType: req.authTokenType })
})

router.put('/profile', requireAuth, requireSessionWalletMatch, authLimiter, async (req, res, next) => {
  try {
    const normalizedBody = {
      bankOwner:
        typeof req.body?.bankOwner === 'string'
          ? req.body.bankOwner.trim().replace(/\s+/g, ' ')
          : req.body?.bankOwner,
      iban:
        typeof req.body?.iban === 'string'
          ? req.body.iban.replace(/\s+/g, '').toUpperCase()
          : req.body?.iban,
      telegram:
        typeof req.body?.telegram === 'string'
          ? req.body.telegram.trim().replace(/^@+/, '')
          : req.body?.telegram,
    }

    const schema = Joi.object({
      bankOwner: Joi.string().min(2).max(100).pattern(/^[a-zA-ZğüşöçİĞÜŞÖÇ\s]+$/, 'geçerli isim karakterleri').allow('').optional(),
      iban: Joi.string().pattern(/^TR\d{24}$/, 'TR IBAN formatı').allow('').optional(),
      telegram: Joi.string().max(50).pattern(/^[a-zA-Z0-9_]{5,}$/, 'Telegram kullanıcı adı').allow('').optional(),
    })

    const { error, value } = schema.validate(normalizedBody)
    if (error) {
      return res.status(400).json({ error: error.message })
    }

    const encrypted = await encryptPII(value, req.wallet)

    await User.findOneAndUpdate(
      { wallet_address: req.wallet },
      {
        $set: {
          'pii_data.bankOwner_enc': encrypted.bankOwner_enc,
          'pii_data.iban_enc': encrypted.iban_enc,
          'pii_data.telegram_enc': encrypted.telegram_enc,
        },
      },
    )

    logger.info(`[Auth] Profil güncellendi: ${req.wallet}`)
    return res.json({ success: true, message: 'Profil bilgilerin güncellendi.' })
  } catch (err) {
    next(err)
  }
})

module.exports = router
