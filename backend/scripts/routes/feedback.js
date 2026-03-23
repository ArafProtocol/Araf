"use strict";

/**
 * Feedback Route
 */

const express  = require("express");
const Joi      = require("joi");
const router   = express.Router();

const { requireAuth }     = require("../middleware/auth");
const { feedbackLimiter } = require("../middleware/rateLimiter");
const Feedback            = require("../models/Feedback");
const logger              = require("../utils/logger");

/**
 * POST /api/feedback
 * Kullanıcı geri bildirimi gönderir. Saatte max 3 istek.
 */
router.post("/", requireAuth, feedbackLimiter, async (req, res, next) => {
  try {
    const schema = Joi.object({
      rating:  Joi.number().integer().min(1).max(5).required(),
      comment: Joi.string().max(1000).allow("").optional(),
      // YENİ: Geri bildirimleri sınıflandırmak için kategori alanı
      category: Joi.string().valid('bug', 'suggestion', 'ui/ux', 'other').required(),
    });

    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    await Feedback.create({
      wallet_address: req.wallet,
      rating:         value.rating,
      comment:        value.comment || "",
      category:       value.category,
    });

    logger.info(`[Feedback] ${req.wallet} → ${value.rating}/5 [${value.category}]`);
    return res.status(201).json({ success: true, message: "Geri bildirim alındı, teşekkürler!" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
