const express = require('express')
const { sendStripeKey, sendRazorpayKey, captureStripePayment, captureRazorpayPayment } = require('../controllers/paymentController')
const router = express.Router()
const { isLoggedIn } = require('../middlewares/user')
router.route("/stripekey").get(isLoggedIn,sendStripeKey)
router.route("/razorpaykey").get(isLoggedIn,sendRazorpayKey)

router.route("/capturestripe").post(isLoggedIn,captureStripePayment)
router.route("/capturerazorpay").post(isLoggedIn,captureRazorpayPayment)
module.exports = router