const express = require("express");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const router = express.Router();

router.post("/create-payment-intent", async (req, res) => {
  try {
    const { amount } = req.body;

    // 1. Validate that amount exists
    if (amount === undefined || amount === null) {
      return res.status(400).json({ error: "Amount is required" });
    }

    // 2. Validate that amount is a valid number
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res
        .status(400)
        .json({ error: "Amount must be a valid positive number" });
    }

    // 3. Convert amount to cents by multiplying by 100
    const amountInCents = Math.round(parsedAmount * 100);

    // 4. Validate amount is within reasonable range (e.g., min $0.50, max $999,999)
    if (amountInCents < 50 || amountInCents > 99999900) {
      return res.status(400).json({
        error: "Amount must be between $0.50 and $999,999.00",
      });
    }

    // 5. Create Stripe PaymentIntent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: "usd",
      payment_method_types: ["card"],
    });

    // 6. Return only the clientSecret (never expose full PaymentIntent object)
    res.status(200).json({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (err) {
    console.error("POST /api/payments/create-payment-intent error:", err);

    // Handle specific Stripe errors
    if (err.type === "StripeInvalidRequestError") {
      return res.status(400).json({ error: err.message });
    }

    if (err.type === "StripeAuthenticationError") {
      return res.status(500).json({ error: "Payment service authentication failed" });
    }

    if (err.type === "StripeRateLimitError") {
      return res.status(429).json({ error: "Too many requests to payment service" });
    }

    if (err.type === "StripeConnectionError") {
      return res.status(503).json({ error: "Payment service temporarily unavailable" });
    }

    // Generic error response
    res.status(500).json({ error: "Failed to create payment intent" });
  }
});

module.exports = router;
