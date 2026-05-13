const express = require("express");
const { generateAIResponse } = require("../../services/aiService");

const router = express.Router();

router.post("/loan-assistant", async (req, res) => {
  try {
    const { prompt } = req.body || {};

    // Validate that prompt exists and is a non-empty string
    if (typeof prompt !== "string" || prompt.trim() === "") {
      return res
        .status(400)
        .json({ error: "Prompt is required and must be a non-empty string" });
    }

    const aiResponse = await generateAIResponse(prompt);
    console.log("AI response generated successfully");
    res.status(200).json({ response: aiResponse });
  } catch (err) {
    console.error("POST /api/routes/loan-assistant error:", err);
    res.status(500).json({ error: "Failed to generate AI response" });
  }
});

module.exports = router;
