const OpenAI = require("openai");

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const generateAIResponse = async (prompt) => {
  try {
    const response = await client.responses.create({
      model: "gpt-5.4-mini",
      instructions: `You are LoanLink AI Assistant.
Help users understand loan applications, eligibility, approval process, and payment status.
Do not guarantee loan approval.
Do not provide legal or financial advice.
Keep answers clear, short, and beginner-friendly.
If user asks for loan eligibility, ask about their income, credit score, and employment status.
If user asks about payment status, ask for their application ID or email to check status.`,
      input: prompt,
    });
    return response.output_text;
  } catch (err) {
    console.error("generateAIResponse error:", err.message);
    throw new Error("Failed to generate AI response");
  }
};

module.exports = { generateAIResponse };
