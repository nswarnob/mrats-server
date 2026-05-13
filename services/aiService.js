const { GoogleGenerativeAI } = require("@google/generative-ai");

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

const generateAIResponse = async (prompt) => {
  try {
    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash",
      systemInstruction: `
You are LoanLink AI Assistant.
Help users understand loan applications, eligibility, approval process, repayment, and payment status.
Do not guarantee loan approval.
Do not provide legal or financial advice.
Keep answers clear, short, and beginner-friendly.
If user asks for loan eligibility, ask about their income, credit score, and employment status.
If user asks about payment status, ask for their application ID or email to check status.
`,
    });

    const result = await model.generateContent(prompt);
    const response = result.response;

    return response.text();
  } catch (err) {
    console.error("generateAIResponse error:", err.message);
    throw new Error("Failed to generate AI response");
  }
};

module.exports = { generateAIResponse };
