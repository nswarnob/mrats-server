require("dotenv").config();
const app = require("./api/index.js");

const PORT = process.env.PORT || 3000;

// Graceful shutdown handler
async function gracefulShutdown(signal) {
  console.log(`\n${signal} received. Shutting down gracefully...`);
  process.exit(0);
}

const server = app.listen(PORT, () =>
  console.log(`✅ Server running on port ${PORT}`),
);

// Handle shutdown signals
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught exceptions
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});

process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
  process.exit(1);
});

