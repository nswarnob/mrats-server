const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// CORS for cookies
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);

const uri = process.env.MONGO_URI;
let db;
let loansCollection;
let userCollection;
let isConnected = false;

const client = new MongoClient(uri, {
  serverSelectionTimeoutMS: 20000,
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function connectDB() {
  if (isConnected) return;

  await client.connect();
  db = client.db("LoanLink");
  loansCollection = db.collection("loans");
  userCollection = db.collection("users");
  isConnected = true;
  console.log("✅ MongoDB connected");
}

// DB connected
app.use(async (req, res, next) => {
  try {
    if (!isConnected) await connectDB();
    next();
  } catch (err) {
    console.error("DB connect middleware error:", err);
    res.status(500).json({ message: "Database connection failed" });
  }
});

/* ------------------- JWT COOKIE ROUTES ------------------- */

// Create token + set cookie
app.post("/jwt", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: "Email required" });

    // get role from DB
    const dbUser = await userCollection.findOne({ email });
    const role = dbUser?.role || "borrower";

    const token = jwt.sign({ email, role }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    res.send({ success: true, role });
  } catch (err) {
    console.error("POST /jwt error:", err);
    res.status(500).json({ message: "JWT failed" });
  }
});

// Logout clears cookie
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
  });
  res.send({ success: true });
});

// Get role by email (optional)
app.get("/users/role", async (req, res) => {
  const email = req.query.email;
  const user = await userCollection.findOne({ email });
  res.send({ role: user?.role || "borrower" });
});

/* ------------------- verification ------------------- */

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    req.user = decoded;
    next();
  });
};

/* ------------------- USERS ------------------- */

app.get("/users", verifyToken, async (req, res) => {
  try {
    const users = await userCollection.find({}).toArray();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/users", async (req, res) => {
  try {
    const newUser = req.body;

    const existing = await userCollection.findOne({ email: newUser.email });
    if (existing) {
      return res.status(409).json({ message: "User already exists" });
    }

    const result = await userCollection.insertOne(newUser);
    res.status(201).json({ ...newUser, _id: result.insertedId });
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ------------------- LOANS ------------------- */

app.get("/loans", async (req, res) => {
  try {
    const loans = await loansCollection.find({}).toArray();
    res.json(loans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/loans", async (req, res) => {
  try {
    const newLoan = req.body;
    const result = await loansCollection.insertOne(newLoan);
    res.status(201).json({ ...newLoan, _id: result.insertedId });
  } catch (err) {
    console.error("Error creating loan:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/loans/:id", async (req, res) => {
  try {
    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid loan id" });
    }

    const loan = await loansCollection.findOne({ _id: new ObjectId(id) });
    if (!loan) return res.status(404).json({ message: "Loan not found" });

    res.json(loan);
  } catch (err) {
    console.error("GET /loans/:id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ------------------- BASE ------------------- */

app.get("/", (req, res) => res.send("API is running..."));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
