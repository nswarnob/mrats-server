const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();

// CORS for cookies
app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);

// Middleware
app.use(express.json());
app.use(cookieParser());

// Handle favicon.ico to prevent DB middleware from running
app.get("/favicon.ico", (req, res) => res.status(404).end());

/* ------------------- MONGODB SETUP ------------------- */

const uri = process.env.MONGO_URI;
let db;
let loansCollection;
let userCollection;
let applicationLoansCollection;
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
  applicationLoansCollection = db.collection("application");
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

/* ------------------- Verification ------------------- */

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

const attachUser = async (req, res, next) => {
  try {
    const dbUser = await userCollection.findOne({ email: req.user.email });
    if (!dbUser) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.user = { ...req.user, ...dbUser };
    next();
  } catch (err) {
    console.error("attachUser error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

const verifyActiveUser = (req, res, next) => {
  if (req.user.suspended) {
    return res.status(403).json({ message: "Account suspended" });
  }
  next();
};

const verifyRole =
  (...allowedRoles) =>
  (req, res, next) => {
    if (!req.user?.role || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };

app.get("/me", verifyToken, attachUser, (req, res) => {
  const { email, role, suspended, suspensionReason, createdAt } = req.user;
  res.json({ email, role, suspended, suspensionReason, createdAt });
});

/* ------------------- USERS ------------------- */

app.get(
  "/users",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const users = await userCollection.find({}).toArray();
      res.json(users);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.post("/users", async (req, res) => {
  try {
    const newUser = req.body;
    const userToInsert = {
      ...newUser,
      role: newUser.role || "borrower",
      suspended: newUser.suspended || false,
      suspensionReason: newUser.suspensionReason || "",
      createdAt: new Date(),
    };

    const existing = await userCollection.findOne({
      email: userToInsert.email,
    });
    if (existing) {
      return res.status(409).json({ message: "User already exists" });
    }

    const result = await userCollection.insertOne(userToInsert);
    res.status(201).json({ ...userToInsert, _id: result.insertedId });
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).json({ error: err.message });
  }
});

app.patch(
  "/users/:id/role",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      const validRoles = ["admin", "manager", "borrower"];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid user id" });
      }

      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role } },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ success: true, role });
    } catch (err) {
      console.error("PATCH /users/:id/role error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.patch(
  "/users/:id/suspension",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { suspended, suspensionReason } = req.body;

      if (typeof suspended !== "boolean") {
        return res.status(400).json({ message: "suspended must be a boolean" });
      }

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid user id" });
      }

      const update = {
        suspended,
        suspensionReason: suspended ? suspensionReason || "" : "",
        suspensionUpdatedAt: new Date(),
      };

      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: update },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        success: true,
        suspended,
        suspensionReason: update.suspensionReason,
      });
    } catch (err) {
      console.error("PATCH /users/:id/suspension error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

/* ------------------- LOANS ------------------- */

app.get("/loans", async (req, res) => {
  try {
    const loans = await loansCollection.find({}).toArray();
    res.json(loans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/loans",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin", "manager"),
  async (req, res) => {
    try {
      const newLoan = req.body;
      const result = await loansCollection.insertOne(newLoan);
      res.status(201).json({ ...newLoan, _id: result.insertedId });
    } catch (err) {
      console.error("Error creating loan:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.patch(
  "/loans/:id",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin", "manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = { ...req.body };
      delete updates._id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid loan id" });
      }

      const result = await loansCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Loan not found" });
      }

      res.json({ success: true, updatedFields: updates });
    } catch (err) {
      console.error("PATCH /loans/:id error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

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

/* ------------------- APPLICATION ------------------- */

app.get(
  "/application-loans",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin", "manager"),
  async (req, res) => {
    try {
      const applicationLoans = await applicationLoansCollection
        .find({})
        .toArray();
      res.json(applicationLoans);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.post(
  "/application-loans",
  verifyToken,
  attachUser,
  verifyActiveUser,
  async (req, res) => {
    try {
      const newApplicationLoan = {
        ...req.body,
        status: req.body.status || "pending",
        applicantEmail: req.user.email,
        createdAt: new Date(),
      };
      const result =
        await applicationLoansCollection.insertOne(newApplicationLoan);
      res.status(201).json({ ...newApplicationLoan, _id: result.insertedId });
    } catch (err) {
      console.error("Error creating application loan:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.patch(
  "/application-loans/:id/status",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin", "manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, decisionReason } = req.body;
      const validStatuses = ["pending", "approved", "rejected"];

      if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: "Invalid status" });
      }

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid application id" });
      }

      const update = {
        status,
        reviewedBy: req.user.email,
        reviewedAt: new Date(),
        decisionReason: status === "pending" ? "" : decisionReason || "",
      };

      const result = await applicationLoansCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: update },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Application not found" });
      }

      res.json({ success: true, status, reviewedBy: req.user.email });
    } catch (err) {
      console.error("PATCH /application-loans/:id/status error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

/* ------------------- BASE ------------------- */

app.get("/", (req, res) => res.send("API is running..."));

const PORT = process.env.PORT || 3000;

if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
}
