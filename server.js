const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

const app = express();

/* ------------------- CONFIG ------------------- */

const isProduction = process.env.NODE_ENV === "production";
const jwtSecret = process.env.JWT_SECRET;
const mongoUri = process.env.MONGO_URI;
const firebaseApiKey = process.env.FIREBASE_API_KEY;

const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "admin@gmail.com")
  .trim()
  .toLowerCase();
const MANAGER_EMAIL = String(process.env.MANAGER_EMAIL || "manager@gmail.com")
  .trim()
  .toLowerCase();

const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: "/",
};

if (!jwtSecret) {
  throw new Error("Missing JWT_SECRET");
}
if (!mongoUri) {
  throw new Error("Missing MONGO_URI");
}

const allowedOrigins = (process.env.CORS_ORIGINS ||
  "http://localhost:5173,https://mrats-client.vercel.app")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

/* ------------------- APP MIDDLEWARE ------------------- */

/* ------------------- RATE LIMITING ------------------- */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/favicon.ico",
});

const jwtLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // stricter limit for auth endpoints
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(
  cors({
    credentials: true,
    origin: (origin, callback) => {
      // allow non-browser requests and same-origin tools
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS: origin not allowed"));
    },
  }),
);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(limiter);

app.get("/favicon.ico", (req, res) => res.status(404).end());

/* ------------------- HELPERS ------------------- */

const normalizeEmail = (email = "") => String(email).trim().toLowerCase();

const getSystemRole = (email) => {
  const normalized = normalizeEmail(email);
  if (normalized === ADMIN_EMAIL) return "admin";
  if (normalized === MANAGER_EMAIL) return "manager";
  return "borrower";
};

const toObjectId = (id) => {
  if (!ObjectId.isValid(id)) return null;
  return new ObjectId(id);
};

const normalizeStatus = (status = "") => {
  const value = String(status).trim().toLowerCase();
  const map = {
    pending: "Pending",
    approved: "Approved",
    rejected: "Rejected",
    cancelled: "Cancelled",
  };
  return map[value] || null;
};

async function verifyFirebaseIdToken(idToken) {
  if (!firebaseApiKey) {
    throw new Error("Missing FIREBASE_API_KEY for ID token verification");
  }

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseApiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken }),
    },
  );

  if (!response.ok) {
    throw new Error("Invalid Firebase token");
  }

  const data = await response.json();
  const firebaseUser = data?.users?.[0];
  if (!firebaseUser?.email) {
    throw new Error("Invalid Firebase user payload");
  }

  return {
    email: normalizeEmail(firebaseUser.email),
    emailVerified: !!firebaseUser.emailVerified,
    name: firebaseUser.displayName || "",
    photoURL: firebaseUser.photoUrl || "",
  };
}

/* ------------------- MONGODB ------------------- */

let db;
let loansCollection;
let userCollection;
let applicationLoansCollection;
let isConnected = false;
let connectPromise = null;

const client = new MongoClient(mongoUri, {
  serverSelectionTimeoutMS: 20000,
  retryWrites: true,
  w: "majority",
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function connectDB() {
  if (isConnected) return;
  if (connectPromise) {
    await connectPromise;
    return;
  }

  connectPromise = client
    .connect()
    .then(() => {
      db = client.db("LoanLink");
      loansCollection = db.collection("loans");
      userCollection = db.collection("users");
      applicationLoansCollection = db.collection("application");
      isConnected = true;
      console.log("✅ MongoDB connected");
    })
    .catch((err) => {
      console.error("❌ MongoDB connection failed:", err.message);
      isConnected = false;
      throw err;
    })
    .finally(() => {
      connectPromise = null;
    });

  await connectPromise;
}

async function closeDB() {
  if (client) {
    try {
      await client.close();
      isConnected = false;
      console.log("✅ MongoDB connection closed");
    } catch (err) {
      console.error("Error closing MongoDB:", err);
    }
  }
}

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error("DB connect middleware error:", err);
    res.status(500).json({ message: "Database connection failed" });
  }
});

/* ------------------- AUTH MIDDLEWARE ------------------- */

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    req.user = decoded;
    next();
  });
};

const attachUser = async (req, res, next) => {
  try {
    const email = normalizeEmail(req.user?.email);
    const dbUser = await userCollection.findOne({ email });
    if (!dbUser) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Always enforce system-defined role for reserved emails.
    const forcedRole = getSystemRole(email);
    if (dbUser.role !== forcedRole) {
      await userCollection.updateOne(
        { _id: dbUser._id },
        { $set: { role: forcedRole, roleSyncedAt: new Date() } },
      );
      dbUser.role = forcedRole;
    }

    req.user = { ...req.user, ...dbUser };
    next();
  } catch (err) {
    console.error("attachUser error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

const verifyActiveUser = (req, res, next) => {
  if (req.user?.suspended) {
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

/* ------------------- JWT / SESSION ------------------- */

app.post("/jwt", jwtLimiter, async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(400).json({ message: "Firebase idToken is required" });
    }

    const firebaseUser = await verifyFirebaseIdToken(idToken);
    const email = firebaseUser.email;

    let dbUser = await userCollection.findOne({ email });
    const enforcedRole = getSystemRole(email);

    if (!dbUser) {
      const toInsert = {
        name: firebaseUser.name || email.split("@")[0],
        email,
        photoURL: firebaseUser.photoURL || "",
        role: enforcedRole,
        suspended: false,
        suspensionReason: "",
        createdAt: new Date(),
      };
      const result = await userCollection.insertOne(toInsert);
      dbUser = { ...toInsert, _id: result.insertedId };
    } else if (dbUser.role !== enforcedRole) {
      await userCollection.updateOne(
        { _id: dbUser._id },
        { $set: { role: enforcedRole, roleSyncedAt: new Date() } },
      );
      dbUser.role = enforcedRole;
    }

    const token = jwt.sign(
      { email: dbUser.email, role: dbUser.role },
      jwtSecret,
      {
        expiresIn: "7d",
      },
    );

    res.cookie("token", token, cookieOptions);
    res.json({ success: true, role: dbUser.role });
  } catch (err) {
    console.error("POST /jwt error:", err);
    res.status(401).json({ message: "JWT issuance failed" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    ...cookieOptions,
    maxAge: 0,
  });
  res.json({ success: true });
});

app.get("/me", verifyToken, attachUser, (req, res) => {
  const { email, role, suspended, suspensionReason, createdAt, name, photoURL } =
    req.user;
  res.json({
    email,
    role,
    suspended,
    suspensionReason,
    createdAt,
    name,
    photoURL,
  });
});

app.get("/users/role", verifyToken, attachUser, async (req, res) => {
  const requestedEmail = normalizeEmail(req.query.email || req.user.email);
  const requesterEmail = normalizeEmail(req.user.email);

  if (req.user.role !== "admin" && requestedEmail !== requesterEmail) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const user = await userCollection.findOne({ email: requestedEmail });
  res.json({ role: user?.role || "borrower" });
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

app.post("/users", jwtLimiter, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = normalizeEmail(req.body?.email);
    const photoURL = String(req.body?.photoURL || "").trim();

    if (!email || !email.includes("@")) {
      return res.status(400).json({ message: "Valid email is required" });
    }

    const existing = await userCollection.findOne({ email });
    const role = getSystemRole(email);

    if (existing) {
      if (existing.role !== role) {
        await userCollection.updateOne(
          { _id: existing._id },
          { $set: { role, roleSyncedAt: new Date() } },
        );
        existing.role = role;
      }
      return res.status(200).json({ ...existing, alreadyExists: true });
    }

    const userToInsert = {
      name,
      email,
      photoURL,
      role,
      suspended: false,
      suspensionReason: "",
      createdAt: new Date(),
    };

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
      const objectId = toObjectId(id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid user id" });
      }

      const { role } = req.body;
      const validRoles = ["admin", "manager", "borrower"];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      const target = await userCollection.findOne({ _id: objectId });
      if (!target) {
        return res.status(404).json({ message: "User not found" });
      }

      // Reserved identities keep fixed roles.
      const forcedRole = getSystemRole(target.email);
      const nextRole =
        target.email === ADMIN_EMAIL || target.email === MANAGER_EMAIL
          ? forcedRole
          : role;

      const result = await userCollection.updateOne(
        { _id: objectId },
        { $set: { role: nextRole } },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ success: true, role: nextRole });
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
      const objectId = toObjectId(id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid user id" });
      }

      const { suspended, suspensionReason } = req.body;
      if (typeof suspended !== "boolean") {
        return res.status(400).json({ message: "suspended must be a boolean" });
      }

      const update = {
        suspended,
        suspensionReason: suspended ? String(suspensionReason || "") : "",
        suspensionUpdatedAt: new Date(),
      };

      const result = await userCollection.updateOne(
        { _id: objectId },
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

app.delete(
  "/users/:id",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const objectId = toObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid user id" });
      }

      const user = await userCollection.findOne({ _id: objectId });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Prevent deleting currently authenticated admin account
      if (normalizeEmail(user.email) === normalizeEmail(req.user.email)) {
        return res
          .status(400)
          .json({ message: "You cannot delete your own active account" });
      }

      await applicationLoansCollection.deleteMany({
        applicantEmail: normalizeEmail(user.email),
      });

      const result = await userCollection.deleteOne({ _id: objectId });
      if (!result.deletedCount) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ success: true, deletedUserId: req.params.id });
    } catch (err) {
      console.error("DELETE /users/:id error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

/* ------------------- LOANS ------------------- */

app.get("/loans", async (req, res) => {
  try {
    const query = {};

    if (req.query.showOnHome === "true") {
      query.showOnHome = true;
    }

    if (req.query.managerEmail) {
      query.createdBy = normalizeEmail(req.query.managerEmail);
    }

    const loans = await loansCollection.find(query).toArray();
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
      const payload = req.body || {};
      const title = String(payload.title || "").trim();
      const category = String(payload.category || "").trim();
      const description = String(payload.description || "").trim();
      const interestRate = Number(payload.interestRate || 0);
      const maxLimit = Number(payload.maxLimit || 0);

      if (!title || !category || !description) {
        return res.status(400).json({ message: "Title, category, and description are required" });
      }

      if (title.length < 3 || title.length > 100) {
        return res.status(400).json({ message: "Title must be 3-100 characters" });
      }

      if (interestRate < 0 || interestRate > 100) {
        return res.status(400).json({ message: "Interest rate must be 0-100" });
      }

      if (maxLimit < 0) {
        return res.status(400).json({ message: "Max limit cannot be negative" });
      }

      const loanToInsert = {
        title,
        category,
        description,
        image: String(payload.image || "").trim(),
        interestRate,
        maxLimit,
        emiPlans: Array.isArray(payload.emiPlans) ? payload.emiPlans : [],
        showOnHome: !!payload.showOnHome,
        createdBy: normalizeEmail(req.user.email),
        createdAt: new Date(),
      };

      const result = await loansCollection.insertOne(loanToInsert);
      res.status(201).json({ ...loanToInsert, _id: result.insertedId });
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
      const objectId = toObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid loan id" });
      }

      const existing = await loansCollection.findOne({ _id: objectId });
      if (!existing) {
        return res.status(404).json({ message: "Loan not found" });
      }

      if (
        req.user.role === "manager" &&
        normalizeEmail(existing.createdBy) !== normalizeEmail(req.user.email)
      ) {
        return res.status(403).json({ message: "Managers can only edit own loans" });
      }

      const updates = { ...req.body };
      delete updates._id;
      delete updates.createdBy;
      updates.updatedAt = new Date();

      const result = await loansCollection.updateOne(
        { _id: objectId },
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

app.delete(
  "/loans/:id",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const objectId = toObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid loan id" });
      }

      const existing = await loansCollection.findOne({ _id: objectId });
      if (!existing) {
        return res.status(404).json({ message: "Loan not found" });
      }

      await applicationLoansCollection.deleteMany({ loanId: objectId });

      const result = await loansCollection.deleteOne({ _id: objectId });
      if (!result.deletedCount) {
        return res.status(404).json({ message: "Loan not found" });
      }

      res.json({ success: true, deletedLoanId: req.params.id });
    } catch (err) {
      console.error("DELETE /loans/:id error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.get("/loans/:id", async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id);
    if (!objectId) {
      return res.status(400).json({ message: "Invalid loan id" });
    }

    const loan = await loansCollection.findOne({ _id: objectId });
    if (!loan) return res.status(404).json({ message: "Loan not found" });

    res.json(loan);
  } catch (err) {
    console.error("GET /loans/:id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ------------------- APPLICATIONS ------------------- */

app.get(
  "/application-loans",
  verifyToken,
  attachUser,
  verifyActiveUser,
  async (req, res) => {
    try {
      const query = {};
      const requesterEmail = normalizeEmail(req.user.email);

      if (req.user.role === "borrower") {
        query.applicantEmail = requesterEmail;
      } else if (req.user.role === "manager") {
        query.loanManagerEmail = requesterEmail;
      }

      if (req.user.role === "admin" && req.query.borrowerEmail) {
        query.applicantEmail = normalizeEmail(req.query.borrowerEmail);
      }

      if (req.query.managerEmail) {
        const managerEmail = normalizeEmail(req.query.managerEmail);
        if (req.user.role === "manager" && managerEmail !== requesterEmail) {
          return res.status(403).json({ message: "Forbidden" });
        }
        if (req.user.role !== "borrower") {
          query.loanManagerEmail = managerEmail;
        }
      }

      const items = await applicationLoansCollection
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();

      res.json(items);
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
  verifyRole("borrower"),
  async (req, res) => {
    try {
      const payload = req.body || {};
      const loanObjectId = toObjectId(payload.loanId);
      if (!loanObjectId) {
        return res.status(400).json({ message: "Invalid loan id" });
      }

      const sourceLoan = await loansCollection.findOne({ _id: loanObjectId });
      if (!sourceLoan) {
        return res.status(404).json({ message: "Loan not found" });
      }

      const loanAmount = Number(payload.loanAmount || 0);
      const monthlyIncome = Number(payload.monthlyIncome || 0);
      const reason = String(payload.reason || "").trim();
      const firstName = String(payload.firstName || "").trim();
      const lastName = String(payload.lastName || "").trim();

      if (loanAmount <= 0 || loanAmount > sourceLoan.maxLimit) {
        return res.status(400).json({ message: `Loan amount must be 1-${sourceLoan.maxLimit}` });
      }

      if (!reason || reason.length < 5) {
        return res.status(400).json({ message: "Reason must be at least 5 characters" });
      }

      if (!firstName || !lastName) {
        return res.status(400).json({ message: "First and last name are required" });
      }

      const applicationToInsert = {
        loanId: sourceLoan._id,
        loanTitle: String(sourceLoan.title || "").trim(),
        category: String(sourceLoan.category || "").trim(),
        interestRate: Number(sourceLoan.interestRate || 0),
        loanAmount,
        reason,
        address: String(payload.address || "").trim(),
        notes: String(payload.notes || "").trim(),

        firstName,
        lastName,
        contactNumber: String(payload.contactNumber || "").trim(),
        nationalId: String(payload.nationalId || "").trim(),
        incomeSource: String(payload.incomeSource || "").trim(),
        monthlyIncome,

        applicantEmail: normalizeEmail(req.user.email),
        borrowerEmail: normalizeEmail(req.user.email),
        borrowerName: String(req.user.name || "").trim(),

        loanManagerEmail: normalizeEmail(sourceLoan.createdBy || ""),

        status: "Pending",
        feeStatus: "Unpaid",
        createdAt: new Date(),
      };

      const result = await applicationLoansCollection.insertOne(applicationToInsert);
      res.status(201).json({ ...applicationToInsert, _id: result.insertedId });
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
  async (req, res) => {
    try {
      const objectId = toObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid application id" });
      }

      const normalizedStatus = normalizeStatus(req.body?.status);
      if (!normalizedStatus) {
        return res.status(400).json({ message: "Invalid status" });
      }

      const application = await applicationLoansCollection.findOne({ _id: objectId });
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }

      const requesterRole = req.user.role;
      const requesterEmail = normalizeEmail(req.user.email);

      // Borrower can only cancel own pending application.
      if (requesterRole === "borrower") {
        if (normalizedStatus !== "Cancelled") {
          return res.status(403).json({ message: "Forbidden" });
        }
        if (normalizeEmail(application.applicantEmail) !== requesterEmail) {
          return res.status(403).json({ message: "Forbidden" });
        }
        if (normalizeStatus(application.status) !== "Pending") {
          return res
            .status(400)
            .json({ message: "Only pending applications can be cancelled" });
        }
      }

      // Managers can only review applications for their own loans.
      if (
        requesterRole === "manager" &&
        normalizeEmail(application.loanManagerEmail) !== requesterEmail
      ) {
        return res.status(403).json({ message: "Forbidden" });
      }

      if (!["admin", "manager", "borrower"].includes(requesterRole)) {
        return res.status(403).json({ message: "Forbidden" });
      }

      const update = {
        status: normalizedStatus,
        updatedAt: new Date(),
      };

      if (requesterRole === "admin" || requesterRole === "manager") {
        update.reviewedBy = requesterEmail;
        update.reviewedAt = new Date();
        update.decisionReason =
          normalizedStatus === "Pending" ? "" : String(req.body?.decisionReason || "");
      }

      if (normalizedStatus === "Cancelled") {
        update.cancelledAt = new Date();
      }

      const result = await applicationLoansCollection.updateOne(
        { _id: objectId },
        { $set: update },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Application not found" });
      }

      res.json({ success: true, status: normalizedStatus });
    } catch (err) {
      console.error("PATCH /application-loans/:id/status error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.patch(
  "/application-loans/:id/payment",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("borrower"),
  async (req, res) => {
    try {
      const objectId = toObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid application id" });
      }

      const application = await applicationLoansCollection.findOne({ _id: objectId });
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }

      if (normalizeEmail(application.applicantEmail) !== normalizeEmail(req.user.email)) {
        return res.status(403).json({ message: "Forbidden" });
      }

      const update = {
        feeStatus: "Paid",
        paymentMethod: String(req.body?.paymentMethod || "stripe_demo"),
        paidAmount: Number(req.body?.paidAmount || 10),
        paymentUpdatedAt: new Date(),
      };

      await applicationLoansCollection.updateOne(
        { _id: objectId },
        { $set: update },
      );

      res.json({ success: true, feeStatus: "Paid" });
    } catch (err) {
      console.error("PATCH /application-loans/:id/payment error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// fallback patch for borrower-owned fee updates used by frontend fallback
app.patch(
  "/application-loans/:id",
  verifyToken,
  attachUser,
  verifyActiveUser,
  verifyRole("borrower"),
  async (req, res) => {
    try {
      const objectId = toObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ message: "Invalid application id" });
      }

      const application = await applicationLoansCollection.findOne({ _id: objectId });
      if (!application) {
        return res.status(404).json({ message: "Application not found" });
      }

      if (normalizeEmail(application.applicantEmail) !== normalizeEmail(req.user.email)) {
        return res.status(403).json({ message: "Forbidden" });
      }

      const updates = {};
      if (req.body?.feeStatus) updates.feeStatus = String(req.body.feeStatus);
      if (req.body?.paymentMethod)
        updates.paymentMethod = String(req.body.paymentMethod);
      if (req.body?.paidAmount !== undefined)
        updates.paidAmount = Number(req.body.paidAmount);
      updates.updatedAt = new Date();

      await applicationLoansCollection.updateOne(
        { _id: objectId },
        { $set: updates },
      );

      res.json({ success: true, updatedFields: updates });
    } catch (err) {
      console.error("PATCH /application-loans/:id error:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

/* ------------------- BASE ------------------- */

app.get("/", (req, res) => res.send("API is running..."));

const PORT = process.env.PORT || 3000;

// Graceful shutdown handler
async function gracefulShutdown(signal) {
  console.log(`\n${signal} received. Shutting down gracefully...`);
  try {
    await closeDB();
    process.exit(0);
  } catch (err) {
    console.error("Error during shutdown:", err);
    process.exit(1);
  }
}

if (process.env.VERCEL) {
  module.exports = app;
} else {
  const server = app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

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
}
