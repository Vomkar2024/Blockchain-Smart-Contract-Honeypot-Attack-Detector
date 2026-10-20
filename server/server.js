const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const fs = require("fs");
const auditRoutes = require("./routes/auditRoutes");

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/honeypot_detector";

// Middleware
app.use(cors());
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));

// Static uploads / reports directory
app.use("/reports", express.static(path.join(__dirname, "../reports")));

// Mount API routes
app.use("/api", auditRoutes);

// Serve static React production bundle if built
const clientDist = path.join(__dirname, "../client/dist");
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api") || req.path.startsWith("/reports")) return next();
    res.sendFile(path.join(clientDist, "index.html"));
  });
} else {
  app.get("/", (req, res) => {
    res.json({
      system: "EVM Smart Contract Honeypot Attack Detector — MERN Backend",
      status: "online",
      version: "1.0.0",
      mongoStatus: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
      endpoints: [
        "POST /api/analyze",
        "GET /api/history",
        "GET /api/stats",
        "GET /api/samples",
        "POST /api/train-ml"
      ]
    });
  });
}

// Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log(`[+] Connected to MongoDB at: ${MONGO_URI}`);
  })
  .catch((err) => {
    console.warn(`[!] MongoDB connection warning: ${err.message}`);
    console.warn("[!] Server will operate with degraded persistent history (audit execution remains fully functional).");
  });

// Start Express server if run directly (skip app.listen in Vercel serverless environment)
let server = null;
if (!process.env.VERCEL) {
  const HOST = process.env.HOST || "0.0.0.0";
  server = app.listen(PORT, HOST, () => {
    console.log(`[+] MERN Backend Server listening on http://127.0.0.1:${PORT} (all interfaces on ${HOST}:${PORT})`);
  });
}

app.server = server;
module.exports = app;
module.exports.app = app;
module.exports.server = server;
