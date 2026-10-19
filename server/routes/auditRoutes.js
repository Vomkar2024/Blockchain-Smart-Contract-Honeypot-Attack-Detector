const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const multer = require("multer");
const AuditReport = require("../models/AuditReport");

// Configure upload storage for contract files
const upload = multer({ dest: path.join(__dirname, "../uploads/") });

const BASE_DIR = path.resolve(__dirname, "../../");
const SAMPLES_DIR = path.join(BASE_DIR, "samples");

// Determine Python executable path (.venv or system fallback)
function getPythonExecutable() {
  const venvPythonWin = path.join(BASE_DIR, ".venv", "Scripts", "python.exe");
  const venvPythonUnix = path.join(BASE_DIR, ".venv", "bin", "python");
  if (fs.existsSync(venvPythonWin)) return venvPythonWin;
  if (fs.existsSync(venvPythonUnix)) return venvPythonUnix;
  return process.platform === "win32" ? "python" : "python3";
}

/**
 * Executes the Python analysis pipeline using child_process.
 * Safely passes input code/address via temporary JSON or stdin to avoid Windows CLI escaping limits.
 */
function runPythonAudit(inputData, inputType = "auto", network = "ethereum", simulate = false) {
  return new Promise((resolve, reject) => {
    const pythonExe = getPythonExecutable();
    const tempDir = path.join(BASE_DIR, "reports");
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

    const tempPayloadFile = path.join(tempDir, `payload_${Date.now()}_${Math.random().toString(36).substring(7)}.json`);
    const tempOutputFile = path.join(tempDir, `out_${Date.now()}_${Math.random().toString(36).substring(7)}.json`);
    const tempScriptFile = path.join(tempDir, `runner_${Date.now()}_${Math.random().toString(36).substring(7)}.py`);

    const cleanup = () => {
      [tempPayloadFile, tempScriptFile, tempOutputFile].forEach((f) => {
        try {
          if (fs.existsSync(f)) fs.unlinkSync(f);
        } catch (_) {}
      });
    };

    try {
      fs.writeFileSync(tempPayloadFile, JSON.stringify({
        inputData,
        inputType,
        network,
        simulate
      }), "utf-8");

      const pyScript = `import json, sys
from pathlib import Path
sys.path.insert(0, r"${BASE_DIR.replace(/\\/g, '\\\\')}")
import app

with open(r"${tempPayloadFile.replace(/\\/g, '\\\\')}", "r", encoding="utf-8") as f:
    payload = json.load(f)

report = app.execute_contract_audit(
    contract_input=payload["inputData"],
    input_type=payload.get("inputType", "auto"),
    network_name=payload.get("network", "ethereum"),
    simulate=payload.get("simulate", False),
)

with open(r"${tempOutputFile.replace(/\\/g, '\\\\')}", "w", encoding="utf-8") as f:
    f.write(report.to_json())
`;
      fs.writeFileSync(tempScriptFile, pyScript, "utf-8");
    } catch (writeErr) {
      cleanup();
      return reject(new Error(`Failed to initialize audit runner: ${writeErr.message}`));
    }

    const proc = spawn(pythonExe, [tempScriptFile], {
      cwd: BASE_DIR,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      shell: false
    });

    let stderr = "";
    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("error", (err) => {
      cleanup();
      reject(new Error(`Failed to launch Python audit engine: ${err.message}`));
    });

    proc.on("close", (code) => {
      try {
        if (fs.existsSync(tempPayloadFile)) fs.unlinkSync(tempPayloadFile);
        if (fs.existsSync(tempScriptFile)) fs.unlinkSync(tempScriptFile);
      } catch (_) {}

      if (code !== 0 && !fs.existsSync(tempOutputFile)) {
        cleanup();
        return reject(new Error(`Python audit process failed (code ${code}): ${stderr}`));
      }

      try {
        if (!fs.existsSync(tempOutputFile)) {
          cleanup();
          return reject(new Error("Python analysis did not generate an output report."));
        }
        const rawJson = fs.readFileSync(tempOutputFile, "utf-8");
        cleanup();
        const parsedReport = JSON.parse(rawJson);
        resolve(parsedReport);
      } catch (err) {
        cleanup();
        reject(new Error(`Failed to read/parse Python report: ${err.message}`));
      }
    });
  });
}

/**
 * POST /api/analyze
 * Run static and ML honeypot analysis on uploaded file, code, or address
 */
router.post("/analyze", upload.single("file"), async (req, res) => {
  try {
    let inputData = "";
    let inputType = "source_code";
    const network = req.body.network || "ethereum";
    const simulate = req.body.simulate === "true" || req.body.simulate === true;

    if (req.file) {
      inputData = fs.readFileSync(req.file.path, "utf-8");
      inputType = "source_code";
      try { fs.unlinkSync(req.file.path); } catch (e) {}
    } else if (req.body.preset) {
      const presetName = req.body.preset;
      const fileMap = {
        "HoneypotToken": "sample_honeypot_token.sol",
        "CriticalDexTrapToken": "sample_critical_dextrap.sol",
        "CriticalDelegatecallToken": "sample_critical_delegatecall_backdoor.sol",
        "HighUnboundedTaxToken": "sample_high_unbounded_tax.sol",
        "HighHiddenBlacklistToken": "sample_high_hidden_blacklist.sol",
        "RestrictedGovernanceToken": "sample_restricted_token.sol",
        "ModeratePausableToken": "sample_moderate_pausable_token.sol",
        "ModerateCooldownToken": "sample_moderate_cooldown_token.sol",
        "SafeToken": "sample_safe_token.sol",
        "BenignDeFiToken": "sample_benign_defi_token.sol",
        "BenignCharityToken": "sample_benign_charity_token.sol"
      };
      const sampleFile = fileMap[presetName] || "sample_safe_token.sol";
      const samplePath = path.join(SAMPLES_DIR, sampleFile);
      if (fs.existsSync(samplePath)) {
        inputData = fs.readFileSync(samplePath, "utf-8");
        inputType = "source_code";
      } else {
        return res.status(404).json({ error: `Preset ${presetName} not found.` });
      }
    } else if (req.body.address) {
      inputData = req.body.address.trim();
      inputType = "address";
    } else if (req.body.code) {
      inputData = typeof req.body.code === "string" ? req.body.code : JSON.stringify(req.body.code);
      inputType = "source_code";
    } else {
      return res.status(400).json({ error: "Please provide a contract file, code snippet, or address." });
    }

    // Execute Python analysis engine
    const rawReport = await runPythonAudit(inputData, inputType, network, simulate);

    // Extract standardized fields
    const contract = rawReport.contract || {};
    const risk = rawReport.risk_assessment || {};
    const ml = rawReport.machine_learning || {};
    const staticAnalysis = rawReport.static_analysis || {};

    // Transform findings for MongoDB schema
    const findings = (staticAnalysis.findings || []).map(f => ({
      rule_id: f.rule_id,
      rule_name: f.rule_name,
      category: f.category || "General",
      severity: f.severity || "LOW",
      confidence: f.confidence || "MEDIUM",
      line_number: f.line_number,
      evidence: f.evidence || "",
      explanation: f.explanation || "",
      suggested_verification: f.suggested_verification || ""
    }));

    // Transform positive indicators
    const positiveIndicators = (staticAnalysis.positive_indicators || []).map(p => ({
      indicator_id: p.indicator_id,
      name: p.name,
      evidence: p.evidence || "",
      explanation: p.explanation || ""
    }));

    // Persist report in MongoDB (fail-safe if Mongo is running or in-memory)
    let savedAudit = null;
    try {
      savedAudit = await AuditReport.create({
        contractName: contract.name || "Contract",
        contractAddress: contract.address || null,
        network: contract.network || network,
        inputType: inputType,
        riskScore: risk.risk_score || 0,
        riskLevel: risk.risk_level || "LOW",
        isHoneypot: ml.is_honeypot || false,
        mlProbability: ml.honeypot_probability || 0.0,
        mlConfidence: ml.confidence_score || 0.0,
        modelUsed: ml.model_used || "RandomForestClassifier",
        featureContributions: ml.feature_contributions || {},
        findings: findings,
        positiveIndicators: positiveIndicators,
        summaryExplanation: risk.summary_explanation || "",
        sourceCodeSnippet: contract.source_code ? contract.source_code.slice(0, 1500) : "",
        rawReport: rawReport
      });
    } catch (dbErr) {
      console.warn("MongoDB persistence warning:", dbErr.message);
    }

    res.json({
      success: true,
      auditId: savedAudit ? savedAudit._id : null,
      report: rawReport,
      summary: {
        contractName: contract.name || "Contract",
        riskScore: risk.risk_score || 0,
        riskLevel: risk.risk_level || "LOW",
        isHoneypot: ml.is_honeypot || false,
        mlProbability: ml.honeypot_probability || 0.0,
        findingsCount: findings.length,
        positiveCount: positiveIndicators.length
      }
    });
  } catch (error) {
    console.error("Audit processing error:", error);
    res.status(500).json({ error: error.message || "Audit pipeline failed." });
  }
});

/**
 * GET /api/history
 * Retrieve recent audits from MongoDB
 */
router.get("/history", async (req, res) => {
  try {
    const history = await AuditReport.find()
      .sort({ createdAt: -1 })
      .limit(30)
      .select("-rawReport");
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch audit history.", details: err.message });
  }
});

/**
 * GET /api/history/:id
 * Retrieve a specific audit record with full details
 */
router.get("/history/:id", async (req, res) => {
  try {
    const report = await AuditReport.findById(req.params.id);
    if (!report) return res.status(404).json({ error: "Audit record not found." });
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch audit.", details: err.message });
  }
});

/**
 * DELETE /api/history/:id
 * Delete an audit record from MongoDB
 */
router.delete("/history/:id", async (req, res) => {
  try {
    await AuditReport.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Audit report deleted." });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete audit.", details: err.message });
  }
});

/**
 * GET /api/stats
 * Return aggregated audit statistics from MongoDB with threat tier breakdown
 */
router.get("/stats", async (req, res) => {
  try {
    const total = await AuditReport.countDocuments();
    const honeypots = await AuditReport.countDocuments({ isHoneypot: true });
    const clean = total - honeypots;

    const criticalCount = await AuditReport.countDocuments({ riskLevel: "CRITICAL" });
    const highCount = await AuditReport.countDocuments({ riskLevel: "HIGH" });
    const moderateCount = await AuditReport.countDocuments({ riskLevel: "MODERATE" });
    const benignCount = await AuditReport.countDocuments({ riskLevel: { $in: ["LOW", "BENIGN"] } });

    const avgRisk = await AuditReport.aggregate([
      { $group: { _id: null, avgScore: { $avg: "$riskScore" } } }
    ]);

    res.json({
      totalAudited: total,
      honeypotsDetected: honeypots,
      cleanContracts: clean,
      averageRiskScore: avgRisk.length > 0 ? Math.round(avgRisk[0].avgScore) : 0,
      honeypotRatio: total > 0 ? Math.round((honeypots / total) * 100) : 0,
      breakdown: {
        critical: criticalCount,
        high: highCount,
        moderate: moderateCount,
        benign: benignCount
      }
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to compute stats.", details: err.message });
  }
});

/**
 * GET /api/samples
 * Return comprehensive multi-tier educational samples across all 4 threat levels
 */
router.get("/samples", (req, res) => {
  try {
    const sampleFiles = [
      // 1. CRITICAL THREAT LEVEL
      {
        key: "HoneypotToken",
        name: "Classic Honeypot Token",
        threatLevel: "CRITICAL",
        category: "Multi-Vector Trap",
        expectedScore: "100/100",
        file: "sample_honeypot_token.sol",
        tags: ["Blacklist Trap", "Asymmetric Sell", "99% Tax", "Hidden Mint", "Assembly"],
        desc: "Multi-vector malicious honeypot with blacklist traps, asymmetric sell locks, 99% confiscatory tax, and hidden mint privileges."
      },
      {
        key: "CriticalDexTrapToken",
        name: "DEX Liquidity Siphon Trap",
        threatLevel: "CRITICAL",
        category: "Trading Restrictions",
        expectedScore: "100/100",
        file: "sample_critical_dextrap.sol",
        tags: ["DEX Pair Revert", "99% Sell Tax", "External Oracle Trap", "Infinite Mint"],
        desc: "Permits seamless DEX buying but reverts sell transfers back to the Uniswap pair, siphoning liquidity into deployer wallet."
      },
      {
        key: "CriticalDelegatecallToken",
        name: "Shadow Delegatecall Backdoor",
        threatLevel: "CRITICAL",
        category: "Low-Level Backdoors",
        expectedScore: "100/100",
        file: "sample_critical_delegatecall_backdoor.sol",
        tags: ["Delegatecall", "Address Blacklist", "Unbounded Tax", "Arbitrary Execution"],
        desc: "Low-level EVM delegatecall backdoor disguised inside execution hooks, combined with administrative blacklist mappings."
      },

      // 2. HIGH THREAT LEVEL
      {
        key: "HighUnboundedTaxToken",
        name: "Unbounded Tax & Mint Token",
        threatLevel: "HIGH",
        category: "Privileged Manipulation",
        expectedScore: "65/100",
        file: "sample_high_unbounded_tax.sol",
        address: "0x71c8dC0563b7c8449c25fBA0B991461FfFAe7748",
        network: "ethereum",
        tags: ["Uncapped Fee Setter", "Unconstrained Mint", "Inline Assembly", "On-Chain Address"],
        desc: "Owner can hike transfer taxes arbitrarily without an immutable ceiling, alongside unconstrained token supply inflation."
      },
      {
        key: "HighHiddenBlacklistToken",
        name: "Blacklist Guard & Inflation Token",
        threatLevel: "HIGH",
        category: "Access Control",
        expectedScore: "50/100",
        file: "sample_high_hidden_blacklist.sol",
        tags: ["Hidden Blacklist Check", "Privileged Minting", "Max Wallet Limit"],
        desc: "Enforces selective address blocking in transfer execution paths paired with privileged unconstrained token minting."
      },

      // 3. MODERATE THREAT LEVEL
      {
        key: "RestrictedGovernanceToken",
        name: "Restricted Governance Token",
        threatLevel: "MODERATE",
        category: "Enterprise Governance",
        expectedScore: "30/100",
        file: "sample_restricted_token.sol",
        tags: ["Pausable Transfers", "Max Wallet Cap", "Whitelist Exemption", "Cooldown Delay"],
        desc: "Enterprise compliance token with emergency pause switches, anti-whale transaction limits, and partner whitelist mechanisms."
      },
      {
        key: "ModeratePausableToken",
        name: "Enterprise Pausable Token",
        threatLevel: "MODERATE",
        category: "Pausable Controls",
        expectedScore: "30/100",
        file: "sample_moderate_pausable_token.sol",
        tags: ["Emergency Pause", "Anti-Whale Limit", "Hard Fee Cap (<=3%)"],
        desc: "Legitimate enterprise token featuring owner-controlled emergency circuit-breakers, hardcoded fee ceilings, and OpenZeppelin base."
      },
      {
        key: "ModerateCooldownToken",
        name: "Anti-Bot Cooldown Token",
        threatLevel: "MODERATE",
        category: "Anti-Bot Mechanics",
        expectedScore: "30/100",
        file: "sample_moderate_cooldown_token.sol",
        tags: ["Transfer Cooldown Delay", "Trading Enable Switch", "Anti-Whale 2%"],
        desc: "DeFi launch token enforcing anti-bot transfer timestamp cooldowns and launch trading enablement toggles."
      },

      // 4. BENIGN THREAT LEVEL
      {
        key: "SafeToken",
        name: "Safe Reference Token",
        threatLevel: "BENIGN",
        category: "Audited Standard",
        expectedScore: "0/100",
        file: "sample_safe_token.sol",
        tags: ["OpenZeppelin Standard", "Hard Fee Cap (5%)", "Renounced Ownership", "Transparent Events"],
        desc: "Fully audited standard ERC-20 reference token with immutable 5% fee ceiling, renounced ownership, and symmetric trading."
      },
      {
        key: "BenignDeFiToken",
        name: "DeFi Zero-Fee Fixed Token",
        threatLevel: "BENIGN",
        category: "Zero-Risk Protocol",
        expectedScore: "0/100",
        file: "sample_benign_defi_token.sol",
        tags: ["Zero Fees", "Fixed Supply", "Renounced Ownership", "Audited Base"],
        desc: "Zero-risk DeFi standard ERC-20 token with 100% fixed supply minted at construction, zero fees, and full ownership renunciation."
      },
      {
        key: "BenignCharityToken",
        name: "Capped Charity Token",
        threatLevel: "BENIGN",
        category: "Community & Charity",
        expectedScore: "0/100",
        file: "sample_benign_charity_token.sol",
        tags: ["Hard Fee Cap (3%)", "Transparent Treasury", "Renounceable", "Standard Events"],
        desc: "Community token with hardcoded 3% fee ceiling, dedicated transparent public good charity treasury, and standard events."
      }
    ];

    const filterLevel = req.query.level ? req.query.level.toUpperCase() : null;
    const samples = {};

    sampleFiles.forEach(s => {
      if (filterLevel && s.threatLevel !== filterLevel) return;
      const p = path.join(SAMPLES_DIR, s.file);
      samples[s.key] = {
        name: s.name,
        key: s.key,
        threatLevel: s.threatLevel,
        category: s.category,
        expectedScore: s.expectedScore,
        description: s.desc,
        tags: s.tags,
        file: s.file,
        address: s.address || null,
        network: s.network || "ethereum",
        code: fs.existsSync(p) ? fs.readFileSync(p, "utf-8") : ""
      };
    });

    res.json(samples);
  } catch (err) {
    res.status(500).json({ error: "Failed to load sample contracts.", details: err.message });
  }
});

/**
 * GET /api/rules
 * Return static detection rules specifications
 */
router.get("/rules", (req, res) => {
  const rules = [
    {
      rule_id: "HONEYPOT_BLACKLIST",
      rule_name: "Arbitrary Address Blacklist Mechanism",
      category: "Access Control & Transfer Restrictions",
      severity: "CRITICAL",
      confidence: "HIGH",
      description: "Detects address blacklisting logic, address checks, and modifier traps that can block token holders from transferring or selling."
    },
    {
      rule_id: "HONEYPOT_SELL_RESTRICTION",
      rule_name: "Asymmetric Sell / DEX Transfer Restriction",
      category: "Trading Restrictions",
      severity: "CRITICAL",
      confidence: "HIGH",
      description: "Detects transfer conditions that selectively restrict selling to DEX liquidity pools."
    },
    {
      rule_id: "HONEYPOT_EXCESSIVE_SELL_TAX",
      rule_name: "Excessive or Confiscatory Sell Tax",
      category: "Fee Manipulation",
      severity: "CRITICAL",
      confidence: "HIGH",
      description: "Detects hardcoded or dynamic tax rates that exceed normal trading levels (>= 25%)."
    },
    {
      rule_id: "HONEYPOT_UNLIMITED_OWNER_TAX",
      rule_name: "Unbounded Owner Fee Setter",
      category: "Fee Manipulation",
      severity: "HIGH",
      confidence: "HIGH",
      description: "Detects fee setter functions without an upper bound limit check (sanity cap)."
    },
    {
      rule_id: "HONEYPOT_TRADING_COOLDOWN_DELAY",
      rule_name: "Transfer Delay or Trading Cooldown Lockup",
      category: "Trading Restrictions",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      description: "Detects transfer delay timers or cooldown blocks that can freeze selling."
    },
    {
      rule_id: "HONEYPOT_PAUSABLE_TRANSFERS",
      rule_name: "Owner-Controlled Pausable Transfers",
      category: "Access Control & Transfer Restrictions",
      severity: "MEDIUM",
      confidence: "HIGH",
      description: "Detects owner-controlled transfer pause mechanisms that can freeze liquidity."
    },
    {
      rule_id: "HONEYPOT_MAX_WALLET_TX_LIMIT",
      rule_name: "Restrictive Transaction or Wallet Limit",
      category: "Trading Restrictions",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      description: "Detects micro-limits on transaction or wallet amounts that prevent liquidating tokens."
    },
    {
      rule_id: "HONEYPOT_HIDDEN_MINT",
      rule_name: "Privileged Unconstrained Minting",
      category: "Supply Manipulation",
      severity: "HIGH",
      confidence: "HIGH",
      description: "Detects hidden or unconstrained token minting capability outside constructor."
    },
    {
      rule_id: "HONEYPOT_SUSPICIOUS_ASSEMBLY",
      rule_name: "Inline Assembly or Delegatecall in Transfer Logic",
      category: "Code Obfuscation & Low-Level Calls",
      severity: "HIGH",
      confidence: "HIGH",
      description: "Detects inline assembly blocks or delegatecalls within transfer paths."
    },
    {
      rule_id: "HONEYPOT_EXTERNAL_RESTRICTION_CALL",
      rule_name: "External Oracle / Permission Call in Transfer",
      category: "External Dependencies",
      severity: "CRITICAL",
      confidence: "MEDIUM",
      description: "Detects external contract calls during transfer logic that can trigger reverts on sells."
    }
  ];
  res.json(rules);
});

/**
 * POST /api/train-ml
 * Retrain ML models via Python pipeline
 */
router.post("/train-ml", (req, res) => {
  const pythonExe = getPythonExecutable();
  const proc = spawn(pythonExe, ["main.py", "--train-ml"], {
    cwd: BASE_DIR,
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
    shell: true
  });

  let output = "";
  let errorOutput = "";

  proc.stdout.on("data", (data) => output += data.toString());
  proc.stderr.on("data", (data) => errorOutput += data.toString());

  proc.on("close", (code) => {
    if (code !== 0) {
      return res.status(500).json({ error: "Model training failed.", details: errorOutput });
    }
    res.json({
      success: true,
      message: "Machine learning models retrained and persisted successfully.",
      log: output
    });
  });
});

module.exports = router;
