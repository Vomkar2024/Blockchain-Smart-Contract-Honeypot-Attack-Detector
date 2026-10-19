const mongoose = require("mongoose");

const FindingSchema = new mongoose.Schema({
  rule_id: { type: String, required: true },
  rule_name: { type: String, required: true },
  category: { type: String, default: "General" },
  severity: { type: String, enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], default: "LOW" },
  confidence: { type: String, default: "MEDIUM" },
  line_number: { type: Number, default: null },
  evidence: { type: String, default: "" },
  explanation: { type: String, default: "" },
  suggested_verification: { type: String, default: "" }
}, { _id: false });

const PositiveIndicatorSchema = new mongoose.Schema({
  indicator_id: { type: String, required: true },
  name: { type: String, required: true },
  evidence: { type: String, default: "" },
  explanation: { type: String, default: "" }
}, { _id: false });

const AuditReportSchema = new mongoose.Schema({
  contractName: { type: String, required: true, default: "UnnamedContract" },
  contractAddress: { type: String, default: null },
  network: { type: String, default: "ethereum" },
  inputType: { type: String, enum: ["file", "source_code", "address", "bytecode", "preset"], default: "source_code" },
  riskScore: { type: Number, required: true, min: 0, max: 100, default: 0 },
  riskLevel: { type: String, enum: ["LOW", "MODERATE", "HIGH", "CRITICAL"], default: "LOW" },
  isHoneypot: { type: Boolean, default: false },
  mlProbability: { type: Number, default: 0.0 },
  mlConfidence: { type: Number, default: 0.0 },
  modelUsed: { type: String, default: "RandomForestClassifier" },
  featureContributions: { type: Map, of: Number, default: {} },
  findings: [FindingSchema],
  positiveIndicators: [PositiveIndicatorSchema],
  summaryExplanation: { type: String, default: "" },
  sourceCodeSnippet: { type: String, default: "" },
  rawReport: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("AuditReport", AuditReportSchema);
