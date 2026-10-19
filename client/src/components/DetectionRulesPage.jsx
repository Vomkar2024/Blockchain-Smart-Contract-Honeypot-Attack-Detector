import React, { useState } from 'react';

export default function DetectionRulesPage({ onBack }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [copiedCode, setCopiedCode] = useState(false);

  // Interactive Risk Simulator state
  const [selectedRules, setSelectedRules] = useState({
    r1: false, // Reproducible successful buy followed by failed sell (+50)
    r2: false, // Confirmed on-chain evidence of blocked investor sells (+35)
    r3: false, // Sell-specific blacklist or transfer-denial logic (+25)
    r4: false, // Owner can raise sell tax above 50% (+20)
    r5: false, // Sell tax can reach 90–100% (+30)
    r6: false, // Sell limit effectively prevents an investor from exiting (+20)
    r7: false, // Owner can enable/disable trading or change restrictions (+12)
    r8: false, // Owner-controlled blacklist or transfer pause (+10)
    r9: false, // Unresolved proxy or upgradeable implementation (+10)
    r10: false, // Unverified contract or unresolved external dependency (+10)
  });

  const scoringRules = [
    { id: 'r1', label: 'Reproducible successful buy followed by failed sell', points: 50, criticalOverride: true },
    { id: 'r2', label: 'Confirmed on-chain evidence of blocked investor sells', points: 35 },
    { id: 'r3', label: 'Sell-specific blacklist or transfer-denial logic', points: 25 },
    { id: 'r4', label: 'Owner can raise sell tax above 50%', points: 20 },
    { id: 'r5', label: 'Sell tax can reach 90–100%', points: 30 },
    { id: 'r6', label: 'Sell limit effectively prevents an investor from exiting', points: 20 },
    { id: 'r7', label: 'Owner can enable/disable trading or change restrictions', points: 12 },
    { id: 'r8', label: 'Owner-controlled blacklist or transfer pause', points: 10 },
    { id: 'r9', label: 'Unresolved proxy or upgradeable implementation', points: 10 },
    { id: 'r10', label: 'Unverified contract or unresolved external dependency', points: 10 },
  ];

  // Calculate dynamic simulator score
  const rawScore = scoringRules.reduce((acc, rule) => acc + (selectedRules[rule.id] ? rule.points : 0), 0);
  const cappedScore = Math.min(rawScore, 100);
  const isCriticalOverride = selectedRules['r1'];

  let riskTier = 'Lower detected risk';
  let tierBadge = 'badge-low';
  let tierAdvice = 'Limited evidence';

  if (isCriticalOverride || cappedScore >= 80) {
    riskTier = 'Critical';
    tierBadge = 'badge-critical';
    tierAdvice = 'Avoid pending investigation';
  } else if (cappedScore >= 50) {
    riskTier = 'High risk';
    tierBadge = 'badge-high';
    tierAdvice = 'Strong warning';
  } else if (cappedScore >= 20) {
    riskTier = 'Elevated';
    tierBadge = 'badge-medium';
    tierAdvice = 'Review needed';
  }

  // Core detection rules specification
  const coreRules = [
    {
      id: 'HP-01',
      title: 'Sell transaction blocked',
      severity: 'Critical',
      badgeClass: 'badge-critical',
      description: 'A purchase succeeds, but selling the acquired tokens through the relevant decentralized exchange repeatedly reverts, fails, or produces no meaningful output.',
      detection: 'Simulate buy → approve → sell against a fork of the relevant chain state.',
      category: 'DEX Sell Execution Path',
      mappedRule: 'HONEYPOT_SELL_RESTRICTION / DYNAMIC_SIMULATION',
    },
    {
      id: 'HP-02',
      title: 'Hidden blacklist',
      severity: 'Critical',
      badgeClass: 'badge-critical',
      description: 'Detect logic that rejects transfers from selected wallets when tokens are sent to a liquidity pool. Check whether transfer, transferFrom, or approve can add buyers to a blacklist.',
      detection: 'Inspect blacklist mappings, wallet-specific restrictions, privileged exemptions, and sell-path conditions.',
      category: 'Access Control & Transfer Restrictions',
      mappedRule: 'HONEYPOT_BLACKLIST',
    },
    {
      id: 'HP-03',
      title: 'Excessive or adjustable sell tax',
      severity: 'Critical / High',
      badgeClass: 'badge-critical',
      description: 'Identify separate buy and sell fee variables, privileged fee setters, uncapped taxes, or conditional logic capable of charging nearly 100% of a sale.',
      detection: 'Calculate the effective tax at runtime and identify who can change it.',
      category: 'Taxation & Fee Traps',
      mappedRule: 'HONEYPOT_EXCESSIVE_TAX / HONEYPOT_UNLIMITED_TAX',
    },
    {
      id: 'HP-04',
      title: 'Hidden selling limits',
      severity: 'High',
      badgeClass: 'badge-high',
      description: 'Find maximum-sell limits, maximum transaction sizes, wallet caps, cooldowns, and one-sell-per-block restrictions that prevent normal investors from exiting.',
      detection: 'Test limits against actual purchased balances and available liquidity, not only declared constants.',
      category: 'Liquidity & Transaction Throttling',
      mappedRule: 'HONEYPOT_MAX_WALLET_LIMIT / HONEYPOT_COOLDOWN_DELAY',
    },
    {
      id: 'HP-05',
      title: 'Trading controls',
      severity: 'High',
      badgeClass: 'badge-high',
      description: 'Identify owner-controlled switches that pause transfers, disable selling, restrict trading to approved wallets, or change transaction rules after investors buy.',
      detection: 'Trace owner privilege modifiers, pause flags, and emergency stops on transfer execution.',
      category: 'Governance & Administrative Switches',
      mappedRule: 'HONEYPOT_PAUSABLE',
    },
    {
      id: 'HP-06',
      title: 'Hidden or upgradeable logic',
      severity: 'High',
      badgeClass: 'badge-high',
      description: 'Flag unresolved proxy implementations, privileged delegatecall paths, external contracts that control transfer decisions, and unverified dependencies.',
      detection: 'Analyze the complete execution path and determine whether the implementation can change.',
      category: 'Proxies & External Code Delegation',
      mappedRule: 'HONEYPOT_EXTERNAL_RESTRICTION_CALL / SUSPICIOUS_ASSEMBLY',
    },
    {
      id: 'HP-07',
      title: 'Abnormal token accounting',
      severity: 'High',
      badgeClass: 'badge-high',
      description: 'Check whether transfers deduct unexpected amounts, silently confiscate balances, emit misleading transfer events, or behave inconsistently between ordinary wallets and liquidity pools.',
      detection: 'Audit balance storage slot updates, deflationary fee deductions, and transfer event logs.',
      category: 'Ledger Accounting & Balance Traps',
      mappedRule: 'HONEYPOT_HIDDEN_MINT / ASYMMETRIC_BALANCE_DEDUCTION',
    },
  ];

  // All 15 Forensic Engine Detection Rules across 10 Attack Vectors
  const all15Rules = [
    { num: '01', id: 'HONEYPOT_BLACKLIST', name: 'Arbitrary Address Blacklist Mechanism', severity: 'HIGH', category: 'Access Control', desc: 'Detects blacklist mappings, modifier guards, and selective address reverts.' },
    { num: '02', id: 'HONEYPOT_SELL_RESTRICTION', name: 'Asymmetric Sell Denial to DEX Pools', severity: 'CRITICAL', category: 'Transfer Logic', desc: 'Permits purchasing while reverting transfers sent to Uniswap/PancakeSwap pairs.' },
    { num: '03', id: 'HONEYPOT_EXCESSIVE_TAX', name: 'Confiscatory Sell Tax (> 25% up to 100%)', severity: 'CRITICAL', category: 'Taxation Traps', desc: 'Identifies hardcoded exorbitant sell fees that drain investor capital upon exit.' },
    { num: '04', id: 'HONEYPOT_UNLIMITED_TAX', name: 'Uncapped Owner Tax Setter Function', severity: 'HIGH', category: 'Taxation Traps', desc: 'Allows the deployer to arbitrarily raise fees to 99%-100% post-deployment.' },
    { num: '05', id: 'HONEYPOT_COOLDOWN_DELAY', name: 'Sell-Trapping Cooldown & Block Delay', severity: 'HIGH', category: 'Trading Throttling', desc: 'Artificially restricts sell frequency via block numbers or timestamp gates.' },
    { num: '06', id: 'HONEYPOT_PAUSABLE', name: 'Owner-Controlled Transfer Freeze Switch', severity: 'HIGH', category: 'Access Control', desc: 'Deployer can pause all trading after liquidity is supplied and users buy.' },
    { num: '07', id: 'HONEYPOT_MAX_WALLET_LIMIT', name: 'Micro Max Sell / Wallet Holding Ceiling', severity: 'HIGH', category: 'Limits & Quotas', desc: 'Restricts sells to negligible fractions (<0.01% or 1 wei), preventing liquidation.' },
    { num: '08', id: 'HONEYPOT_HIDDEN_MINT', name: 'Unbounded Owner Mint Privilege', severity: 'HIGH', category: 'Supply Manipulation', desc: 'Allows owner to print unlimited tokens, diluting pool balances and crashing value.' },
    { num: '09', id: 'HONEYPOT_SUSPICIOUS_ASSEMBLY', name: 'Inline EVM Assembly & Delegatecall Injection', severity: 'HIGH', category: 'Bytecode & Assembly', desc: 'Obfuscates transfer logic or executes external unchecked delegatecalls.' },
    { num: '10', id: 'HONEYPOT_EXTERNAL_RESTRICTION_CALL', name: 'External Oracle / Permission Call in Transfer', severity: 'CRITICAL', category: 'External Dependencies', desc: 'Delegates transfer authorization to external unverified contracts that revert sells.' },
    { num: '11', id: 'HONEYPOT_VARIABLE_NAME_SHADOWING', name: 'State Variable & Storage Slot Shadowing', severity: 'MEDIUM', category: 'Compiler & Storage', desc: 'Shadows standard balance or allowance slots to conceal malicious overrides.' },
    { num: '12', id: 'HONEYPOT_REENTRANCY_TRAP', name: 'Asymmetric Reentrancy Sell Trap', severity: 'HIGH', category: 'State Consistency', desc: 'Crafts state mutation ordering that triggers reverts exclusively during DEX router callbacks.' },
    { num: '13', id: 'HONEYPOT_SELFDESTRUCT_LOGIC', name: 'Emergency Selfdestruct / Liquidity Extraction', severity: 'CRITICAL', category: 'Contract Lifecycle', desc: 'Enables contract self-destruction or draining locked collateral tokens.' },
    { num: '14', id: 'HONEYPOT_DEAD_CODE_TRAP', name: 'Concealed Fallback / Trap Door Function', severity: 'MEDIUM', category: 'EVM Execution', desc: 'Hidden administrative entry points triggered via specific call data payloads.' },
    { num: '15', id: 'HONEYPOT_MIGRATION_DRAIN', name: 'Bogus Token Upgrade / Migration Drain', severity: 'HIGH', category: 'Governance & Upgrade', desc: 'Forced migration routines that confiscate user balances under false pretext.' },
  ];

  const pseudocodeString = `def assess_honeypot(analysis):
    findings = []
    score = 0

    # Do not interpret failed infrastructure checks as proof of fraud.
    if not analysis.simulation_complete:
        return {
            "status": "UNKNOWN",
            "reason": "Simulation incomplete",
            "findings": findings
        }

    # HP-01: Reproduced buy success followed by sell failure
    if analysis.buy_succeeded and analysis.sell_failed_reproducibly:
        findings.append("HP-01: BUY_SUCCEEDS_SELL_FAILS")
        score += 50

    # HP-02: Hidden or sell-specific blacklist logic
    if analysis.sell_specific_blacklist:
        findings.append("HP-02: SELL_PATH_BLACKLIST")
        score += 25

    # HP-03: Excessive or adjustable sell tax
    if analysis.sell_tax_can_exceed_50_percent:
        findings.append("HP-03: EXTREME_SELL_TAX")
        score += 20

    # HP-04: Restrictive sell limits blocking exit
    if analysis.sell_limit_blocks_normal_exit:
        findings.append("HP-04: RESTRICTIVE_SELL_LIMIT")
        score += 20

    # HP-05: Privileged trading pause or rule modification
    if analysis.owner_can_change_transfer_rules:
        findings.append("HP-05: PRIVILEGED_TRADING_CONTROL")
        score += 12

    # Cap score at 100
    score = min(score, 100)

    # Directly reproduced buy-success/sell-failure triggers critical warning
    if analysis.buy_succeeded and analysis.sell_failed_reproducibly:
        status = "CRITICAL"
    elif score >= 80:
        status = "CRITICAL"
    elif score >= 50:
        status = "HIGH"
    elif score >= 20:
        status = "ELEVATED"
    else:
        status = "LOW"

    return {
        "status": status,
        "score": score,
        "findings": findings,
        "confidence": analysis.confidence_level
    }`;

  const copyPseudocode = () => {
    navigator.clipboard.writeText(pseudocodeString);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2500);
  };

  const filteredCoreRules = coreRules.filter(rule => {
    const matchesSearch = rule.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.category.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity === 'ALL' || rule.severity.includes(selectedSeverity);
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="rules-page-container">
      {/* Top Navigation & Breadcrumb */}
      <div className="rules-nav-bar" style={{ justifyContent: 'flex-end' }}>
        <div className="status-pill" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.3)' }}>
          <span>SPECIFICATION & ARCHITECTURE · v2.4</span>
        </div>
      </div>

      {/* Hero Banner */}
      <div className="rules-hero-card">
        <div className="rules-hero-badge">EVM Security Standard · 2025/2026 Forensic Benchmark</div>
        <h1 className="rules-hero-title">Blockchain Smart Contract Honeypot Detector</h1>
        <p className="rules-hero-sub">Detection rules · EVM-compatible tokens · Investor protection</p>

        <div className="rules-hero-desc">
          <p>
            The objective is to inspect cryptocurrency smart contracts and identify tokens that let investors
            <b> buy successfully but prevent them from selling, transfer their tokens, or recover their funds</b>.
          </p>
          <p style={{ marginTop: '10px' }}>
            A reliable detector combines three core techniques: <b>static contract analysis</b>, <b>simulated buy-and-sell transactions</b>, and <b>on-chain behavior monitoring</b>. Research published in <i>Discover Computing in 2025</i> describes bytecode analysis of ERC-20 transfer logic, while existing security services utilize sell simulations, dynamic tax analysis, and blacklist detection.
          </p>
        </div>

        <div className="citation-pill-row">
          <a
            href="https://link.springer.com/journal/10791"
            target="_blank"
            rel="noopener noreferrer"
            className="citation-pill"
          >
            <span>📄 Discover Computing (2025) · Springer Nature Link ↗</span>
          </a>
          <div className="citation-pill-secondary">
            <span>🛡️ Covers 10 Attack Vectors & 15 Heuristic Enforcement Rules</span>
          </div>
        </div>
      </div>

      {/* Section 1: Core Detection Rules */}
      <section className="glass-card rules-section">
        <div className="section-header-row">
          <div>
            <h2 className="section-title">1. Core Honeypot Detection Rules</h2>
            <p className="section-subtitle">
              Fundamental heuristics designed to uncover blocked transfers, trap conditions, and liquidation barriers.
            </p>
          </div>
          <div className="rules-filter-bar">
            <input
              type="text"
              placeholder="🔍 Search rules by name, ID, or behavior..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rules-search-input"
            />
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="rules-severity-select"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical Only</option>
              <option value="High">High Only</option>
            </select>
          </div>
        </div>

        <div className="rules-cards-grid">
          {filteredCoreRules.map((rule) => (
            <div key={rule.id} className="core-rule-card">
              <div className="core-rule-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="rule-id-tag">{rule.id}</span>
                  <h3 className="rule-name-heading">{rule.title}</h3>
                </div>
                <span className={`sev-badge badge ${rule.badgeClass}`}>{rule.severity}</span>
              </div>
              <p className="rule-desc-text">{rule.description}</p>

              <div className="rule-meta-box">
                <div className="rule-meta-item">
                  <span className="meta-label">🎯 Detection Strategy:</span>
                  <span className="meta-content">{rule.detection}</span>
                </div>
                <div className="rule-meta-item" style={{ marginTop: '8px' }}>
                  <span className="meta-label">🏷️ Category:</span>
                  <span className="meta-content-badge">{rule.category}</span>
                  <span style={{ margin: '0 8px', color: '#64748b' }}>|</span>
                  <span className="meta-label">Engine Rule:</span>
                  <code className="meta-code">{rule.mappedRule}</code>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="literature-note">
          <span>ℹ️ <b>Comprehensive Coverage:</b> These rules cover common documented patterns, including blacklisting, transfer locks, upgradeable proxies, blocked transfers, and restrictive sell limits. (<a href="https://link.springer.com" target="_blank" rel="noopener noreferrer" style={{ color: '#38bdf8' }}>Springer Nature Link</a>)</span>
        </div>

        {/* Complete 15 Rules Table */}
        <div style={{ marginTop: '36px' }}>
          <h3 style={{ fontSize: '1.15rem', color: '#f8fafc', fontWeight: 700, marginBottom: '6px' }}>
            📋 Complete 15-Rule Static & Behavioral Enforcement Matrix
          </h3>
          <p style={{ color: '#94a3b8', fontSize: '0.86rem', marginBottom: '16px' }}>
            The 15 modular rule heuristics implemented in the forensic engine mapped across all 10 verified attack vectors:
          </p>

          <div style={{ overflowX: 'auto' }}>
            <table className="rules-matrix-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Rule Identifier</th>
                  <th>Detection Mechanism & Name</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Forensic Target</th>
                </tr>
              </thead>
              <tbody>
                {all15Rules.map((r) => (
                  <tr key={r.num}>
                    <td style={{ color: '#94a3b8', fontWeight: 600 }}>{r.num}</td>
                    <td><code style={{ color: '#38bdf8', fontSize: '0.82rem' }}>{r.id}</code></td>
                    <td style={{ fontWeight: 600, color: '#f8fafc' }}>{r.name}</td>
                    <td><span className="category-pill">{r.category}</span></td>
                    <td>
                      <span className={`sev-badge badge ${r.severity === 'CRITICAL' ? 'badge-critical' : r.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                        {r.severity}
                      </span>
                    </td>
                    <td style={{ color: '#94a3b8', fontSize: '0.84rem' }}>{r.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Section 2: Risk Scoring Engine */}
      <section className="glass-card rules-section">
        <h2 className="section-title">2. Risk Scoring Engine</h2>
        <p className="section-subtitle">
          Configurable 0–100 score policy. Treat this as a proposed initial scoring policy, not a statistically validated prediction model.
        </p>

        <div className="scoring-layout-grid">
          {/* Points Table */}
          <div className="scoring-table-card">
            <h3 style={{ fontSize: '1.05rem', color: '#f8fafc', fontWeight: 600, marginBottom: '12px' }}>
              ⚖️ Rule Penalty Points Table
            </h3>
            <div style={{ overflowX: 'auto' }}>
              <table className="scoring-points-table">
                <thead>
                  <tr>
                    <th>Rule Detected</th>
                    <th style={{ textAlign: 'right' }}>Points</th>
                  </tr>
                </thead>
                <tbody>
                  {scoringRules.map((sr) => (
                    <tr key={sr.id}>
                      <td>
                        <span style={{ color: '#f8fafc' }}>{sr.label}</span>
                        {sr.criticalOverride && (
                          <span className="override-tag">CRITICAL OVERRIDE</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right', fontWeight: 700, color: '#f87171' }}>
                        +{sr.points}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '12px' }}>
              * Count correlated findings only once where appropriate. Cap the aggregate score at 100, and evaluate a separate confidence rating.
            </p>
          </div>

          {/* Dynamic Interactive Simulator */}
          <div className="simulator-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ fontSize: '1.05rem', color: '#f8fafc', fontWeight: 600 }}>
                🧮 Interactive Risk Simulator
              </h3>
              <button
                type="button"
                className="btn-reset-sim"
                onClick={() => setSelectedRules({})}
              >
                Reset Toggles
              </button>
            </div>
            <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginBottom: '14px' }}>
              Toggle detected rules below to test the live scoring engine calculations:
            </p>

            <div className="simulator-checklist">
              {scoringRules.map((sr) => (
                <label key={sr.id} className="sim-checkbox-label">
                  <input
                    type="checkbox"
                    checked={!!selectedRules[sr.id]}
                    onChange={(e) => setSelectedRules(prev => ({ ...prev, [sr.id]: e.target.checked }))}
                    className="sim-checkbox"
                  />
                  <span className="sim-label-text">{sr.label}</span>
                  <span className="sim-pts-badge">+{sr.points}</span>
                </label>
              ))}
            </div>

            {/* Live Score Display */}
            <div className="sim-result-box">
              <div className="sim-score-left">
                <span style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase' }}>Simulated Risk Score</span>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                  <span className="sim-score-number">{cappedScore}</span>
                  <span style={{ color: '#64748b', fontSize: '1rem' }}>/ 100</span>
                </div>
              </div>
              <div className="sim-score-right">
                <span className={`sev-badge badge ${tierBadge}`} style={{ fontSize: '0.9rem', padding: '6px 16px' }}>
                  {riskTier}
                </span>
                <span style={{ fontSize: '0.82rem', color: '#cbd5e1', marginTop: '4px' }}>
                  Action: <b>{tierAdvice}</b>
                </span>
              </div>
            </div>

            {isCriticalOverride && (
              <div className="critical-override-banner">
                ⚠️ <b>CRITICAL OVERRIDE TRIGGERED:</b> A reproducible buy-success with sell-failure automatically forces a <b>CRITICAL</b> threat status regardless of other metrics!
              </div>
            )}
          </div>
        </div>

        {/* Proposed Risk Classification Tiers */}
        <div style={{ marginTop: '28px' }}>
          <h3 style={{ fontSize: '1.1rem', color: '#f8fafc', fontWeight: 600, marginBottom: '14px' }}>
            📊 Proposed Risk Classification Tiers
          </h3>
          <div className="risk-tiers-grid">
            <div className="risk-tier-card tier-low">
              <span className="tier-range">0–19</span>
              <h4 className="tier-name">Lower detected risk</h4>
              <p className="tier-sub">Limited evidence of restriction</p>
              <span className="tier-action">Action: Standard Due Diligence</span>
            </div>
            <div className="risk-tier-card tier-elevated">
              <span className="tier-range">20–49</span>
              <h4 className="tier-name">Elevated</h4>
              <p className="tier-sub">Review needed</p>
              <span className="tier-action">Action: Audit Owner Keys & Limits</span>
            </div>
            <div className="risk-tier-card tier-high">
              <span className="tier-range">50–79</span>
              <h4 className="tier-name">High risk</h4>
              <p className="tier-sub">Strong warning</p>
              <span className="tier-action">Action: Extreme Caution Recommended</span>
            </div>
            <div className="risk-tier-card tier-critical">
              <span className="tier-range">80–100</span>
              <h4 className="tier-name">Critical</h4>
              <p className="tier-sub">Avoid pending investigation</p>
              <span className="tier-action">Action: High Honeypot Probability</span>
            </div>
          </div>
        </div>

        {/* Safety Callouts */}
        <div className="callout-grid">
          <div className="callout-box callout-danger">
            <b>⚡ Critical Override Policy:</b> A directly reproduced buy-success/sell-failure result should trigger a critical warning regardless of the aggregate score.
          </div>
          <div className="callout-box callout-warning">
            <b>🛡️ Safe Fallback Protocol:</b> When simulation or code analysis is incomplete, display <code>UNKNOWN</code> rather than incorrectly reporting a safe token.
          </div>
        </div>
      </section>

      {/* Section 3: Detection Architecture */}
      <section className="glass-card rules-section">
        <h2 className="section-title">3. Detection Architecture & 3-Stage Pipeline</h2>
        <p className="section-subtitle">
          End-to-end multi-stage pipeline taking contract inputs and evaluating forensic evidence across static and dynamic domains.
        </p>

        {/* Pipeline Diagram */}
        <div className="pipeline-flow-container">
          <div className="pipeline-step-node step-input">
            <span className="node-badge">INPUT</span>
            <h4>Contract Ingestion</h4>
            <p>Contract Address + Chain ID</p>
            <span className="node-detail">Validate address, chain, bytecode & token standard</span>
          </div>

          <div className="pipeline-arrow">➔</div>

          <div className="pipeline-step-node step-a">
            <span className="node-badge" style={{ background: '#6366f1' }}>STAGE A</span>
            <h4>Static Analysis</h4>
            <p>Source & AST Inspection</p>
            <span className="node-detail">Transfer paths, access controls, fee setters, proxies & inline assembly</span>
          </div>

          <div className="pipeline-arrow">➔</div>

          <div className="pipeline-step-node step-b">
            <span className="node-badge" style={{ background: '#0284c7' }}>STAGE B</span>
            <h4>Transaction Simulation</h4>
            <p>Forked State Sandbox</p>
            <span className="node-detail">Buy → approve → sell simulation with variable sizes & fresh wallets</span>
          </div>

          <div className="pipeline-arrow">➔</div>

          <div className="pipeline-step-node step-c">
            <span className="node-badge" style={{ background: '#d97706' }}>STAGE C</span>
            <h4>On-Chain Behavior</h4>
            <p>Historical & Ledger Audit</p>
            <span className="node-detail">DEX sell failures, holder restrictions, dynamic tax hikes & liquidity pulls</span>
          </div>

          <div className="pipeline-arrow">➔</div>

          <div className="pipeline-step-node step-output">
            <span className="node-badge" style={{ background: '#10b981' }}>OUTPUT</span>
            <h4>Investor Report</h4>
            <p>Risk Engine Verdict</p>
            <span className="node-detail">Score (0–100), severity, confidence rating, rule IDs & evidence</span>
          </div>
        </div>

        {/* Decision Logic */}
        <div style={{ marginTop: '32px' }}>
          <h3 style={{ fontSize: '1.1rem', color: '#f8fafc', fontWeight: 600, marginBottom: '16px' }}>
            🧭 5-Step Engine Decision Logic
          </h3>
          <div className="decision-steps-list">
            <div className="decision-step-item">
              <span className="step-num-pill">1</span>
              <div>
                <b>Resolve verified source code and runtime bytecode:</b>
                <p>Inspect all relevant external calls, inheritance hierarchies, and resolve proxy implementations (EIP-1967, Diamond proxies) where possible.</p>
              </div>
            </div>
            <div className="decision-step-item">
              <span className="step-num-pill">2</span>
              <div>
                <b>Identify actual trading pair and router:</b>
                <p>Query factory contracts on the selected chain (e.g. Uniswap V2/V3 on Ethereum, PancakeSwap on BSC) to locate genuine liquidity pools.</p>
              </div>
            </div>
            <div className="decision-step-item">
              <span className="step-num-pill">3</span>
              <div>
                <b>Fork latest chain state and simulate execution:</b>
                <p>Simulate a realistic purchase followed by approval and sale against a sandbox chain fork. Repeat with different trade sizes and pristine wallet states to defeat single-wallet exemptions.</p>
              </div>
            </div>
            <div className="decision-step-item">
              <span className="step-num-pill">4</span>
              <div>
                <b>Trace failed sells for root-cause diagnosis:</b>
                <p>Distinguish token-level programmatic restrictions (e.g., custom reverts, balance check traps) from insufficient DEX liquidity, price impact, slippage, or unrelated router gas issues.</p>
              </div>
            </div>
            <div className="decision-step-item">
              <span className="step-num-pill">5</span>
              <div>
                <b>Evaluate static rules, calculate score, and preserve evidence:</b>
                <p>Combine static AST indicators with simulation traces and historical behavior, compute the explainable risk score, and retain line-by-line evidence behind each triggered finding.</p>
              </div>
            </div>
          </div>
        </div>

        {/* 2025 Study Limitation Notice */}
        <div className="callout-box callout-warning" style={{ marginTop: '20px' }}>
          <b>⚠️ Important Limitation Notice:</b> A single successful sell simulation is <b>not proof of safety</b>. Some contracts can change taxes or trading restrictions after the scan. A 2025 detection study published in <i>Discover Computing</i> also identifies limitations of simulation-based checks for honeypots equipped with toggle mechanisms or time-delayed activation. (<a href="https://link.springer.com" target="_blank" rel="noopener noreferrer" style={{ color: '#38bdf8' }}>Springer Nature Link</a>)
        </div>
      </section>

      {/* Section 4: Example Detection Rules in Pseudocode */}
      <section className="glass-card rules-section">
        <div className="section-header-row">
          <div>
            <h2 className="section-title">4. Example Detection Rules in Pseudocode</h2>
            <p className="section-subtitle">
              Reference assessment algorithm illustrating simulation validation, rule accumulation, and critical override logic.
            </p>
          </div>
          <button type="button" className="btn-copy-code" onClick={copyPseudocode}>
            {copiedCode ? '✓ Copied to Clipboard!' : '📋 Copy Pseudocode'}
          </button>
        </div>

        <div className="code-viewer-container">
          <div className="code-viewer-header">
            <span>honeypot_evaluator.py (Python / Starter Specification)</span>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>UTF-8 · Python 3.10+</span>
          </div>
          <pre className="code-pre-block">
            <code>{pseudocodeString}</code>
          </pre>
        </div>

        <p style={{ color: '#94a3b8', fontSize: '0.88rem', marginTop: '14px', lineHeight: 1.6 }}>
          💡 <b>Engineering Note:</b> This is a starter specification; the analysis fields must come from actual bytecode inspection, transaction traces, and a reliable simulation environment. Production code implements the remaining rules and explicit error handling before relying on the final risk verdict.
        </p>
      </section>

      {/* Section 5: Recommended Integration */}
      <section className="glass-card rules-section">
        <h2 className="section-title">5. Recommended Integration & Threat Boundaries</h2>
        <p className="section-subtitle">
          Benchmark your rule engine against industry-standard security APIs, and maintain clear threat classification boundaries.
        </p>

        <div className="integrations-grid">
          {/* Honeypot.is Card */}
          <div className="integration-card">
            <div className="integration-header">
              <span className="integration-icon">🍯</span>
              <div>
                <h3 className="integration-title">Honeypot.is API</h3>
                <span className="integration-badge">Dynamic Simulation Engine</span>
              </div>
            </div>
            <p className="integration-desc">
              Provides real-time buy/sell simulations, tax results, sell limits when detected, source-code indicators, and deterministic honeypot findings across Ethereum, BNB Chain, and EVM L2s.
            </p>
            <a
              href="https://docs.honeypot.is/ishoneypot"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-api-link"
            >
              <span>View Honeypot.is API Docs ↗</span>
            </a>
          </div>

          {/* GoPlus Security Card */}
          <div className="integration-card">
            <div className="integration-header">
              <span className="integration-icon">🛡️</span>
              <div>
                <h3 className="integration-title">GoPlus Token Security API</h3>
                <span className="integration-badge">Comprehensive Multi-Chain API</span>
              </div>
            </div>
            <p className="integration-desc">
              Provides token security checks covering honeypots, blacklists, pausable transfers, buy/sell taxes, ownership controls, DEX liquidity lock verification, and malicious creator tracking.
            </p>
            <a
              href="https://docs.gopluslabs.io/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-api-link"
            >
              <span>View GoPlus Security Docs ↗</span>
            </a>
          </div>
        </div>

        {/* Honeypot vs Rug-pull distinction banner */}
        <div className="threat-boundary-box">
          <h3 style={{ fontSize: '1.05rem', color: '#f8fafc', fontWeight: 600, marginBottom: '8px' }}>
            ⚖️ Critical Forensic Distinction: Honeypot Risk vs. Rug-Pull Risk
          </h3>
          <p style={{ color: '#cbd5e1', fontSize: '0.9rem', lineHeight: 1.6 }}>
            <b>Keep honeypot risk separate from rug-pull risk.</b> Owner minting privileges, concentrated holder ownership, removable liquidity, and privileged withdrawals are serious investor threats, but they are <i>not by themselves proof that a token prevents selling</i>.
          </p>
          <p style={{ color: '#94a3b8', fontSize: '0.88rem', marginTop: '8px', lineHeight: 1.6 }}>
            The strongest initial product is an EVM-compatible scanner that gives investors a <b>clear verdict</b>, the <b>exact rules triggered</b>, and <b>reproducible evidence</b> explaining why a token is dangerous.
          </p>
        </div>

        {/* Back to Top / Return to Scanner Action */}
        <div style={{ textAlign: 'center', marginTop: '32px' }}>
          <button type="button" className="btn-back-scanner-large" onClick={onBack}>
            <span>← Return to Forensic Scanner</span>
          </button>
        </div>
      </section>
    </div>
  );
}
