import React from 'react';

export default function ThreatVerdictBanner({ report, onDismiss }) {
  if (!report) return null;

  const contract = report.contract || {};
  const risk = report.risk_assessment || report.risk_report || {};
  const ml = report.machine_learning || report.ml_prediction || {};
  const score = risk.risk_score ?? 0;
  const level = (risk.risk_level ?? 'LOW').toUpperCase();
  const isHp = ml.is_honeypot ?? false;

  let bannerClass = 'verdict-banner-benign';
  let icon = '🛡️';
  let headline = 'BENIGN AUDITED CONTRACT — NO HONEYPOT TRAPS DETECTED';
  let recommendation = 'Standard ERC-20 transfer invariants verified. No confiscatory taxes, blacklists, or asymmetric sell restrictions identified.';
  let actionAdvice = 'NORMAL INTERACTION SAFE';

  if (level === 'CRITICAL' || isHp) {
    bannerClass = 'verdict-banner-critical';
    icon = '🚨';
    headline = 'CRITICAL HONEYPOT SCAM DETECTED — FUNDS AT IMMINENT RISK OF FORFEITURE';
    recommendation = 'Contract contains malicious traps designed to prevent token holders from liquidating assets or confiscate funds via 99% taxes.';
    actionAdvice = 'DO NOT BUY / DO NOT INTERACT';
  } else if (level === 'HIGH') {
    bannerClass = 'verdict-banner-high';
    icon = '⚠️';
    headline = 'HIGH RISK CONTRACT — PRIVILEGED BACKDOORS DETECTED';
    recommendation = 'Unbounded fee setters, unconstrained minting backdoors, or arbitrary blacklist structures identified. Deployer can modify rules post-launch.';
    actionAdvice = 'HIGH DILIGENCE REQUIRED / RISK OF CAPITAL LOSS';
  } else if (level === 'MODERATE') {
    bannerClass = 'verdict-banner-moderate';
    icon = '🟡';
    headline = 'MODERATE RISK — CENTRALIZED ENTERPRISE CONTROLS PRESENT';
    recommendation = 'Contract implements emergency pause switches, anti-bot cooldown delays, or anti-whale wallet limits. Review governance multi-sig.';
    actionAdvice = 'CAUTION / VERIFY TIMELOCK & GOVERNANCE';
  }

  return (
    <div className={`threat-verdict-banner ${bannerClass}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px' }}>
        <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
          <span style={{ fontSize: '2.4rem', lineHeight: 1 }}>{icon}</span>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span className="verdict-level-tag">{level} THREAT</span>
              <span className="verdict-score-tag">Risk Score: {score}/100</span>
              <span className="verdict-action-pill">{actionAdvice}</span>
            </div>
            <h2 className="verdict-headline">{headline}</h2>
            <p className="verdict-recommendation">{recommendation}</p>
            <div className="verdict-meta">
              Target: <b>{contract.name || 'Contract'}</b> ({contract.network?.toUpperCase() || 'ETHEREUM'}) | Compiler: <code>{contract.compiler_version || '^0.8.20'}</code>
            </div>
          </div>
        </div>

        {onDismiss && (
          <button
            type="button"
            className="btn-verdict-dismiss"
            onClick={onDismiss}
            title="Dismiss current report"
          >
            ✕ Dismiss
          </button>
        )}
      </div>
    </div>
  );
}
