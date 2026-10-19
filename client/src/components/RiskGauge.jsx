import React from 'react';

export default function RiskGauge({ risk, ml }) {
  if (!risk) return null;

  const score = risk.risk_score ?? 0;
  const level = (risk.risk_level ?? 'LOW').toUpperCase();
  const breakdown = risk.breakdown || {};

  // Color mapping based on risk level
  let colorHex = '#10b981';
  let badgeClass = 'badge-benign';
  if (level === 'CRITICAL') {
    colorHex = '#ef4444';
    badgeClass = 'badge-critical';
  } else if (level === 'HIGH') {
    colorHex = '#f97316';
    badgeClass = 'badge-high';
  } else if (level === 'MODERATE') {
    colorHex = '#eab308';
    badgeClass = 'badge-medium';
  }

  // Speedometer arc math: radius = 75, circumference = pi * r = 235.6
  const dashLength = (score / 100) * 235.6;

  // ML values
  const isHp = ml?.is_honeypot ?? false;
  const prob = ml?.honeypot_probability ?? 0;
  const conf = ml?.confidence_score ?? 0;
  const modelUsed = ml?.model_used ?? 'RandomForestClassifier';
  const contributions = ml?.feature_contributions ?? {};

  // Sort contributions by absolute magnitude
  const sortedContributions = Object.entries(contributions)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    .slice(0, 5);

  const formatFeatureName = (feat) => {
    return feat
      .replace(/^has_/, '')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div className="split-results">
      {/* 1. Explainable Risk Gauge Card */}
      <div className="glass-card" style={{ borderColor: `${colorHex}55` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
            🎯 Explainable Risk Score Gauge
          </h2>
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            Confidence: <b style={{ color: '#38bdf8' }}>{risk.confidence || 'HIGH'}</b>
          </span>
        </div>

        <div style={{ textAlign: 'center', padding: '10px 0' }}>
          <svg viewBox="0 0 200 120" width="260" height="150">
            {/* Background Arc */}
            <path
              d="M 25 100 A 75 75 0 0 1 175 100"
              fill="none"
              stroke="#1e293b"
              strokeWidth="16"
              strokeLinecap="round"
            />
            {/* Active Progress Arc */}
            <path
              d="M 25 100 A 75 75 0 0 1 175 100"
              fill="none"
              stroke={colorHex}
              strokeWidth="16"
              strokeLinecap="round"
              strokeDasharray={`${dashLength} 235.6`}
              style={{ transition: 'stroke-dasharray 1s ease' }}
            />
            {/* Center Score */}
            <text x="100" y="85" textAnchor="middle" fontSize="36" fontWeight="bold" fill={colorHex}>
              {score}
            </text>
            <text x="100" y="104" textAnchor="middle" fontSize="13" fill="#94a3b8">
              OUT OF 100
            </text>
          </svg>

          <div style={{ marginTop: '4px' }}>
            <span className={`sev-badge ${badgeClass}`} style={{ fontSize: '1rem', padding: '6px 18px' }}>
              {level} THREAT TIER
            </span>
          </div>
        </div>

        {/* Explainability Breakdown Chips */}
        <div className="breakdown-chips-grid">
          <div className="breakdown-chip">
            <span className="chip-label">Gross Heuristic</span>
            <span className="chip-val">{breakdown.gross_score ?? score} pts</span>
          </div>
          <div className="breakdown-chip">
            <span className="chip-label">Mitigations</span>
            <span className="chip-val" style={{ color: '#34d399' }}>
              -{breakdown.positive_deductions ?? 0} pts
            </span>
          </div>
          <div className="breakdown-chip">
            <span className="chip-label">Net Threat Score</span>
            <span className="chip-val" style={{ color: colorHex }}>
              {score}/100
            </span>
          </div>
          <div className="breakdown-chip">
            <span className="chip-label">Critical Findings</span>
            <span className="chip-val" style={{ color: breakdown.critical_findings_count > 0 ? '#f87171' : '#cbd5e1' }}>
              {breakdown.critical_findings_count ?? 0}
            </span>
          </div>
        </div>

        <div style={{ marginTop: '14px', background: 'rgba(15, 23, 42, 0.6)', padding: '12px 16px', borderRadius: '10px', fontSize: '0.88rem', color: '#cbd5e1', lineHeight: '1.45' }}>
          <b>Risk Breakdown:</b> {risk.summary_explanation}
        </div>
      </div>

      {/* 2. Machine Learning Inference Card */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
            🤖 ML Honeypot Classifier
          </h2>
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            Model: <code style={{ color: '#a78bfa' }}>{modelUsed}</code>
          </span>
        </div>

        <div style={{ textAlign: 'center', padding: '10px 0' }}>
          <span
            className={`sev-badge ${isHp ? 'badge-critical' : 'badge-benign'}`}
            style={{ fontSize: '1.15rem', padding: '8px 24px', letterSpacing: '0.5px' }}
          >
            {isHp ? '🚨 HONEYPOT DETECTED' : '✔ BENIGN CONTRACT'}
          </span>

          <div style={{ marginTop: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.9rem' }}>
              <span style={{ color: '#94a3b8' }}>Honeypot Probability</span>
              <span style={{ fontWeight: 700, color: isHp ? '#f87171' : '#34d399' }}>
                {(prob * 100).toFixed(1)}%
              </span>
            </div>

            {/* Custom Progress Bar */}
            <div style={{ width: '100%', height: '10px', background: '#1e293b', borderRadius: '6px', overflow: 'hidden' }}>
              <div
                style={{
                  width: `${Math.min(100, Math.max(0, prob * 100))}%`,
                  height: '100%',
                  background: isHp ? 'linear-gradient(90deg, #f97316, #ef4444)' : 'linear-gradient(90deg, #38bdf8, #10b981)',
                  transition: 'width 1s ease'
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px', fontSize: '0.82rem', color: '#94a3b8' }}>
              <span>Inference Confidence: <b>{(conf * 100).toFixed(1)}%</b></span>
              <span>Classification: <b>{isHp ? 'Malicious Trap' : 'Safe Standard'}</b></span>
            </div>
          </div>
        </div>

        {/* Feature Attribution Drivers Bar Chart */}
        {sortedContributions.length > 0 && (
          <div style={{ marginTop: '16px' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600, display: 'block', marginBottom: '10px' }}>
              Key ML Feature Weights & Factors:
            </span>
            <div className="feature-contrib-list">
              {sortedContributions.map(([feat, val]) => {
                const isRiskIncreasing = val > 0;
                const barWidth = Math.min(100, Math.max(12, Math.abs(val) * 100));
                return (
                  <div key={feat} className="feature-contrib-row">
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '3px' }}>
                      <span style={{ color: '#cbd5e1' }}>{formatFeatureName(feat)}</span>
                      <span style={{ color: isRiskIncreasing ? '#f87171' : '#34d399', fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
                        {isRiskIncreasing ? `+${val.toFixed(2)}` : val.toFixed(2)}
                      </span>
                    </div>
                    <div className="contrib-bar-track">
                      <div
                        className="contrib-bar-fill"
                        style={{
                          width: `${barWidth}%`,
                          background: isRiskIncreasing ? '#ef4444' : '#10b981'
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
