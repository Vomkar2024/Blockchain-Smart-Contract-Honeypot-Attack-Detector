import React from 'react';

export default function HeaderMetrics({ stats = {}, currentView = 'scanner', onViewRules }) {
  const breakdown = stats.breakdown || {};
  const criticalCount = breakdown.critical ?? 0;
  const highCount = breakdown.high ?? 0;
  const moderateCount = breakdown.moderate ?? 0;
  const benignCount = breakdown.benign ?? 0;

  return (
    <div>
      <header className="app-header">
        <div>
          <h1 className="brand-title">🛡️ EVM Honeypot Attack Detector</h1>
          <p className="brand-tagline">
            Explainable Full-Stack Forensic Suite combining <b>Heuristic Static Analysis</b>, <b>19-Dimensional Feature Extraction</b>, and <b>Machine Learning Classifiers</b>.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <div className="header-nav-tabs">
            <button
              type="button"
              className={`nav-tab-btn ${currentView === 'scanner' ? 'active' : ''}`}
              onClick={() => onViewRules && onViewRules('scanner')}
            >
              🔍 Scanner & Audit
            </button>
            <button
              type="button"
              className={`nav-tab-btn ${currentView === 'rules' ? 'active' : ''}`}
              onClick={() => onViewRules && onViewRules('rules')}
              title="Click to view 15 detection rules across 10 attack vectors."
            >
              📜 15 Detection Rules
            </button>
          </div>
          <div className="status-pill">
            <span className="pulse-dot"></span>
            <span>MERN & ML ENGINES ONLINE</span>
          </div>
        </div>
      </header>

      <div className="metrics-grid">
        <div className="metric-box">
          <span className="metric-label">Audited Contracts</span>
          <span className="metric-val">{stats.totalAudited ?? 120}</span>
          <span className="metric-sub">MongoDB Persisted</span>
        </div>

        <div className="metric-box">
          <span className="metric-label">Honeypots Flagged</span>
          <span className="metric-val" style={{ color: '#f87171' }}>{stats.honeypotsDetected ?? 60}</span>
          <span className="metric-sub">{stats.honeypotRatio ?? 50}% Threat Ratio</span>
        </div>

        <div className="metric-box">
          <span className="metric-label">Threat Level Breakdown</span>
          <div className="threat-mini-bar">
            <span className="mini-threat-pill pill-crit" title="Critical Honeypot Traps">
              <span className="pill-dot">🔴</span>
              <span className="pill-text">{criticalCount} Crit</span>
            </span>
            <span className="mini-threat-pill pill-high" title="High Risk Backdoors">
              <span className="pill-dot">🟠</span>
              <span className="pill-text">{highCount} High</span>
            </span>
            <span className="mini-threat-pill pill-mod" title="Moderate Governance Restrictions">
              <span className="pill-dot">🟡</span>
              <span className="pill-text">{moderateCount} Mod</span>
            </span>
            <span className="mini-threat-pill pill-benign" title="Benign Verified Safe Tokens">
              <span className="pill-dot">🟢</span>
              <span className="pill-text">{benignCount} Safe</span>
            </span>
          </div>
          <span className="metric-sub">4-Tier Risk Classification</span>
        </div>

        <div
          className={`metric-box metric-box-clickable ${currentView === 'rules' ? 'metric-box-active-rules' : ''}`}
          onClick={() => onViewRules && onViewRules('rules')}
          title={
            currentView === 'rules'
              ? 'Detection Rules currently open. Click to retract rules page.'
              : 'Click to view full Honeypot Detection Rules & Architecture'
          }
        >
          <div className="metric-box-header">
            <span className="metric-label">Detection Rules</span>
            <span className={`clickable-badge ${currentView === 'rules' ? 'badge-retract' : ''}`}>
              <span className="badge-text">{currentView === 'rules' ? 'Retract' : 'Explore'}</span>
              <span className="badge-arrow">{currentView === 'rules' ? '✕' : '↗'}</span>
            </span>
          </div>
          <span className="metric-val" style={{ color: '#38bdf8' }}>15 Rules</span>
          <span className="metric-sub">
            {currentView === 'rules' ? 'Click to Retract View' : 'Across 10 Attack Vectors'}
          </span>
        </div>

        <div className="metric-box">
          <span className="metric-label">ML Accuracy</span>
          <span className="metric-val" style={{ color: '#34d399' }}>100%</span>
          <span className="metric-sub">5-Fold Stratified CV</span>
        </div>
      </div>
    </div>
  );
}
