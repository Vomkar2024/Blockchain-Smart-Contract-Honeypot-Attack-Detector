import React from 'react';

export default function PositiveIndicators({ indicators = [] }) {
  return (
    <div className="glass-card">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc', marginBottom: '14px' }}>
        🛡️ Positive Security Indicators ({indicators.length})
      </h2>

      {indicators.length === 0 ? (
        <p style={{ color: '#94a3b8', fontSize: '0.9rem', fontStyle: 'italic' }}>
          No standard positive security patterns (such as OpenZeppelin inheritance or ownership renunciation) were identified in this contract.
        </p>
      ) : (
        <div>
          {indicators.map((ind, idx) => (
            <div key={`${ind.indicator_id}-${idx}`} className="indicator-card">
              <div className="indicator-title">
                ✔ {ind.name} <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontFamily: 'JetBrains Mono' }}>({ind.indicator_id})</span>
              </div>
              <div className="indicator-desc">
                {ind.explanation || ind.evidence || 'Standard security pattern reducing malicious honeypot likelihood.'}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
