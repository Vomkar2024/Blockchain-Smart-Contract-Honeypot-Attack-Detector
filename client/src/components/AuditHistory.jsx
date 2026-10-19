import React from 'react';

export default function AuditHistory({ history = [], onSelectAudit, onDeleteAudit }) {
  if (history.length === 0) return null;

  return (
    <div className="glass-card">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc', marginBottom: '14px' }}>
        📜 MongoDB Audit History ({history.length})
      </h2>

      <div style={{ overflowX: 'auto' }}>
        <table className="findings-table">
          <thead>
            <tr>
              <th>Contract Name</th>
              <th>Network</th>
              <th>Risk Score</th>
              <th>Risk Level</th>
              <th>ML Result</th>
              <th>Date & Time</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {history.map((item) => {
              const level = (item.riskLevel || 'LOW').toUpperCase();
              let badgeClass = 'badge-benign';
              if (level === 'CRITICAL') badgeClass = 'badge-critical';
              else if (level === 'HIGH') badgeClass = 'badge-high';
              else if (level === 'MODERATE') badgeClass = 'badge-medium';

              return (
                <tr key={item._id}>
                  <td style={{ fontWeight: 600, color: '#f1f5f9' }}>
                    {item.contractName}
                    {item.contractAddress && (
                      <div style={{ fontSize: '0.76rem', color: '#94a3b8', fontFamily: 'JetBrains Mono' }}>
                        {item.contractAddress.slice(0, 10)}...{item.contractAddress.slice(-6)}
                      </div>
                    )}
                  </td>
                  <td style={{ textTransform: 'capitalize', color: '#cbd5e1' }}>
                    {item.network || 'ethereum'}
                  </td>
                  <td style={{ fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
                    {item.riskScore} / 100
                  </td>
                  <td>
                    <span className={`sev-badge ${badgeClass}`}>{level}</span>
                  </td>
                  <td>
                    <span className={`sev-badge ${item.isHoneypot ? 'badge-critical' : 'badge-benign'}`}>
                      {item.isHoneypot ? 'HONEYPOT' : 'BENIGN'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
                    {new Date(item.createdAt).toLocaleString()}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      style={{ marginRight: '8px', padding: '4px 10px', fontSize: '0.78rem' }}
                      onClick={() => onSelectAudit(item._id)}
                    >
                      View
                    </button>
                    <button
                      type="button"
                      className="btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.78rem', color: '#f87171' }}
                      onClick={() => onDeleteAudit(item._id)}
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
