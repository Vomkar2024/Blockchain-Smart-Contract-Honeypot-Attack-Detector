import React, { useState, useMemo } from 'react';

export default function FindingsTable({ findings = [], onSelectLine }) {
  const [filter, setFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedIndex, setCopiedIndex] = useState(null);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const sev = (f.severity || '').toUpperCase();
      if (filter !== 'ALL' && sev !== filter) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      const matchName = (f.rule_name || '').toLowerCase().includes(q);
      const matchId = (f.rule_id || '').toLowerCase().includes(q);
      const matchCat = (f.category || '').toLowerCase().includes(q);
      const matchExpl = (f.explanation || '').toLowerCase().includes(q);
      const matchEvid = (f.evidence || '').toLowerCase().includes(q);
      return matchName || matchId || matchCat || matchExpl || matchEvid;
    });
  }, [findings, filter, searchQuery]);

  const getBadgeClass = (severity) => {
    const sev = (severity || '').toUpperCase();
    if (sev === 'CRITICAL') return 'badge-critical';
    if (sev === 'HIGH') return 'badge-high';
    if (sev === 'MEDIUM') return 'badge-medium';
    return 'badge-low';
  };

  const handleCopyEvidence = async (text, idx) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(idx);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (_) {}
  };

  return (
    <div className="glass-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
          ⚠️ Static Forensic Findings ({findings.length})
        </h2>

        {/* Filter & Search Bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <input
            type="text"
            className="search-input"
            placeholder="🔍 Filter findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />

          <div style={{ display: 'flex', gap: '4px' }}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                type="button"
                className="btn-secondary"
                style={{
                  fontSize: '0.78rem',
                  padding: '4px 8px',
                  background: filter === lvl ? 'rgba(99, 102, 241, 0.35)' : undefined,
                  borderColor: filter === lvl ? '#818cf8' : undefined
                }}
                onClick={() => setFilter(lvl)}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>
      </div>

      {filteredFindings.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '36px 0', color: '#34d399' }}>
          <h3>✔ No Suspicious Patterns Detected</h3>
          <p style={{ color: '#94a3b8', fontSize: '0.88rem', marginTop: '6px' }}>
            No static heuristic detection rules triggered for the selected query or severity filter.
          </p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{ width: '100px' }}>Severity</th>
                <th style={{ width: '220px' }}>Rule & Category</th>
                <th style={{ width: '65px', textAlign: 'center' }}>Line</th>
                <th>Evidence Snippet & Code</th>
                <th>Forensic Explanation & Verification</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((item, idx) => (
                <tr key={`${item.rule_id}-${idx}`}>
                  <td>
                    <span className={`sev-badge ${getBadgeClass(item.severity)}`}>
                      {item.severity}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{item.rule_name}</div>
                    <div style={{ fontSize: '0.76rem', color: '#38bdf8', marginTop: '2px' }}>
                      {item.category || 'General'}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'JetBrains Mono', marginTop: '1px' }}>
                      {item.rule_id}
                    </div>
                  </td>
                  <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono' }}>
                    {item.line_number ? (
                      <button
                        type="button"
                        className="line-num-btn"
                        onClick={() => onSelectLine && onSelectLine(item.line_number)}
                        title="Click to view line in code inspector"
                      >
                        L{item.line_number}
                      </button>
                    ) : (
                      <span style={{ color: '#64748b' }}>—</span>
                    )}
                  </td>
                  <td>
                    {item.evidence ? (
                      <div>
                        <div className="code-evidence">
                          {item.evidence}
                        </div>
                        <button
                          type="button"
                          className="btn-copy-evidence"
                          onClick={() => handleCopyEvidence(item.evidence, idx)}
                        >
                          {copiedIndex === idx ? '✔ Copied' : '📋 Copy Evidence'}
                        </button>
                      </div>
                    ) : (
                      <span style={{ color: '#64748b', fontStyle: 'italic' }}>Syntactic / structural indicator</span>
                    )}
                  </td>
                  <td>
                    <div style={{ color: '#cbd5e1', fontSize: '0.88rem', lineHeight: '1.4' }}>
                      {item.explanation}
                    </div>
                    {item.suggested_verification && (
                      <div style={{ marginTop: '6px', fontSize: '0.82rem', color: '#94a3b8', fontStyle: 'italic' }}>
                        👉 <b>Verification:</b> {item.suggested_verification}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
