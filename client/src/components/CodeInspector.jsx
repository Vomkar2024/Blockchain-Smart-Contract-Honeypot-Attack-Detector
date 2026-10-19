import React, { useState, useEffect, useRef } from 'react';

export default function CodeInspector({ sourceCode = '', findings = [], targetLine = null }) {
  const [isOpen, setIsOpen] = useState(false);
  const lineRefs = useRef({});

  // Map findings by line number
  const findingsByLine = {};
  findings.forEach((f) => {
    if (f.line_number) {
      if (!findingsByLine[f.line_number]) findingsByLine[f.line_number] = [];
      findingsByLine[f.line_number].push(f);
    }
  });

  // Auto-scroll when targetLine changes
  useEffect(() => {
    if (targetLine && lineRefs.current[targetLine]) {
      setIsOpen(true);
      setTimeout(() => {
        lineRefs.current[targetLine]?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 100);
    }
  }, [targetLine]);

  if (!sourceCode) return null;

  const lines = sourceCode.split('\n');

  return (
    <div className="glass-card" style={{ marginTop: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
            🔍 Source Code Forensic Inspector
          </h3>
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            {lines.length} lines | {findings.filter((f) => f.line_number).length} lines with flagged patterns
          </span>
        </div>

        <button
          type="button"
          className="btn-secondary"
          onClick={() => setIsOpen(!isOpen)}
          style={{ fontSize: '0.82rem', padding: '6px 14px' }}
        >
          {isOpen ? '▲ Collapse Code' : '▼ Expand Code Viewer'}
        </button>
      </div>

      {isOpen && (
        <div className="code-inspector-container">
          <div className="code-inspector-scroll">
            {lines.map((lineText, idx) => {
              const lineNum = idx + 1;
              const lineFindings = findingsByLine[lineNum] || [];
              const hasCritical = lineFindings.some((f) => (f.severity || '').toUpperCase() === 'CRITICAL');
              const hasHigh = lineFindings.some((f) => (f.severity || '').toUpperCase() === 'HIGH');
              const hasMedium = lineFindings.some((f) => (f.severity || '').toUpperCase() === 'MEDIUM');

              let rowClass = 'code-line-row';
              if (hasCritical) rowClass += ' line-critical';
              else if (hasHigh) rowClass += ' line-high';
              else if (hasMedium) rowClass += ' line-medium';

              const isTargeted = targetLine === lineNum;
              if (isTargeted) rowClass += ' line-targeted';

              return (
                <div
                  key={lineNum}
                  ref={(el) => (lineRefs.current[lineNum] = el)}
                  className={rowClass}
                >
                  <span className="code-line-number">{lineNum}</span>
                  <span className="code-line-content">{lineText || ' '}</span>

                  {lineFindings.length > 0 && (
                    <div className="line-finding-badge">
                      {lineFindings.map((f, fIdx) => (
                        <span
                          key={fIdx}
                          className={`sev-badge ${hasCritical ? 'badge-critical' : hasHigh ? 'badge-high' : 'badge-medium'}`}
                          style={{ fontSize: '0.68rem', padding: '1px 6px' }}
                          title={f.explanation}
                        >
                          {f.rule_id}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
