import React, { useState, useEffect } from 'react';
import HeaderMetrics from './components/HeaderMetrics';
import ContractInput from './components/ContractInput';
import ThreatVerdictBanner from './components/ThreatVerdictBanner';
import RiskGauge from './components/RiskGauge';
import FindingsTable from './components/FindingsTable';
import CodeInspector from './components/CodeInspector';
import PositiveIndicators from './components/PositiveIndicators';
import LimitationAdvisories from './components/LimitationAdvisories';
import AuditHistory from './components/AuditHistory';
import DetectionRulesPage from './components/DetectionRulesPage';
import SimulationResultCard from './components/SimulationResultCard';
import './App.css';

export default function App() {
  const [currentView, setCurrentView] = useState(() => {
    return window.location.hash === '#rules' ? 'rules' : 'scanner';
  });
  const [stats, setStats] = useState({});
  const [samples, setSamples] = useState({});
  const [history, setHistory] = useState([]);
  const [currentReport, setCurrentReport] = useState(null);
  const [targetLine, setTargetLine] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [isBackendOnline, setIsBackendOnline] = useState(true);

  // Safe fetch helper with defensive JSON parsing and server-offline diagnostics
  const safeFetchJson = async (url, options = {}) => {
    let res;
    try {
      res = await fetch(url, options);
    } catch (networkErr) {
      setIsBackendOnline(false);
      throw new Error(
        'Backend server is unreachable. Please verify the Express server is running on http://127.0.0.1:5000 (run `npm run dev` or `npm run server`).'
      );
    }

    let parsedData = null;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        parsedData = await res.json();
      } catch (_) {}
    } else {
      try {
        const text = await res.text();
        if (text && (text.trim().startsWith('{') || text.trim().startsWith('['))) {
          parsedData = JSON.parse(text);
        }
      } catch (_) {}
    }

    if (!res.ok) {
      if (res.status === 504 || res.status === 502 || res.status === 503) {
        setIsBackendOnline(false);
        throw new Error(
          `Vite Proxy Error (HTTP ${res.status}): Backend server at http://127.0.0.1:5000 is not responding. Please start the Express server.`
        );
      }
      const errMessage =
        (parsedData && (parsedData.error || parsedData.message)) ||
        `Request failed with HTTP status ${res.status}.`;
      throw new Error(errMessage);
    }

    setIsBackendOnline(true);
    return parsedData;
  };

  // Initial data loading from Express / MongoDB backend
  useEffect(() => {
    fetchStats();
    fetchSamples();
    fetchHistory();

    const handleHashChange = () => {
      if (window.location.hash === '#rules') {
        setCurrentView('rules');
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else {
        setCurrentView('scanner');
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    window.addEventListener('popstate', handleHashChange);
    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      window.removeEventListener('popstate', handleHashChange);
    };
  }, []);

  // Automatic recovery: poll backend every 3 seconds if initially offline until connection is established
  useEffect(() => {
    if (isBackendOnline) return;

    const retryTimer = setInterval(() => {
      fetchStats();
      fetchSamples();
      fetchHistory();
    }, 3000);

    return () => clearInterval(retryTimer);
  }, [isBackendOnline]);

  const navigateView = (view) => {
    if (view === 'rules') {
      if (currentView === 'rules') {
        setCurrentView('scanner');
        if (window.location.hash === '#rules') {
          window.history.pushState(null, '', window.location.pathname);
        }
        return;
      }
      setCurrentView('rules');
      window.location.hash = '#rules';
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      setCurrentView('scanner');
      if (window.location.hash === '#rules') {
        window.history.pushState(null, '', window.location.pathname);
      }
    }
  };

  const fetchStats = async () => {
    try {
      const data = await safeFetchJson('/api/stats');
      if (data) setStats(data);
    } catch (err) {
      console.warn('Could not fetch stats:', err.message);
    }
  };

  const fetchSamples = async () => {
    try {
      const data = await safeFetchJson('/api/samples');
      if (data) setSamples(data);
    } catch (err) {
      console.warn('Could not fetch samples:', err.message);
    }
  };

  const fetchHistory = async () => {
    try {
      const data = await safeFetchJson('/api/history');
      if (data) setHistory(data);
    } catch (err) {
      console.warn('Could not fetch history:', err.message);
    }
  };

  const handleAnalyze = async (payload, isFormData = false) => {
    setIsLoading(true);
    setErrorMessage('');
    setTargetLine(null);
    try {
      const options = {
        method: 'POST',
      };
      if (isFormData) {
        options.body = payload;
      } else {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(payload);
      }

      const data = await safeFetchJson('/api/analyze', options);

      if (!data || data.error) {
        throw new Error(data?.error || 'Failed to analyze smart contract.');
      }

      setCurrentReport(data.report);
      fetchStats();
      fetchHistory();

      // Smooth scroll to results
      setTimeout(() => {
        window.scrollTo({ top: 480, behavior: 'smooth' });
      }, 100);
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearReport = () => {
    setCurrentReport(null);
    setErrorMessage('');
    setTargetLine(null);
  };

  const handleSelectAudit = async (id) => {
    try {
      const data = await safeFetchJson(`/api/history/${id}`);
      if (data && data.rawReport) {
        setCurrentReport(data.rawReport);
        setTargetLine(null);
        window.scrollTo({ top: 500, behavior: 'smooth' });
      }
    } catch (err) {
      console.error('Error fetching audit details:', err);
    }
  };

  const handleDeleteAudit = async (id) => {
    try {
      await safeFetchJson(`/api/history/${id}`, { method: 'DELETE' });
      fetchHistory();
      fetchStats();
    } catch (err) {
      console.error('Error deleting audit record:', err);
    }
  };

  const handleSelectLineInInspector = (lineNum) => {
    setTargetLine(lineNum);
  };

  const downloadJSON = () => {
    if (!currentReport) return;
    const name = currentReport.contract?.name || 'contract';
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}_audit_report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadCSV = () => {
    if (!currentReport) return;
    const name = currentReport.contract?.name || 'contract';
    const risk = currentReport.risk_assessment || currentReport.risk_report || {};
    const findings = currentReport.static_analysis?.findings || [];

    const headers = [
      'Contract Name', 'Address', 'Network', 'Risk Score', 'Risk Level',
      'Rule ID', 'Rule Name', 'Severity', 'Confidence', 'Line Number', 'Evidence', 'Explanation'
    ];

    const rows = [];
    if (findings.length === 0) {
      rows.push([
        name,
        currentReport.contract?.address || 'N/A',
        currentReport.contract?.network || 'ethereum',
        risk.risk_score ?? 0,
        risk.risk_level ?? 'LOW',
        'NONE', 'No Suspicious Patterns Detected', 'INFORMATIONAL', 'HIGH', '', 'Clean Source Code', 'No honeypot rules triggered.'
      ]);
    } else {
      findings.forEach(f => {
        rows.push([
          name,
          currentReport.contract?.address || 'N/A',
          currentReport.contract?.network || 'ethereum',
          risk.risk_score ?? 0,
          risk.risk_level ?? 'LOW',
          f.rule_id,
          `"${(f.rule_name || '').replace(/"/g, '""')}"`,
          f.severity,
          f.confidence,
          f.line_number ?? '',
          `"${(f.evidence || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`,
          `"${(f.explanation || '').replace(/"/g, '""')}"`
        ]);
      });
    }

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}_findings.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrintReport = () => {
    window.print();
  };

  return (
    <div className="container">
      {/* 1. Header & Live System Metrics */}
      <HeaderMetrics
        stats={stats}
        currentView={currentView}
        onViewRules={navigateView}
      />

      {currentView === 'rules' ? (
        <DetectionRulesPage onBack={() => navigateView('scanner')} />
      ) : (
        <>
          {/* 2. Contract Ingestion Section */}
          <ContractInput
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
            samples={samples}
            onClearReport={handleClearReport}
          />

          {/* Backend Connection Alert Banner */}
          {!isBackendOnline && (
            <div
              className="glass-card"
              style={{
                borderColor: '#f59e0b',
                background: 'rgba(245, 158, 11, 0.12)',
                marginTop: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
                padding: '14px 18px'
              }}
            >
              <div>
                <b style={{ color: '#fbbf24' }}>⚠ Express Backend Server Offline:</b>{' '}
                <span style={{ color: '#e2e8f0' }}>
                  Cannot reach API at <code style={{ color: '#6ee7b7' }}>http://127.0.0.1:5000</code>.
                </span>
                <div style={{ fontSize: '13px', color: '#cbd5e1', marginTop: '4px' }}>
                  Run <code style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px', color: '#38bdf8' }}>npm run dev</code> from the root folder (or <code style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px', color: '#38bdf8' }}>npm run server</code>) to start the Express API and analysis engine.
                </div>
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: '6px 14px', fontSize: '13px', cursor: 'pointer' }}
                onClick={() => {
                  fetchStats();
                  fetchSamples();
                  fetchHistory();
                }}
              >
                🔄 Retry Connection
              </button>
            </div>
          )}

          {/* Error Banner */}
          {errorMessage && (
            <div className="glass-card" style={{ borderColor: '#ef4444', background: 'rgba(239, 68, 68, 0.12)', marginTop: '20px' }}>
              <b style={{ color: '#f87171' }}>✘ Forensic Audit Pipeline Error:</b> {errorMessage}
            </div>
          )}

          {/* 3. Analysis Results Section */}
          {currentReport && (
            <div className="report-fade-in" style={{ marginTop: '24px' }}>
              {/* Threat Verdict Banner */}
              <ThreatVerdictBanner
                report={currentReport}
                onDismiss={handleClearReport}
              />

              {/* Visual Risk Gauge & ML Prediction */}
              <RiskGauge
                risk={currentReport.risk_assessment || currentReport.risk_report}
                ml={currentReport.machine_learning || currentReport.ml_prediction}
              />

              {/* Dynamic Transaction Simulation Adapter (Buy / Sell DEX Revert Test) */}
              <SimulationResultCard
                simulation={currentReport.simulation}
                contract={currentReport.contract}
              />

              {/* Findings Table with Line Highlighter triggers */}
              <FindingsTable
                findings={currentReport.static_analysis?.findings || []}
                onSelectLine={handleSelectLineInInspector}
              />

              {/* Source Code Forensic Inspector */}
              <CodeInspector
                sourceCode={currentReport.contract?.source_code}
                findings={currentReport.static_analysis?.findings || []}
                targetLine={targetLine}
              />

              {/* Positive Indicators & Limitation Advisories */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '20px', marginTop: '20px' }}>
                <PositiveIndicators
                  indicators={currentReport.static_analysis?.positive_indicators || []}
                />
                <LimitationAdvisories />
              </div>

              {/* Download & Export Forensic Artifacts Bar */}
              <div className="glass-card" style={{ marginTop: '20px' }}>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#f8fafc', marginBottom: '12px' }}>
                  💾 Export & Forensic Incident Artifacts
                </h3>
                <p style={{ color: '#94a3b8', fontSize: '0.88rem' }}>
                  Export immutable audit documentation for compliance documentation, incident response, or developer remediation:
                </p>
                <div className="export-bar">
                  <button type="button" className="btn-export" onClick={downloadJSON}>
                    📥 Download JSON Audit Report
                  </button>
                  <button type="button" className="btn-export" onClick={downloadCSV}>
                    📥 Download CSV Findings Summary
                  </button>
                  <button type="button" className="btn-export btn-print" onClick={handlePrintReport}>
                    🖨️ Print / Save PDF Report
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* 4. MongoDB Persistent Audit History */}
          <AuditHistory
            history={history}
            onSelectAudit={handleSelectAudit}
            onDeleteAudit={handleDeleteAudit}
          />
        </>
      )}
    </div>
  );
}
