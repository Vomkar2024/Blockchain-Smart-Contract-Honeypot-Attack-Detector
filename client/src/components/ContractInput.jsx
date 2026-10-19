import React, { useState, useMemo } from 'react';

const DEFAULT_SAMPLE_CODE = `pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ExampleToken is ERC20, Ownable {
    uint256 public constant MAX_FEE = 5;
    uint256 public feePercent = 2;

    constructor() ERC20("Example", "EXP") Ownable() {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    function setFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Fee exceeds ceiling");
        feePercent = newFee;
    }
}`;

const BENCHMARK_ONCHAIN_SAMPLE = {
  address: '0x71c8dC0563b7c8449c25fBA0B991461FfFAe7748',
  name: 'HighRiskUnboundedTaxToken',
  symbol: 'HRUNBOUND',
  network: 'ethereum',
  threatLevel: 'HIGH',
  expectedScore: '65/100',
  category: 'Privileged Manipulation & Unbounded Tax',
  tags: ['Uncapped Fee Setter', 'Privileged Minting', 'Inline Assembly', 'Dynamic Simulation'],
  description:
    'Live on-chain benchmark contract demonstrating high-severity privileged manipulation: the owner can hike transfer taxes arbitrarily without an immutable ceiling, mint unlimited supply, and executes inline assembly in transfer routines.',
  sampleKey: 'HighUnboundedTaxToken',
};

export default function ContractInput({ onAnalyze, isLoading, samples = {}, onClearReport }) {
  const [activeTab, setActiveTab] = useState('presets');
  const [code, setCode] = useState(DEFAULT_SAMPLE_CODE);
  const [address, setAddress] = useState('');
  const [network, setNetwork] = useState('ethereum');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileName, setFileName] = useState('');
  const [simulate, setSimulate] = useState(true);
  const [selectedPreset, setSelectedPreset] = useState('');
  const [presetFilter, setPresetFilter] = useState('ALL');
  const [copiedStatus, setCopiedStatus] = useState(false);
  const [copiedAddrStatus, setCopiedAddrStatus] = useState(false);

  const handleFillSampleAddress = (sample = BENCHMARK_ONCHAIN_SAMPLE) => {
    setAddress(sample.address);
    setNetwork(sample.network || 'ethereum');
    if (onClearReport) onClearReport();
  };

  const handleAuditSampleAddress = (sample = BENCHMARK_ONCHAIN_SAMPLE) => {
    setAddress(sample.address);
    setNetwork(sample.network || 'ethereum');
    if (onClearReport) onClearReport();
    onAnalyze({
      address: sample.address,
      network: sample.network || 'ethereum',
      simulate,
    });
  };

  const handleCopySampleAddress = async (addr) => {
    if (!addr) return;
    try {
      await navigator.clipboard.writeText(addr);
      setCopiedAddrStatus(true);
      setTimeout(() => setCopiedAddrStatus(false), 2000);
    } catch (_) {}
  };

  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    if (onClearReport) {
      onClearReport();
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      setFileName(file.name);
      if (onClearReport) {
        onClearReport();
      }
      const reader = new FileReader();
      reader.onload = (evt) => {
        setCode(evt.target.result);
      };
      reader.readAsText(file);
    }
  };

  const handlePresetSelect = (presetKey, runImmediately = false) => {
    setSelectedPreset(presetKey);
    const sample = samples[presetKey];
    if (sample && sample.code) {
      setCode(sample.code);
      if (onClearReport) {
        onClearReport();
      }
      if (runImmediately) {
        onAnalyze({ code: sample.code, network, simulate });
        return;
      }
    }
    setActiveTab('editor');
  };

  const handleQuickDropdownSelect = (e) => {
    const key = e.target.value;
    if (!key) return;
    handlePresetSelect(key, false);
  };

  const handleCopyCode = async () => {
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code);
      setCopiedStatus(true);
      setTimeout(() => setCopiedStatus(false), 2000);
    } catch (_) {}
  };

  const handleClearCode = () => {
    setCode('');
    setSelectedPreset('');
    if (onClearReport) onClearReport();
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (activeTab === 'address') {
      if (!address.trim()) return alert('Please enter a contract address.');
      onAnalyze({ address: address.trim(), network, simulate });
    } else if (activeTab === 'upload' && selectedFile) {
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('network', network);
      formData.append('simulate', simulate);
      onAnalyze(formData, true);
    } else {
      if (!code.trim()) return alert('Please provide Solidity source code.');
      onAnalyze({ code, network, simulate });
    }
  };

  // Filtered presets
  const sampleList = useMemo(() => {
    return Object.values(samples);
  }, [samples]);

  const filteredSamples = useMemo(() => {
    if (presetFilter === 'ALL') return sampleList;
    return sampleList.filter(
      (s) => (s.threatLevel || '').toUpperCase() === presetFilter.toUpperCase()
    );
  }, [sampleList, presetFilter]);

  const countByLevel = useMemo(() => {
    const counts = { ALL: sampleList.length, CRITICAL: 0, HIGH: 0, MODERATE: 0, BENIGN: 0 };
    sampleList.forEach((s) => {
      const lvl = (s.threatLevel || 'BENIGN').toUpperCase();
      if (counts[lvl] !== undefined) counts[lvl]++;
    });
    return counts;
  }, [sampleList]);

  const getBadgeClass = (threatLevel) => {
    const lvl = (threatLevel || '').toUpperCase();
    if (lvl === 'CRITICAL') return 'badge-critical';
    if (lvl === 'HIGH') return 'badge-high';
    if (lvl === 'MODERATE') return 'badge-medium';
    return 'badge-benign';
  };

  return (
    <div className="glass-card">
      <div className="tabs-header">
        <button
          type="button"
          className={`tab-btn ${activeTab === 'presets' ? 'active' : ''}`}
          onClick={() => handleTabSwitch('presets')}
        >
          📚 Educational Presets ({sampleList.length || 11})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'editor' ? 'active' : ''}`}
          onClick={() => handleTabSwitch('editor')}
        >
          ✍️ Direct Code Editor
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'upload' ? 'active' : ''}`}
          onClick={() => handleTabSwitch('upload')}
        >
          📄 File Upload (.sol)
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'address' ? 'active' : ''}`}
          onClick={() => handleTabSwitch('address')}
        >
          🌐 On-Chain Address Lookup
        </button>
      </div>

      <form onSubmit={handleSubmit}>
        {/* Network & Simulation Control Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '18px' }}>
          <div>
            <label className="form-label">Target Blockchain Network</label>
            <select
              className="select-input"
              value={network}
              onChange={(e) => setNetwork(e.target.value)}
            >
              <option value="ethereum">Ethereum Mainnet (Chain ID 1)</option>
              <option value="bsc">BNB Smart Chain (Chain ID 56)</option>
              <option value="polygon">Polygon Mainnet (Chain ID 137)</option>
              <option value="arbitrum">Arbitrum One (Chain ID 42161)</option>
              <option value="sepolia">Sepolia Testnet (Chain ID 11155111)</option>
            </select>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', marginTop: '24px' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '0.92rem', color: '#cbd5e1' }}>
              <input
                type="checkbox"
                checked={simulate}
                onChange={(e) => setSimulate(e.target.checked)}
                style={{ width: '18px', height: '18px', accentColor: '#4f46e5' }}
              />
              <span>Enable Dynamic Simulation Adapter (Buy / Sell DEX Revert Test)</span>
            </label>
          </div>
        </div>

        {/* Tab 1: Educational Presets Hub */}
        {activeTab === 'presets' && (
          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
              <p style={{ color: '#94a3b8', fontSize: '0.9rem', margin: 0 }}>
                Select a benchmark contract across all 4 threat tiers to evaluate static detection heuristics and ML classifier behavior:
              </p>
              {/* Category Filter Pills */}
              <div className="filter-pill-group">
                {[
                  { id: 'ALL', label: `All (${countByLevel.ALL})` },
                  { id: 'CRITICAL', label: `🔴 Critical (${countByLevel.CRITICAL})` },
                  { id: 'HIGH', label: `🟠 High (${countByLevel.HIGH})` },
                  { id: 'MODERATE', label: `🟡 Moderate (${countByLevel.MODERATE})` },
                  { id: 'BENIGN', label: `🟢 Benign (${countByLevel.BENIGN})` },
                ].map((tier) => (
                  <button
                    key={tier.id}
                    type="button"
                    className={`filter-pill ${presetFilter === tier.id ? 'active' : ''}`}
                    onClick={() => setPresetFilter(tier.id)}
                  >
                    {tier.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="preset-grid">
              {filteredSamples.map((sample) => {
                const isSelected = selectedPreset === sample.key;
                const badgeClass = getBadgeClass(sample.threatLevel);
                return (
                  <div
                    key={sample.key}
                    className={`preset-card ${isSelected ? 'active' : ''}`}
                    onClick={() => handlePresetSelect(sample.key, false)}
                  >
                    <div className="preset-card-header">
                      <span className="preset-card-title">{sample.name || sample.key}</span>
                      <span className={`sev-badge ${badgeClass}`}>
                        {sample.threatLevel} ({sample.expectedScore || 'Score'})
                      </span>
                    </div>

                    <div className="preset-category">
                      📂 {sample.category || 'Forensic Archetype'}
                    </div>

                    <p className="preset-desc">
                      {sample.description}
                    </p>

                    {sample.tags && sample.tags.length > 0 && (
                      <div className="preset-tags">
                        {sample.tags.map((t, idx) => (
                          <span key={idx} className="tag-pill">{t}</span>
                        ))}
                      </div>
                    )}

                    {sample.address && (
                      <div
                        style={{
                          margin: '8px 0',
                          padding: '6px 10px',
                          background: 'rgba(249, 115, 22, 0.1)',
                          border: '1px solid rgba(249, 115, 22, 0.25)',
                          borderRadius: '8px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          flexWrap: 'wrap',
                        }}
                      >
                        <span style={{ fontSize: '0.76rem', color: '#fb923c', fontFamily: 'JetBrains Mono, monospace' }}>
                          🌐 Deployed: <b>{sample.address.slice(0, 10)}...{sample.address.slice(-6)}</b>
                        </span>
                        <button
                          type="button"
                          style={{
                            background: 'transparent',
                            border: 'none',
                            color: '#38bdf8',
                            fontSize: '0.76rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            textDecoration: 'underline',
                          }}
                          onClick={(e) => {
                            e.stopPropagation();
                            handleFillSampleAddress({ address: sample.address, network: sample.network || 'ethereum' });
                            setActiveTab('address');
                          }}
                        >
                          Lookup Address ➔
                        </button>
                      </div>
                    )}

                    <div className="preset-actions">
                      <button
                        type="button"
                        className="btn-preset-action btn-inspect"
                        onClick={(e) => {
                          e.stopPropagation();
                          handlePresetSelect(sample.key, false);
                        }}
                      >
                        ✍️ Edit Code
                      </button>
                      <button
                        type="button"
                        className="btn-preset-action btn-audit-now"
                        onClick={(e) => {
                          e.stopPropagation();
                          handlePresetSelect(sample.key, true);
                        }}
                      >
                        ⚡ Run Audit
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Tab 2: Direct Code Editor */}
        {activeTab === 'editor' && (
          <div className="form-group">
            <div className="editor-toolbar">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label className="form-label" style={{ margin: 0 }}>Solidity Source Code</label>
                <span className="line-count-badge">
                  {code.split('\n').length} lines
                </span>
                {selectedPreset && (
                  <span className="loaded-preset-tag">
                    Loaded: <b>{selectedPreset}</b>
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {/* Quick Sample Selector Dropdown */}
                <select
                  className="quick-sample-select"
                  value={selectedPreset}
                  onChange={handleQuickDropdownSelect}
                >
                  <option value="">-- Quick Load Sample --</option>
                  <optgroup label="🔴 Critical Threat (Scam Traps)">
                    <option value="HoneypotToken">Classic Honeypot Token (100/100)</option>
                    <option value="CriticalDexTrapToken">DEX Liquidity Siphon Trap (100/100)</option>
                    <option value="CriticalDelegatecallToken">Shadow Delegatecall Backdoor (100/100)</option>
                  </optgroup>
                  <optgroup label="🟠 High Threat (Privileged Manipulation)">
                    <option value="HighUnboundedTaxToken">Unbounded Tax & Mint Token (65/100)</option>
                    <option value="HighHiddenBlacklistToken">Blacklist Guard & Inflation Token (50/100)</option>
                  </optgroup>
                  <optgroup label="🟡 Moderate Threat (Enterprise / Governance)">
                    <option value="RestrictedGovernanceToken">Restricted Governance Token (30/100)</option>
                    <option value="ModeratePausableToken">Enterprise Pausable Token (30/100)</option>
                    <option value="ModerateCooldownToken">Anti-Bot Cooldown Token (30/100)</option>
                  </optgroup>
                  <optgroup label="🟢 Benign Standard (Audited Reference)">
                    <option value="SafeToken">Safe Reference Token (0/100)</option>
                    <option value="BenignDeFiToken">DeFi Zero-Fee Fixed Token (0/100)</option>
                    <option value="BenignCharityToken">Capped Charity Token (0/100)</option>
                  </optgroup>
                </select>

                <button
                  type="button"
                  className="btn-toolbar"
                  onClick={handleCopyCode}
                  title="Copy contract source code to clipboard"
                >
                  {copiedStatus ? '✔ Copied' : '📋 Copy'}
                </button>
                <button
                  type="button"
                  className="btn-toolbar"
                  onClick={handleClearCode}
                  title="Clear source code editor"
                >
                  🧹 Clear
                </button>
              </div>
            </div>

            <textarea
              className="code-textarea"
              value={code}
              onChange={(e) => {
                setCode(e.target.value);
                setSelectedPreset('');
              }}
              placeholder="Paste Solidity smart contract code here..."
              spellCheck="false"
            />
          </div>
        )}

        {/* Tab 3: File Upload */}
        {activeTab === 'upload' && (
          <div className="form-group">
            <label className="form-label">Upload Smart Contract Source (.sol, .json, .txt)</label>
            <input
              type="file"
              accept=".sol,.json,.txt"
              onChange={handleFileUpload}
              className="text-input"
              style={{ cursor: 'pointer' }}
            />
            {fileName && (
              <p style={{ marginTop: '8px', color: '#38bdf8', fontSize: '0.88rem' }}>
                Selected file: <b>{fileName}</b> ({code.split('\n').length} lines loaded into editor)
              </p>
            )}
          </div>
        )}

        {/* Tab 4: On-Chain Address Lookup */}
        {activeTab === 'address' && (
          <div className="form-group">
            {/* Featured Benchmark Address Sample Card (High Level Threat) */}
            <div
              className="benchmark-sample-card"
              style={{
                background: 'linear-gradient(135deg, rgba(249, 115, 22, 0.08) 0%, rgba(15, 23, 42, 0.9) 100%)',
                border: '1px solid rgba(249, 115, 22, 0.35)',
                borderRadius: '14px',
                padding: '20px 22px',
                marginBottom: '22px',
                boxShadow: '0 8px 24px rgba(249, 115, 22, 0.08)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '1.4rem' }}>⚡</span>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 700, fontSize: '1.05rem', color: '#f8fafc' }}>
                        {BENCHMARK_ONCHAIN_SAMPLE.name}
                      </span>
                      <span style={{ fontSize: '0.8rem', color: '#94a3b8', background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: '4px' }}>
                        ${BENCHMARK_ONCHAIN_SAMPLE.symbol}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.82rem', color: '#38bdf8' }}>
                      📂 {BENCHMARK_ONCHAIN_SAMPLE.category}
                    </span>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="sev-badge badge-high" style={{ padding: '6px 14px' }}>
                    🟠 HIGH THREAT ({BENCHMARK_ONCHAIN_SAMPLE.expectedScore} · High Tier)
                  </span>
                </div>
              </div>

              <p style={{ color: '#cbd5e1', fontSize: '0.88rem', lineHeight: 1.5, margin: '8px 0 14px 0' }}>
                {BENCHMARK_ONCHAIN_SAMPLE.description}
              </p>

              {/* Security Tags */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '16px' }}>
                {BENCHMARK_ONCHAIN_SAMPLE.tags.map((tag, idx) => (
                  <span
                    key={idx}
                    style={{
                      background: 'rgba(249, 115, 22, 0.12)',
                      border: '1px solid rgba(249, 115, 22, 0.3)',
                      color: '#fb923c',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      padding: '3px 10px',
                      borderRadius: '6px',
                    }}
                  >
                    🏷️ {tag}
                  </span>
                ))}
              </div>

              {/* Address details bar & Quick Action Buttons */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px',
                  background: 'rgba(10, 15, 30, 0.8)',
                  padding: '12px 16px',
                  borderRadius: '10px',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 600 }}>Address:</span>
                  <code style={{ color: '#38bdf8', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.86rem', wordBreak: 'break-all' }}>
                    {BENCHMARK_ONCHAIN_SAMPLE.address}
                  </code>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    onClick={() => handleCopySampleAddress(BENCHMARK_ONCHAIN_SAMPLE.address)}
                    style={{
                      background: 'rgba(56, 189, 248, 0.12)',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      color: '#38bdf8',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                    title="Copy sample address to clipboard"
                  >
                    {copiedAddrStatus ? '✔ Copied' : '📋 Copy Address'}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleFillSampleAddress(BENCHMARK_ONCHAIN_SAMPLE)}
                    style={{
                      background: 'rgba(99, 102, 241, 0.15)',
                      border: '1px solid rgba(99, 102, 241, 0.4)',
                      color: '#a5b4fc',
                      padding: '6px 14px',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                    title="Fill address into input field"
                  >
                    ✏️ Fill Address
                  </button>
                  <button
                    type="button"
                    onClick={() => handleAuditSampleAddress(BENCHMARK_ONCHAIN_SAMPLE)}
                    style={{
                      background: 'linear-gradient(135deg, #f97316 0%, #ea580c 100%)',
                      border: 'none',
                      color: '#ffffff',
                      padding: '6px 16px',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                      boxShadow: '0 2px 10px rgba(249, 115, 22, 0.3)',
                    }}
                    title="Run on-chain audit immediately"
                  >
                    ⚡ Audit Sample Now
                  </button>
                </div>
              </div>
            </div>

            <label className="form-label">Contract Address (0x...)</label>
            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                className="text-input"
                placeholder="0x71c8dC0563b7c8449c25fBA0B991461FfFAe7748"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
              />
              {address && (
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => {
                    setAddress('');
                    if (onClearReport) onClearReport();
                  }}
                  title="Clear contract address input"
                >
                  Clear
                </button>
              )}
            </div>
            <p style={{ marginTop: '8px', fontSize: '0.82rem', color: '#94a3b8' }}>
              The forensic engine will fetch verified explorer source code or fetch deployed runtime bytecode from the selected network RPC, inspect 15 AST honeypot rules, and execute dynamic DEX buy/sell simulation.
            </p>
          </div>
        )}

        <div style={{ marginTop: '20px' }}>
          <button type="submit" className="btn-primary" disabled={isLoading}>
            {isLoading ? '⏳ Executing Forensic Pipeline...' : '🚀 Execute Forensic Audit'}
          </button>
        </div>
      </form>
    </div>
  );
}
