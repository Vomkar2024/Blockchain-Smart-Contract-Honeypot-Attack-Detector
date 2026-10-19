import React from 'react';

export default function SimulationResultCard({ simulation, contract }) {
  if (!simulation) return null;

  const {
    provider = 'Auto Cascade',
    is_available = false,
    is_honeypot = null,
    buy_tax_percent = null,
    sell_tax_percent = null,
    buy_gas = null,
    sell_gas = null,
    honeypot_reason = null,
    error_message = null,
  } = simulation;

  const isContractAddress = Boolean(contract?.address);

  // Status badge styling
  let statusBadge = {
    label: 'SIMULATION COMPLETED',
    class: 'badge-benign',
    icon: '✔',
    bg: 'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.3)',
    color: '#34d399',
  };

  if (!is_available) {
    statusBadge = {
      label: isContractAddress ? 'SERVICE NOTICE' : 'DEPLOYMENT NOTICE',
      class: 'badge-medium',
      icon: 'ℹ️',
      bg: 'rgba(56, 189, 248, 0.1)',
      border: 'rgba(56, 189, 248, 0.25)',
      color: '#38bdf8',
    };
  } else if (is_honeypot) {
    statusBadge = {
      label: 'HONEYPOT REVERT DETECTED',
      class: 'badge-critical',
      icon: '🚨',
      bg: 'rgba(239, 68, 68, 0.15)',
      border: 'rgba(239, 68, 68, 0.4)',
      color: '#f87171',
    };
  }

  return (
    <div
      className="glass-card"
      style={{
        marginTop: '20px',
        border: `1px solid ${is_honeypot ? 'rgba(239, 68, 68, 0.4)' : 'var(--border-glow)'}`,
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          marginBottom: '14px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '1.4rem' }}>🔄</span>
          <div>
            <h2 style={{ fontSize: '1.22rem', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
              Dynamic Simulation Adapter (Buy / Sell DEX Revert Test)
            </h2>
            <p style={{ color: '#94a3b8', fontSize: '0.84rem', margin: '2px 0 0 0' }}>
              Simulated sandbox buy, approval, and sell sequence to test liquidity lock and transfer revert traps.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '0.78rem',
              fontWeight: 600,
              background: 'rgba(99, 102, 241, 0.12)',
              color: '#818cf8',
              border: '1px solid rgba(99, 102, 241, 0.3)',
            }}
          >
            Provider: {provider}
          </span>
          <span
            style={{
              padding: '4px 12px',
              borderRadius: '6px',
              fontSize: '0.82rem',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              background: statusBadge.bg,
              color: statusBadge.color,
              border: `1px solid ${statusBadge.border}`,
            }}
          >
            {statusBadge.icon} {statusBadge.label}
          </span>
        </div>
      </div>

      {/* 3-Step Sandbox Lifecycle Sequence Visualizer */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '12px',
          margin: '18px 0',
          padding: '14px',
          background: 'rgba(15, 23, 42, 0.65)',
          borderRadius: '12px',
          border: '1px solid rgba(255, 255, 255, 0.05)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
          <span style={{ fontSize: '1.3rem' }}>1️⃣</span>
          <div>
            <b style={{ color: '#f8fafc', fontSize: '0.88rem' }}>1. Simulated Buy Order</b>
            <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '2px 0 0 0' }}>
              Estimate gas & swap ETH/BNB for token via factory router.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
          <span style={{ fontSize: '1.3rem' }}>2️⃣</span>
          <div>
            <b style={{ color: '#f8fafc', fontSize: '0.88rem' }}>2. Router Approval</b>
            <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '2px 0 0 0' }}>
              Call <code>approve(router, max)</code> from simulated buyer wallet.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
          <span style={{ fontSize: '1.3rem' }}>3️⃣</span>
          <div>
            <b style={{ color: is_honeypot ? '#f87171' : '#f8fafc', fontSize: '0.88rem' }}>
              3. Simulated Sell Liquidation
            </b>
            <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '2px 0 0 0' }}>
              {is_honeypot
                ? 'Execution reverted or charged confiscatory tax!'
                : 'Execute sell transaction back to DEX pool.'}
            </p>
          </div>
        </div>
      </div>

      {/* Live Simulation Metrics Grid (When Available) */}
      {is_available && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '12px',
            marginTop: '14px',
          }}
        >
          <div
            style={{
              background: 'rgba(15, 23, 42, 0.7)',
              padding: '12px 14px',
              borderRadius: '10px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}
          >
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', textTransform: 'uppercase' }}>
              Simulated Buy Tax
            </span>
            <div
              style={{
                fontSize: '1.3rem',
                fontWeight: 700,
                marginTop: '4px',
                color: buy_tax_percent !== null && buy_tax_percent > 10 ? '#f87171' : '#34d399',
              }}
            >
              {buy_tax_percent !== null ? `${buy_tax_percent.toFixed(1)}%` : '0.0%'}
            </div>
          </div>

          <div
            style={{
              background: 'rgba(15, 23, 42, 0.7)',
              padding: '12px 14px',
              borderRadius: '10px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}
          >
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', textTransform: 'uppercase' }}>
              Simulated Sell Tax
            </span>
            <div
              style={{
                fontSize: '1.3rem',
                fontWeight: 700,
                marginTop: '4px',
                color: sell_tax_percent !== null && sell_tax_percent > 10 ? '#f87171' : '#34d399',
              }}
            >
              {sell_tax_percent !== null ? `${sell_tax_percent.toFixed(1)}%` : '0.0%'}
            </div>
          </div>

          <div
            style={{
              background: 'rgba(15, 23, 42, 0.7)',
              padding: '12px 14px',
              borderRadius: '10px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}
          >
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', textTransform: 'uppercase' }}>
              Estimated Buy Gas
            </span>
            <div
              style={{
                fontSize: '1.15rem',
                fontWeight: 700,
                marginTop: '4px',
                color: '#38bdf8',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              {buy_gas ? `${buy_gas.toLocaleString()} gas` : 'Standard'}
            </div>
          </div>

          <div
            style={{
              background: 'rgba(15, 23, 42, 0.7)',
              padding: '12px 14px',
              borderRadius: '10px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}
          >
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', textTransform: 'uppercase' }}>
              Estimated Sell Gas
            </span>
            <div
              style={{
                fontSize: '1.15rem',
                fontWeight: 700,
                marginTop: '4px',
                color: is_honeypot ? '#f87171' : '#38bdf8',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              {sell_gas ? `${sell_gas.toLocaleString()} gas` : is_honeypot ? 'REVERTED' : 'Standard'}
            </div>
          </div>
        </div>
      )}

      {/* Honeypot Revert Warning Banner */}
      {is_honeypot && (
        <div
          style={{
            marginTop: '16px',
            padding: '12px 16px',
            borderRadius: '10px',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            fontSize: '0.9rem',
          }}
        >
          <b>🚨 Live Simulation Failure:</b>{' '}
          {honeypot_reason || 'Simulated sell transaction reverted on DEX router. Contract actively blocks token sales.'}
        </div>
      )}

      {/* Informational Guidance for Local/Source Code Contracts */}
      {!is_available && (
        <div
          style={{
            marginTop: '14px',
            padding: '12px 16px',
            borderRadius: '10px',
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.2)',
            fontSize: '0.86rem',
            color: '#cbd5e1',
            lineHeight: 1.5,
          }}
        >
          <b style={{ color: '#38bdf8' }}>ℹ️ Dynamic Simulation Scope:</b>{' '}
          {error_message ||
            'Dynamic simulation tests live buy/sell DEX trades on deployed EVM state. When auditing un-deployed source code files, static AST heuristics and ML classification perform deep structural inspection. To run live simulation against Uniswap/PancakeSwap liquidity pools, provide a verified contract address in the On-Chain Address Lookup tab.'}
        </div>
      )}
    </div>
  );
}
