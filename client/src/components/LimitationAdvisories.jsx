import React from 'react';

export default function LimitationAdvisories() {
  return (
    <div className="glass-card">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc', marginBottom: '14px' }}>
        ⚠️ Limitation Advisories & Safety Scope
      </h2>

      <div className="advisory-box">
        <b>Forensic Analysis Boundaries & Safety Guidance:</b>
        <ul>
          <li>
            <b>Static Analysis Boundary:</b> Heuristic pattern matching inspects visible Solidity code. Upgradeable contracts (ERC-1967 proxies) can alter logic post-deployment; delegatecall targets must be verified independently.
          </li>
          <li>
            <b>Non-Guarantee Notice:</b> A <code>LOW</code> risk score does not guarantee financial safety. Off-chain liquidity removal (rugpulls) can drain an audited pool without contract-level honeypot traps.
          </li>
          <li>
            <b>Simulation Recommendation:</b> Always perform a test buy/sell transaction with minimal capital on an EVM testnet or local fork prior to allocating funds.
          </li>
          <li>
            <b>Educational Purpose:</b> This system provides forensic indicator scoring and does not constitute formal smart contract certification or investment advice.
          </li>
        </ul>
      </div>
    </div>
  );
}
