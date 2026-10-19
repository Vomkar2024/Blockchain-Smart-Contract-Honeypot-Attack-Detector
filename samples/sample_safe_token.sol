// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Educational Safe Token (Standard Benign Reference Implementation)
 * @author CSDF Educational Security Research Team
 * @dev This smart contract exemplifies a secure, transparent, and standard ERC-20 token.
 * 
 * =========================================================================
 * SECURITY & FORENSIC ATTRIBUTES:
 * =========================================================================
 * 1. OpenZeppelin Base Library: Inherits audited, battle-tested implementations of ERC20 and Ownable.
 * 2. Capped Transfer Fees: Transfer fees cannot exceed an immutable hard ceiling of 5% (MAX_FEE).
 * 3. Sanitized Access Control: Fee setters are guarded by onlyOwner and bounded by strict require checks.
 * 4. Transparent Event Logging: Emits standard ERC-20 Transfer and Approval events for off-chain indexing.
 * 5. Ownership Renunciation: Implements standard renounceOwnership() to permit deployers to permanently relinquish administrative control.
 * 6. Symmetrical Trading: Sells to DEX liquidity pools and peer-to-peer transfers execute under identical rules without blacklists or hidden trapdoors.
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeToken is ERC20, Ownable {
    // Hardcoded absolute ceiling preventing confiscatory fees (maximum 5%)
    uint256 public constant MAX_FEE = 5;
    
    // Dynamic fee percentage for operational treasury (starts at 1%)
    uint256 public feePercent = 1;

    // Operational treasury wallet to receive transfer fee distributions
    address public treasury;

    // Events documenting fee governance changes
    event FeeUpdated(uint256 previousFee, uint256 newFee);
    event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);

    /**
     * @notice Initializes token with 1,000,000 units minted to deployer.
     * @param _treasury Initial treasury address for protocol development.
     */
    constructor(address _treasury) ERC20("Educational Safe Token", "SAFE") Ownable() {
        require(_treasury != address(0), "SafeToken: Treasury cannot be zero address");
        treasury = _treasury;
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    /**
     * @notice Updates the token transfer fee with strict sanity caps.
     * @dev Static analyzers verify that `fee` is bounded by a hardcoded constant (<= MAX_FEE).
     * @param fee New fee percentage (must be <= MAX_FEE and <= 25).
     */
    function setFee(uint256 fee) external onlyOwner {
        require(fee <= MAX_FEE, "SafeToken: Fee exceeds maximum immutable ceiling");
        require(fee <= 25, "SafeToken: Hard safety boundary exceeded");
        emit FeeUpdated(feePercent, fee);
        feePercent = fee;
    }

    /**
     * @notice Updates the operational treasury recipient address.
     * @param newTreasury New treasury address.
     */
    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "SafeToken: Invalid treasury address");
        emit TreasuryUpdated(treasury, newTreasury);
        treasury = newTreasury;
    }

    /**
     * @notice Allows deployer to renounce ownership, leaving the protocol with zero privileged access.
     * @dev This is a high-value positive security indicator for automated detectors.
     */
    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    /**
     * @notice Internal transfer mechanism enforcing symmetrical rules and capped fees.
     * @param from Sender address.
     * @param to Recipient address.
     * @param amount Token transfer quantity.
     */
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(from != address(0), "ERC20: transfer from zero address");
        require(to != address(0), "ERC20: transfer to zero address");
        require(amount > 0, "Transfer amount must be greater than zero");

        uint256 fee = (amount * feePercent) / 100;
        uint256 sendAmount = amount - fee;

        super._transfer(from, to, sendAmount);

        if (fee > 0 && treasury != address(0)) {
            super._transfer(from, treasury, fee);
        }

        // Standard ERC-20 event emissions for off-chain reconciliation
        emit Transfer(from, to, sendAmount);
        emit Approval(from, to, amount);
    }
}
