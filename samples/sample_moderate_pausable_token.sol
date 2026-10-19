// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Moderate Risk Pausable Enterprise Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating MODERATE threat level patterns:
 *      1. Pausable Transfers: Emergency circuit breaker allowing the owner to pause trading.
 *      2. Maximum Transaction / Anti-Whale Limit: Limits transaction sizes to prevent large market impacts.
 *      3. Anti-Bot Cooldown Delay: Enforces timestamp delay between consecutive transfers.
 *      4. Audited Mitigations: Uses OpenZeppelin standards, hardcoded fee ceiling, and transparent events.
 *
 * EXPECTED AUDIT THREAT LEVEL: MODERATE (Score: ~30-40/100)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ModeratePausableToken is ERC20, Ownable {
    // MODERATE INDICATOR 1: Owner-controlled pause switch
    bool public paused = false;

    // MODERATE INDICATOR 2: Anti-whale transaction size limit
    uint256 public maxTxAmount = 25000 * 10**18;
    uint256 public maxWalletAmount = 50000 * 10**18;

    // MODERATE INDICATOR 3: Cooldown delay mapping
    mapping(address => uint256) public _holderLastTransferTimestamp;

    // MITIGATING FACTOR: Strictly capped fee (<= 3%)
    uint256 public constant MAX_FEE = 3;
    uint256 public feePercent = 1;

    event TradingPaused(address indexed account);
    event TradingUnpaused(address indexed account);
    event FeeConfigured(uint256 fee);

    constructor() ERC20("Enterprise Pausable Token", "ENTPAUSE") Ownable() {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    function pause() external onlyOwner {
        paused = true;
        emit TradingPaused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit TradingUnpaused(msg.sender);
    }

    function setFee(uint256 fee) external onlyOwner {
        require(fee <= MAX_FEE, "Fee exceeds ceiling");
        require(fee <= 25, "Safety check");
        feePercent = fee;
        emit FeeConfigured(fee);
    }

    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(!paused, "Pausable: token transfers are temporarily paused");
        require(amount <= maxTxAmount, "Pausable: exceeds max transaction limit");

        _holderLastTransferTimestamp[from] = block.timestamp;

        uint256 fee = (amount * feePercent) / 100;
        uint256 sendAmount = amount - fee;

        super._transfer(from, to, sendAmount);
        if (fee > 0) {
            super._transfer(from, owner(), fee);
        }

        emit Transfer(from, to, sendAmount);
        emit Approval(from, to, amount);
    }
}
