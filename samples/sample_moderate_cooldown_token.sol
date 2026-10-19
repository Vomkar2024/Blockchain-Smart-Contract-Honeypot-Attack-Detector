// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Moderate Risk Anti-Bot Cooldown Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating MODERATE threat level patterns:
 *      1. Transfer Delay / Cooldown Timers: Enforces anti-bot delay intervals between transfers.
 *      2. Launch Trading Enable Toggle: Deployer enables trading once DEX liquidity pool is funded.
 *      3. Anti-Whale Wallet Cap: Configured to 2% of total supply to prevent pump-and-dump.
 *      4. Transparent Mitigations: OpenZeppelin ERC20 base, ownership renunciation, and standard events.
 *
 * EXPECTED AUDIT THREAT LEVEL: MODERATE (Score: ~30-40/100)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ModerateCooldownToken is ERC20, Ownable {
    // MODERATE INDICATOR 1: Anti-bot transfer delay timestamp
    mapping(address => uint256) public _holderLastTransferTimestamp;
    bool public transferDelayEnabled = true;

    // MODERATE INDICATOR 2: Trading enable flag
    bool public tradingEnabled = false;

    // MODERATE INDICATOR 3: Maximum wallet limit (2% of supply)
    uint256 public maxWalletAmount = 20000 * 10**18;

    event TradingEnabled();
    event CooldownDelayDisabled();

    constructor() ERC20("Anti-Bot Cooldown Token", "ABCOOL") Ownable() {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    function enableTrading() external onlyOwner {
        tradingEnabled = true;
        emit TradingEnabled();
    }

    function disableTransferDelay() external onlyOwner {
        transferDelayEnabled = false;
        emit CooldownDelayDisabled();
    }

    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        if (!tradingEnabled) {
            require(from == owner() || to == owner(), "Trading not active yet");
        }

        if (transferDelayEnabled && to != owner() && from != owner()) {
            require(
                _holderLastTransferTimestamp[from] < block.timestamp,
                "Cooldown delay active between transfers"
            );
            _holderLastTransferTimestamp[from] = block.timestamp + 10 seconds;
        }

        if (to != owner()) {
            require(balanceOf(to) + amount <= maxWalletAmount, "Exceeds max wallet limit");
        }

        super._transfer(from, to, amount);
        emit Transfer(from, to, amount);
        emit Approval(from, to, amount);
    }
}
