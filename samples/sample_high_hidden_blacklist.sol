// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title High Threat Privileged Mint & Blacklist Guard Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating HIGH threat level vulnerabilities:
 *      1. Hardcoded Flagged Address Restrictions: Modifier checking address without timelock.
 *      2. Privileged Unconstrained Minting: Owner can mint arbitrary new supply outside constructor.
 *      3. Restrictive Max Wallet / Max Transaction limits: Prevents large liquidations.
 *
 * EXPECTED AUDIT THREAT LEVEL: HIGH (Score: ~55-65/100)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract HighRiskHiddenBlacklistToken is ERC20, Ownable {
    // VULNERABILITY 1: Address check mapping
    mapping(address => bool) private _isBlacklisted;

    // VULNERABILITY 2: Restrictive transaction limits
    uint256 public maxTxAmount = 5000 * 10**18;
    uint256 public maxWalletAmount = 10000 * 10**18;

    event AddressBlocked(address indexed account, bool status);
    event LimitsConfigured(uint256 maxTx, uint256 maxWallet);
    event TokensMinted(address indexed to, uint256 amount);

    constructor() ERC20("High Risk Guard Token", "HRGUARD") Ownable() {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    // HIGH VULNERABILITY: Privileged unconstrained minting allows sudden supply inflation
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }

    function setLimits(uint256 newMaxTx, uint256 newMaxWallet) external onlyOwner {
        maxTxAmount = newMaxTx;
        maxWalletAmount = newMaxWallet;
        emit LimitsConfigured(newMaxTx, newMaxWallet);
    }

    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(amount <= maxTxAmount, "Exceeds max transaction limit");

        if (to != owner()) {
            require(balanceOf(to) + amount <= maxWalletAmount, "Exceeds max wallet limit");
        }

        super._transfer(from, to, amount);
        emit Transfer(from, to, amount);
        emit Approval(from, to, amount);
    }
}
