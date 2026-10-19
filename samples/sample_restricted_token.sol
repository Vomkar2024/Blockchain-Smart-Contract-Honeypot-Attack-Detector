// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Educational Restricted Token (Ambiguous Governance / Compliance Archetype)
 * @author CSDF Educational Security Research Team
 * @dev This smart contract models an ambiguous governance/enterprise token featuring
 *      centralized administrative controls (pausability, anti-whale wallet caps, whitelist).
 * 
 * =========================================================================
 * SECURITY FORENSICS & ARCHITECTURAL AMBIGUITY:
 * =========================================================================
 * In smart contract security analysis, tokens with administrative restrictions reside in an
 * ambiguous zone between legitimate compliance/anti-bot protection and potential rug-pull traps:
 * 
 * 1. Pausable Transfers (HONEYPOT_PAUSABLE_TRANSFERS):
 *    - Legitimate Purpose: Emergency circuit-breaker during hacks, bridge exploits, or audits.
 *    - Malicious Abuse: Unscrupulous deployer pauses transfers permanently after adding DEX liquidity,
 *      preventing buyers from liquidating.
 * 
 * 2. Maximum Transaction & Wallet Limits (HONEYPOT_MAX_WALLET_TX_LIMIT):
 *    - Legitimate Purpose: Anti-whale protection preventing predatory dump transactions.
 *    - Malicious Abuse: Microscopic limits (e.g. 10 tokens) preventing users from exiting their positions.
 * 
 * 3. Whitelist Exemption Mechanism:
 *    - Legitimate Purpose: Allows institutional partners, staking pools, and governance contracts
 *      to bypass anti-whale limits.
 *    - Malicious Abuse: Only whitelisted insider addresses can transfer, locking retail investors out.
 * 
 * 4. Mitigating Positive Security Indicators:
 *    - Uses audited OpenZeppelin ERC20 base contracts.
 *    - Emits standard ERC-20 Transfer and Approval events.
 *    - Fee setter is strictly bounded by a hard ceiling (<= 3%).
 *    - Ownership renunciation is fully supported once initial governance bootstrap concludes.
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract RestrictedGovernanceToken is ERC20, Ownable {
    // Maximum anti-whale bounds (2.5% of total supply per tx, 5.0% max wallet holding)
    uint256 public maxTxAmount = 25000 * 10**18;
    uint256 public maxWalletAmount = 50000 * 10**18;

    // Hard ceiling for governance fees (maximum 3%)
    uint256 public constant MAX_FEE = 3;
    uint256 public feePercent = 1;

    // Administrative state switches
    bool public paused = false;
    mapping(address => uint256) public _holderLastTransferTimestamp;

    // Governance and partner whitelist mapping
    mapping(address => bool) public isWhitelisted;

    // Educational audit events
    event TradingPaused(address indexed account);
    event TradingUnpaused(address indexed account);
    event WhitelistUpdated(address indexed target, bool status);
    event LimitsUpdated(uint256 newMaxTx, uint256 newMaxWallet);
    event FeeConfigured(uint256 fee);

    constructor() ERC20("Educational Restricted Token", "RESTRICT") Ownable() {
        // Mint initial supply of 1,000,000 tokens
        _mint(msg.sender, 1000000 * 10**18);

        // Deployer is initially whitelisted for bootstrapping liquidity
        isWhitelisted[msg.sender] = true;
    }

    /**
     * @notice Updates whitelist exemption status for institutional or ecosystem wallets.
     */
    function setWhitelisted(address account, bool status) external onlyOwner {
        require(account != address(0), "RestrictedToken: Zero address cannot be whitelisted");
        isWhitelisted[account] = status;
        emit WhitelistUpdated(account, status);
    }

    /**
     * @notice Emergency circuit-breaker pausing all non-whitelisted token transfers.
     * @dev Static detectors flag this as HONEYPOT_PAUSABLE_TRANSFERS due to centralization risk.
     */
    function pause() external onlyOwner {
        paused = true;
        emit TradingPaused(msg.sender);
    }

    /**
     * @notice Resumes token transfers following an emergency pause.
     */
    function unpause() external onlyOwner {
        paused = false;
        emit TradingUnpaused(msg.sender);
    }

    /**
     * @notice Configures anti-whale transaction and wallet limits.
     * @dev Protected by minimum sanity checks to prevent micro-limit lockups.
     */
    function setLimits(uint256 newMaxTx, uint256 newMaxWallet) external onlyOwner {
        require(newMaxTx >= 1000 * 10**18, "RestrictedToken: Max tx limit cannot be lower than 0.1% supply");
        require(newMaxWallet >= 5000 * 10**18, "RestrictedToken: Max wallet limit cannot be lower than 0.5% supply");
        maxTxAmount = newMaxTx;
        maxWalletAmount = newMaxWallet;
        emit LimitsUpdated(newMaxTx, newMaxWallet);
    }

    /**
     * @notice Updates transfer fee with strict sanity caps.
     */
    function setFee(uint256 fee) external onlyOwner {
        require(fee <= MAX_FEE, "RestrictedToken: Fee exceeds maximum immutable ceiling");
        require(fee <= 25, "RestrictedToken: Safety ceiling exceeded");
        feePercent = fee;
        emit FeeConfigured(fee);
    }

    /**
     * @notice Renounces ownership permanently, rendering parameters immutable.
     */
    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    /**
     * @notice Internal transfer implementing pause guards, anti-whale caps, and whitelist bypass.
     */
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(from != address(0), "ERC20: transfer from zero address");
        require(to != address(0), "ERC20: transfer to zero address");

        // Gated pause check: whitelisted addresses can transfer during maintenance
        if (paused && !isWhitelisted[from] && !isWhitelisted[to]) {
            revert("RestrictedToken: Transfers are currently paused");
        }

        // Anti-whale limits enforced for non-whitelisted participants
        if (!isWhitelisted[from] && !isWhitelisted[to]) {
            require(amount <= maxTxAmount, "RestrictedToken: Transfer amount exceeds maxTxAmount");
            require(balanceOf[to] + amount <= maxWalletAmount, "RestrictedToken: Recipient balance exceeds maxWalletAmount");
        }

        uint256 fee = (amount * feePercent) / 100;
        uint256 sendAmount = amount - fee;

        super._transfer(from, to, sendAmount);

        if (fee > 0 && owner() != address(0)) {
            super._transfer(from, owner(), fee);
        }

        // Emits standard ERC-20 transfer and approval events
        emit Transfer(from, to, sendAmount);
        emit Approval(from, to, amount);
    }
}
