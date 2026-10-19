// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Critical Delegatecall Backdoor Honeypot Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating CRITICAL severity honeypot vectors:
 *      1. Unsafe Low-Level Delegatecall: Contract forwards execution context to arbitrary targets.
 *      2. Address Blacklisting Mechanism: Admin can selectively freeze user accounts.
 *      3. Unbounded Dynamic Tax Setter: Owner can adjust fees to 100% without sanity cap.
 *
 * EXPECTED AUDIT THREAT LEVEL: CRITICAL (Score >= 75/100)
 */

contract CriticalDelegatecallToken {
    string public name = "Shadow Delegatecall Token";
    string public symbol = "SHADOW";
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000 * 10**18;

    address public owner;
    address public executionTarget;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    // HONEYPOT TRAP 1: Arbitrary address blacklist
    mapping(address => bool) public isBlacklisted;

    uint256 public sellTax = 10;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not owner");
        _;
    }

    modifier notBlacklisted(address account) {
        require(!isBlacklisted[account], "Blacklist: address is blacklisted");
        _;
    }

    constructor(address _target) {
        owner = msg.sender;
        executionTarget = _target;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function setBlacklist(address account, bool state) external onlyOwner {
        isBlacklisted[account] = state;
    }

    function setExecutionTarget(address _target) external onlyOwner {
        executionTarget = _target;
    }

    // HONEYPOT TRAP 2: Unbounded owner fee setter without require cap
    function setSellTax(uint256 newTax) external onlyOwner {
        sellTax = newTax;
    }

    // HONEYPOT TRAP 3: Low-level delegatecall backdoor
    function executeHook(bytes calldata hookData) external onlyOwner returns (bytes memory) {
        (bool success, bytes memory result) = executionTarget.delegatecall(hookData);
        require(success, "Delegatecall execution failed");
        return result;
    }

    function transfer(address recipient, uint256 amount) external notBlacklisted(msg.sender) returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external notBlacklisted(sender) returns (bool) {
        uint256 currentAllowance = allowance[sender][msg.sender];
        require(currentAllowance >= amount, "ERC20: allowance exceeded");
        allowance[sender][msg.sender] = currentAllowance - amount;
        _transfer(sender, recipient, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: zero address from");
        require(to != address(0), "ERC20: zero address to");
        require(balanceOf[from] >= amount, "ERC20: balance exceeded");

        uint256 fee = (amount * sellTax) / 100;
        uint256 netAmount = amount - fee;

        balanceOf[from] -= amount;
        balanceOf[to] += netAmount;

        if (fee > 0) {
            balanceOf[owner] += fee;
            emit Transfer(from, owner, fee);
        }

        emit Transfer(from, to, netAmount);
    }
}
