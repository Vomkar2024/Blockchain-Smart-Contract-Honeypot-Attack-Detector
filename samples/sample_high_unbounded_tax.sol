// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title High Risk Unbounded Tax & Mint Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating HIGH threat level vulnerabilities:
 *      1. Unbounded Owner Tax Setter: Owner can adjust transfer tax without an immutable ceiling check.
 *      2. Hidden Mint Privilege: Owner can mint arbitrary new supply outside constructor.
 *      3. Low-Level Inline Assembly: Assembly block used inside transfer logic.
 *
 * EXPECTED AUDIT THREAT LEVEL: HIGH (Score: ~55-65/100)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract HighRiskUnboundedTaxToken is ERC20, Ownable {
    uint256 public sellTax = 5; // Initial 5% tax
    address public treasury;

    event TaxUpdated(uint256 previousTax, uint256 newTax);
    event TokensMinted(address indexed to, uint256 amount);

    constructor(address _treasury) ERC20("High Risk Dynamic Token", "HRUNBOUND") Ownable() {
        require(_treasury != address(0), "Invalid treasury");
        treasury = _treasury;
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    // HIGH VULNERABILITY 1: Unbounded tax setter without require(newTax <= MAX)
    function setSellTax(uint256 newTax) external onlyOwner {
        emit TaxUpdated(sellTax, newTax);
        sellTax = newTax;
    }

    // HIGH VULNERABILITY 2: Unconstrained privileged minting allows infinite supply inflation
    function mint(address account, uint256 amount) external onlyOwner {
        _mint(account, amount);
        emit TokensMinted(account, amount);
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(from != address(0), "ERC20: transfer from zero");
        require(to != address(0), "ERC20: transfer to zero");

        uint256 taxAmount = (amount * sellTax) / 100;
        uint256 sendAmount = amount - taxAmount;

        // HIGH VULNERABILITY 3: Inline assembly block in transfer execution
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, caller())
        }

        super._transfer(from, to, sendAmount);
        if (taxAmount > 0) {
            super._transfer(from, treasury, taxAmount);
        }

        emit Transfer(from, to, sendAmount);
        emit Approval(from, to, amount);
    }
}
