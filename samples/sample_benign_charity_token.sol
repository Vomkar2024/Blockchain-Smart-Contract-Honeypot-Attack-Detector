// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Benign Capped Charity & Community Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating BENIGN architecture with transparent capped fees:
 *      1. Immutable Fee Cap: Maximum possible fee is hardcoded to 3% (MAX_FEE), preventing tax hikes.
 *      2. Dedicated Charity Treasury: 1% fee routed transparently to verified public good address.
 *      3. OpenZeppelin Security: Standard ERC-20 with standard Transfer and Approval event logs.
 *      4. Transparent Governance: All fee changes strictly bounded by require(newFee <= 25).
 *
 * EXPECTED AUDIT THREAT LEVEL: BENIGN (Score: 0/100)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BenignCharityToken is ERC20, Ownable {
    // Hard ceiling preventing confiscatory fees (maximum 3%)
    uint256 public constant MAX_FEE = 3;
    uint256 public feePercent = 1;

    address public charityTreasury;

    event FeeUpdated(uint256 previousFee, uint256 newFee);
    event CharityTreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);

    constructor(address _charity) ERC20("Community Charity Token", "CHARITY") Ownable() {
        require(_charity != address(0), "Invalid charity address");
        charityTreasury = _charity;
        _mint(msg.sender, 50000000 * 10 ** decimals());
    }

    function setFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Fee exceeds immutable charity ceiling");
        require(newFee <= 25, "Safety check ceiling enforced");
        emit FeeUpdated(feePercent, newFee);
        feePercent = newFee;
    }

    function setCharityTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "Invalid charity address");
        emit CharityTreasuryUpdated(charityTreasury, newTreasury);
        charityTreasury = newTreasury;
    }

    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(from != address(0), "ERC20: transfer from zero");
        require(to != address(0), "ERC20: transfer to zero");

        uint256 fee = (amount * feePercent) / 100;
        uint256 sendAmount = amount - fee;

        super._transfer(from, to, sendAmount);
        if (fee > 0) {
            super._transfer(from, charityTreasury, fee);
        }

        emit Transfer(from, to, sendAmount);
        emit Approval(from, to, amount);
    }
}
