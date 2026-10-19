// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev OpenZeppelin Contracts v4.9.0 - Standard ERC-20 Benign Reference Implementation
 */
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BenignToken is ERC20, Ownable {
    uint256 public constant MAX_FEE = 5; // 5% maximum ceiling
    uint256 public feePercent = 1;

    constructor() ERC20("Benign Token", "BNG") Ownable() {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    function setFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Fee exceeds safety cap");
        feePercent = newFee;
    }

    function renounceOwnership() public override onlyOwner {
        super.renounceOwnership();
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(from != address(0), "ERC20: transfer from zero address");
        require(to != address(0), "ERC20: transfer to zero address");

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
