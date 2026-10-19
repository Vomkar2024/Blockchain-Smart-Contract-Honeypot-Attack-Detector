// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Benign DeFi Fixed-Supply Token
 * @author CSDF Educational Security Research Team
 * @dev Educational reference token demonstrating BENIGN / ZERO-RISK architecture:
 *      1. Zero Fees: Pure value transfer standard without taxes, slippage fees, or siphon logic.
 *      2. Fixed Supply: 100% of tokens minted strictly in constructor; no post-deployment mint function.
 *      3. Renounced Ownership: Full administrative renunciation supported.
 *      4. OpenZeppelin Audited Base: Adheres strictly to standard ERC-20 invariants.
 *
 * EXPECTED AUDIT THREAT LEVEL: BENIGN (Score: 0/100)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BenignDeFiToken is ERC20, Ownable {
    uint256 public constant TOTAL_FIXED_SUPPLY = 21000000 * 10**18;

    constructor() ERC20("DeFi Standard Protocol", "DEFISAFE") Ownable() {
        _mint(msg.sender, TOTAL_FIXED_SUPPLY);
    }

    /**
     * @notice Renounces ownership permanently, making the contract completely immutable.
     */
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

        super._transfer(from, to, amount);
        emit Transfer(from, to, amount);
        emit Approval(from, to, amount);
    }
}
