// SPDX-License-Identifier: MIT
// Test double for the two CoNET passport contracts the SilentPass exit checks
// (duplicateFactory, passport distributor). Placed at their mainnet addresses on a LOCAL anvil.
pragma solidity ^0.8.30;

contract PassportMock {
    mapping(address => bool) public paid;

    function setPaid(address who, bool on) external {
        paid[who] = on;
    }

    /// (nftIds, expires, expiresDays, premium), as the live contracts return.
    function getCurrentPassport(address who) external view returns (uint256, uint256, uint256, bool) {
        if (!paid[who]) return (0, 0, 0, false);
        return (1, 4102444800, 30, false); // expires 2100-01-01
    }
}
