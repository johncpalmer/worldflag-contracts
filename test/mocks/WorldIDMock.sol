// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../../src/interfaces/IWorldID.sol";

contract WorldIDMock is IWorldID {
    bool private verificationResult = true;

    function setVerificationResult(bool result) external {
        verificationResult = result;
    }

    function verifyProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external view override {
        if (!verificationResult) {
            revert("WorldID verification failed");
        }
        // If verificationResult is true, the function will complete successfully
    }
}