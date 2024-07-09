// contracts/CCIPSender.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CCIPSender {
    event CCIPMessageSent(bytes32 indexed messageId, uint256 destChainId, bytes data);

    function _send(uint256 destChainId, bytes memory data) internal virtual returns (bytes32) {
        bytes32 messageId = keccak256(abi.encodePacked(destChainId, data, block.timestamp));
        emit CCIPMessageSent(messageId, destChainId, data);
        return messageId;
    }
}
