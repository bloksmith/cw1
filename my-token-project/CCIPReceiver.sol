// contracts/CCIPReceiver.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CCIPReceiver {
    event CCIPMessageReceived(bytes32 indexed messageId, uint256 sourceChainId, bytes data);

    function _onCCIPMessageReceived(bytes32 messageId, uint256 sourceChainId, bytes memory data) internal virtual {
        emit CCIPMessageReceived(messageId, sourceChainId, data);
    }
}
