// SPDX-License-Identifier: GPL-3.0
pragma solidity >0.8.0 <0.9.0;

import {CompatibilityFallbackHandler} from "./vendored/CompatibilityFallbackHandler.sol";

interface IERC1271 {
    function isValidSignature(bytes32 _data, bytes calldata _signature) external view returns (bytes4 magicValue);
}

/// @title Chained Signature Fallback Handler
/// @author mfw78 <mfw78@rndlabs.xyz>
/// @dev Allows chaining of EIP-1271 contracts to sign on behalf of Safe.
contract ChainedEIP1271FallbackHandler is CompatibilityFallbackHandler {

    // --- constants
    // CHAINED_MAGIC_VALUE = keccak256("safe.chained.signer");
    bytes32 internal constant CHAINED_MAGIC_VALUE = 0x97dfe645dd06a4ab5cf2d27ca53c2a61422acecf7834493d04db1230936dcf01;

    // --- state
    // TODO: Analyse gsa efficiency of `bool` versus `uint256` for storage.
    mapping (address => mapping (address => bool)) public isTrustedSigner;

    // --- events
    event TrustedSignerAdded(address indexed safe, address indexed signer);
    event TrustedSignerRemoved(address indexed safe, address indexed signer);

    /// @dev EIP-1271 signature validation.
    /// @param _data The data that was signed.
    /// @param _signature The signature.
    function isValidSignature(bytes32 _data, bytes calldata _signature) public view override returns (bytes4) {
        // If the signature is greater than 64 bytes, it *may* be a chained signature.
        if (_signature.length > 64) {
            // If the first 32 bytes of the signature are the magic value, then the signature is a chained signature.
            // Otherwise, the signature is a standard EIP-1271 safe signature.
            bytes32 chainMagicValue;
            assembly {
                chainMagicValue := calldataload(_signature.offset)
            }

            if (chainMagicValue == CHAINED_MAGIC_VALUE) {
                // The signature is a chained signature.
                // The first 32 bytes of the signature are the magic value.
                // The next 32 bytes of the signature are the address of the signer.
                // The remaining bytes of the signature for verification by the signer.
                address signer;
                bytes memory signature;
                assembly {
                    signer := calldataload(add(_signature.offset, 0x40))
                    signature := calldataload(add(_signature.offset, 0x60))
                }

                // Check if the signer is trusted and only then call the isValidSignature function.
                if (isTrustedSigner[msg.sender][signer]) {
                    // We prefix the data with the Safe address so context is preserved.
                    // TODO: Analyse for abi.encodePacked.
                    bytes4 magicValue = IERC1271(signer).isValidSignature(_data, abi.encode(msg.sender, signature));
                    if (magicValue == UPDATED_MAGIC_VALUE) {
                        // The signer is an EIP-1271 contract and the signature is valid.
                        return UPDATED_MAGIC_VALUE;
                    }
                }
            }
        }

        // The signature is a standard EIP-1271 signature.
        return super.isValidSignature(_data, _signature);
    }

    // --- state modification functions

    /// @dev Add a trusted signer for a Safe.
    /// @param signer The EIP-1271 contract that will sign on behalf of the Safe.
    function addTrustedSigner(address signer) external {
        isTrustedSigner[msg.sender][signer] = true;
        emit TrustedSignerAdded(msg.sender, signer);
    }

    /// @dev Remove a trusted signer for a Safe.
    /// @param signer The EIP-1271 contract that was signing on behalf of the Safe.
    function removeTrustedSigner(address signer) external {
        isTrustedSigner[msg.sender][signer] = false;
        emit TrustedSignerRemoved(msg.sender, signer);
    }
}