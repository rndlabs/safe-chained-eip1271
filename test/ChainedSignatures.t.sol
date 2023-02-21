// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity >=0.8.0 <0.9.0;

import "./Base.t.sol";

import {ChainedEIP1271FallbackHandler, IERC1271, CHAINED_MAGIC_VALUE} from "../src/ChainedEIP1271FallbackHandler.sol";

contract ChainedEIP1271FallbackHandlerTest is Base {

    // --- events
    event TrustedSignerAdded(address indexed safe, address indexed signer);
    event TrustedSignerRemoved(address indexed safe, address indexed signer);

    ChainedEIP1271FallbackHandler chainHandler;
    TestSigner authorisedSigner;
    TestSigner unauthorisedSigner;

    function setUp() public virtual override(Base) {
        super.setUp();

        // deploy the ChainedEIP1271FallbackHandler
        chainHandler = new ChainedEIP1271FallbackHandler();

        // deploy test signers
        authorisedSigner = new TestSigner();
        unauthorisedSigner = new TestSigner();

        // Set the ChainedEIP1271Fallbackhandler as the fallback handler for safe 1
        setFallbackHandler(safe1, address(chainHandler));
    }

    function test_addTrustedSigner() public {
        assertTrue(chainHandler.isTrustedSigner(address(safe1), address(authorisedSigner)) == false);

        // test event emission
        vm.expectEmit(true, true, true, true);
        emit TrustedSignerAdded(address(safe1), address(authorisedSigner));

        // add the test signer as a trusted signer for safe 1
        SafeLib.execute(
            safe1,
            address(safe1),
            0,
            abi.encodeWithSelector(chainHandler.addTrustedSigner.selector, address(authorisedSigner)),
            Enum.Operation.Call,
            signers()
        );

        assertTrue(chainHandler.isTrustedSigner(address(safe1), address(authorisedSigner)) == true);
    }

    function test_removeTrustedSigner() public {
        // add the test signer as a trusted signer for safe 1
        SafeLib.execute(
            safe1,
            address(safe1),
            0,
            abi.encodeWithSelector(chainHandler.addTrustedSigner.selector, address(authorisedSigner)),
            Enum.Operation.Call,
            signers()
        );

        assertTrue(chainHandler.isTrustedSigner(address(safe1), address(authorisedSigner)) == true);

        // test event emission
        vm.expectEmit(true, true, true, true);
        emit TrustedSignerRemoved(address(safe1), address(authorisedSigner));

        // remove the test signer as a trusted signer for safe 1
        SafeLib.execute(
            safe1,
            address(safe1),
            0,
            abi.encodeWithSelector(chainHandler.removeTrustedSigner.selector, address(authorisedSigner)),
            Enum.Operation.Call,
            signers()
        );

        assertTrue(chainHandler.isTrustedSigner(address(safe1), address(authorisedSigner)) == false);
    }

    function test_trustedSigner() public {
        // add the test signer as a trusted signer for safe 1
        SafeLib.execute(
            safe1,
            address(safe1),
            0,
            abi.encodeWithSelector(chainHandler.addTrustedSigner.selector, address(authorisedSigner)),
            Enum.Operation.Call,
            signers()
        );

        // check that the fallback handler is trusted for safe 1
        bytes memory data = abi.encode(CHAINED_MAGIC_VALUE, address(authorisedSigner), keccak256("something else"));
        assertTrue(IERC1271(address(safe1)).isValidSignature(bytes32(bytes20(address(safe1))), data) == IERC1271.isValidSignature.selector);
    }

    function test_untrustedSigner() public {
        // check that the fallback handler is trusted for safe 1
        bytes memory data = abi.encode(CHAINED_MAGIC_VALUE, address(unauthorisedSigner), keccak256("something else"));

        // Any call to `isValidSignature` should actually revert due to the implementation of EIP-1271 in Safe contracts
        vm.expectRevert("GS020");
        IERC1271(address(safe1)).isValidSignature(bytes32(bytes20(address(safe1))), data);
    }

    // TODO: Add test case for when it's just a normal EIP-1271 signature from Safe owners using standard Safe signatures
}

/// @dev An EIP1271 implementation that can be used to test the ChainedEIP1271FallbackHandler
contract TestSigner is IERC1271 {

    /// @dev A chained EIP-1271 signature is a tightly packed bytes array
    /// The first 20 bytes of the signature is the address of the safe
    /// The rest of the bytes are the signature
    /// @param _data The data that was signed
    /// @param _signature The signature
    function isValidSignature(bytes32 _data, bytes calldata _signature) external view override returns (bytes4) {
        address safe;
        assembly {
            safe := shr(96, calldataload(_signature.offset))
        }

        // the rest of the bytes are the signature
        bytes memory signature = _signature[20:];

        // debugging
        console.log("Safe address:", safe);
        console.logBytes(signature);

        // _data for testing is actually a bytes32 of the safe address
        if (_data != bytes32(bytes20(safe))) {
            return bytes4(0);
        }

        // Expect signature to be keccak256("something else")
        if (abi.decode(signature, (bytes32)) != keccak256("something else")) {
            return bytes4(0);
        }

        // return the magic value
        return IERC1271.isValidSignature.selector;
    }
}