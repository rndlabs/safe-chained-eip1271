// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

import {Enum} from "safe/common/Enum.sol";
import {GnosisSafe} from "safe/GnosisSafe.sol";
import {GnosisSafeProxy} from "safe/proxies/GnosisSafeProxy.sol";
import {MultiSend} from "safe/libraries/MultiSend.sol";
import {SignMessageLib} from "safe/libraries/SignMessageLib.sol";

import {TestAccount, TestAccountLib} from "./libraries/TestAccountLib.t.sol";
import {SafeLib} from "./libraries/SafeLib.t.sol";
import {Safe} from "./helpers/Safe.t.sol";

abstract contract Base is Test, Safe {
    using TestAccountLib for TestAccount[];
    using TestAccountLib for TestAccount;
    using SafeLib for GnosisSafe;

    // --- accounts
    TestAccount alice;
    TestAccount bob;
    TestAccount carol;

    GnosisSafe public safe1;
    GnosisSafe public safe2;
    GnosisSafe public safe3;

    function setUp() public virtual {
        // setup test accounts
        alice = TestAccountLib.createTestAccount("alice");
        bob = TestAccountLib.createTestAccount("bob");
        carol = TestAccountLib.createTestAccount("carol");

        // create a safe with alice, bob and carol as owners and a threshold of 2
        address[] memory owners = new address[](3);
        owners[0] = alice.addr;
        owners[1] = bob.addr;
        owners[2] = carol.addr;

        safe1 = GnosisSafe(payable(SafeLib.createSafe(factory, singleton, owners, 2, address(handler), 0)));
        safe2 = GnosisSafe(payable(SafeLib.createSafe(factory, singleton, owners, 2, address(handler), 1)));
        safe3 = GnosisSafe(payable(SafeLib.createSafe(factory, singleton, owners, 2, address(handler), 2)));
    }

    function signers() internal view returns (TestAccount[] memory) {
        TestAccount[] memory _signers = new TestAccount[](2);
        _signers[0] = alice;
        _signers[1] = bob;
        _signers = TestAccountLib.sortAccounts(_signers);
        return _signers;
    }

    function setFallbackHandler(GnosisSafe safe, address handler) internal {
        // do the transaction
        safe.execute(
            address(safe),
            0,
            abi.encodeWithSelector(safe.setFallbackHandler.selector, handler),
            Enum.Operation.Call,
            signers()
        );
    }

    function safeSignMessage(GnosisSafe safe, bytes memory message) internal {
        safe.execute(
            address(signMessageLib),
            0,
            abi.encodeWithSelector(signMessageLib.signMessage.selector, message),
            Enum.Operation.DelegateCall,
            signers()
        );
    }
}
