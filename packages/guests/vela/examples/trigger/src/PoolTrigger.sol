// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {AbstractTrigger} from "vela/contracts/trigger/AbstractTrigger.sol";
import {IProcessorEndpoint} from "vela/contracts/interfaces/IProcessorEndpoint.sol";
import {Structs} from "vela/contracts/Structs.sol";

/// The companion of `examples/trigger_app.syn`: an execution pool. The app locks a user's private
/// balance, the ProcessorEndpoint claims that ETH into this contract and calls `execute` with the
/// app event the guest emitted — abi.encode(bytes16 lockId, address target, uint256 value, bytes data).
/// The call runs from the pool's address; whatever is left is swept back by the base `withdraw()`,
/// and `getTrustProcessPayload` hands the guest (lockId, remain, outcome) as a TRUSTPROCESS.
contract PoolTrigger is AbstractTrigger {
    error CallFailed();

    constructor(IProcessorEndpoint _processorEndpoint) AbstractTrigger(_processorEndpoint) {}

    function _execute(Structs.EventData calldata appEventData) internal override {
        if (appEventData.events.length == 0) return; // a TRUSTPROCESS carries no app events
        (, address target, uint256 value, bytes memory data) =
            abi.decode(appEventData.events[0], (bytes16, address, uint256, bytes));
        (bool ok, ) = target.call{value: value}(data);
        if (!ok) revert CallFailed(); // executeSuccess = false → everything is swept back
    }

    function _getTrustProcessPayload(
        Structs.EventData calldata appEventData,
        bool executeSuccess,
        bool, /* withdrawSuccess */
        Structs.TokenAndAmount[] calldata returnedTokens,
        Structs.TokenAndAmount[] calldata /* failedTokens */
    ) internal pure override returns (bytes memory) {
        if (appEventData.events.length == 0) return ""; // no follow-up: the loop ends here
        (bytes16 lockId, , , ) = abi.decode(appEventData.events[0], (bytes16, address, uint256, bytes));
        uint256 remain = 0;
        if (returnedTokens.length > 0) {
            remain = returnedTokens[returnedTokens.length - 1].amount; // ETH is the last entry
        }
        return abi.encode(lockId, remain, uint8(executeSuccess ? 0 : 1));
    }
}
