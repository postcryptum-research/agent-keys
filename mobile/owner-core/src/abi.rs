//! Kernel v3.3 call types used by the encoders in `kernel.rs`. Only the
//! calls, no RPC bindings: the CLI keeps its own `#[sol(rpc)]` interfaces in
//! `agent-signer/src/abi.rs` for talking to the chain; the phone never does.
//! Kernel's user-defined value types are spelled out as their underlying ABI
//! types (`ValidationId` → `bytes21`, `ExecMode` → `bytes32`).

use alloy_sol_types::sol;

sol! {
    interface IKernelFactory {
        function createAccount(bytes calldata data, bytes32 salt) external payable returns (address);
    }

    interface IKernel {
        struct ValidationConfig {
            uint32 nonce;
            address hook;
        }
        struct Execution {
            address target;
            uint256 value;
            bytes callData;
        }
        function uninstallValidation(bytes21 vId, bytes calldata deinitData, bytes calldata hookDeinitData)
            external payable;
        function initialize(
            bytes21 rootValidator,
            address hook,
            bytes calldata validatorData,
            bytes calldata hookData,
            bytes[] calldata initConfig
        ) external;
        function installValidations(
            bytes21[] calldata vIds,
            ValidationConfig[] calldata configs,
            bytes[] calldata validationData,
            bytes[] calldata hookData
        ) external payable;
        function grantAccess(bytes21 vId, bytes4 selector, bool allow) external payable;
        function changeRootValidator(bytes21 rootValidator, address hook, bytes calldata validatorData, bytes calldata hookData)
            external payable;
        function execute(bytes32 execMode, bytes calldata executionCalldata) external payable;
    }
}
