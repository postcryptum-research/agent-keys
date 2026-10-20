//! On-chain interfaces the CLI talks to — only what it actually calls.
//! Kernel v3.3 user-defined value types are spelled out as their underlying
//! ABI types (`ValidationId` → `bytes21`, `ExecMode` → `bytes32`).

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IEntryPoint {
        struct PackedUserOperation {
            address sender;
            uint256 nonce;
            bytes initCode;
            bytes callData;
            bytes32 accountGasLimits;
            uint256 preVerificationGas;
            bytes32 gasFees;
            bytes paymasterAndData;
            bytes signature;
        }

        error FailedOp(uint256 opIndex, string reason);
        error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

        function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
        function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);
        function handleOps(PackedUserOperation[] calldata ops, address beneficiary) external;
        function balanceOf(address account) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IKernelFactory {
        function createAccount(bytes calldata data, bytes32 salt) external payable returns (address);
        function getAddress(bytes calldata data, bytes32 salt) external view returns (address);
    }

    interface IKernel {
        struct ValidationConfig {
            uint32 nonce;
            address hook;
        }

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
        function execute(bytes32 execMode, bytes calldata executionCalldata) external payable;
    }

    #[sol(rpc)]
    interface IDemoCounter {
        function increment() external;
        function count() external view returns (uint256);
    }

    #[sol(rpc)]
    interface IWhitelistPaymaster {
        function setSponsored(address account, bool allowed) external;
        function sponsored(address account) external view returns (bool);
        function deposit() external payable;
        function getDeposit() external view returns (uint256);
    }
}
