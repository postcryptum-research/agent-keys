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

        event UserOperationEvent(
            bytes32 indexed userOpHash,
            address indexed sender,
            address indexed paymaster,
            uint256 nonce,
            bool success,
            uint256 actualGasCost,
            uint256 actualGasUsed
        );
        event UserOperationRevertReason(
            bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
        );

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

    #[sol(rpc)]
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
            external
            payable;
        function currentNonce() external view returns (uint32);
        function validationConfig(bytes21 vId) external view returns (ValidationConfig memory);

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

    /// Reverts unless `safe.nonce() == expected`.
    interface ISafeNonceAssert {
        function check(address safe, uint256 expected) external view;
    }

    #[sol(rpc)]
    interface IWhitelistPaymaster {
        /// Gas budget and per-operation cap, in wei; a zero budget delists.
        function setSponsored(address account, uint128 budget, uint128 maxPerOp) external;
        function sponsored(address account) external view returns (bool);
        function sponsorships(address account) external view returns (uint128 remaining, uint128 maxPerOp);
        function deposit() external payable;
        function getDeposit() external view returns (uint256);
        /// Public bundlers only relay operations whose paymaster is staked
        /// in the EntryPoint (ERC-7562 reputation rules).
        function addStake(uint32 unstakeDelaySec) external payable;
    }
}
