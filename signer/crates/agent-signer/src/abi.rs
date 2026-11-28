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
    interface IERC20Allowance {
        function allowance(address owner, address spender) external view returns (uint256);
    }

    /// A paymaster that takes a token from the account for its gas (Circle
    /// Paymaster): the token, and the gas its `postOp` charges on top.
    #[sol(rpc)]
    interface ITokenPaymaster {
        function token() external view returns (address);
        function additionalGasCharge() external view returns (uint256);
    }

    #[sol(rpc)]
    interface IKernelFactory {
        function createAccount(bytes calldata data, bytes32 salt) external payable returns (address);
        function getAddress(bytes calldata data, bytes32 salt) external view returns (address);
    }

    /// ZeroDev's `FactoryStaker` (issue #102).
    #[sol(rpc)]
    interface IFactoryStaker {
        function approved(address factory) external view returns (bool);
        function deployWithFactory(address factory, bytes calldata createData, bytes32 salt) external payable returns (address);
    }

    #[sol(rpc)]
    interface IEntryPointStake {
        function getDepositInfo(address account) external view returns (uint256 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime);
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
        function isAllowedSelector(bytes21 vId, bytes4 selector) external view returns (bool);
        function changeRootValidator(bytes21 rootValidator, address hook, bytes calldata validatorData, bytes calldata hookData)
            external
            payable;
        function rootValidator() external view returns (bytes21);

        struct PermissionConfig {
            bytes2 permissionFlag;
            address signer;
            bytes22[] policyData;
        }
        function permissionConfig(bytes4 pId) external view returns (PermissionConfig memory);
        function execute(bytes32 execMode, bytes calldata executionCalldata) external payable;
    }

    /// Read side of the agent modules, for `permission show`.
    #[sol(rpc)]
    interface IAgentPolicyView {
        function isAllowed(address account, bytes32 id, address target, bytes4 selector) external view returns (bool);
        function tokenLimit(address account, bytes32 id, address token)
            external
            view
            returns (uint128 maxPerOp, uint128 budget, uint128 spent, bool set);
        /// Since payee lists (issue #66); an earlier AgentPolicy reverts.
        function payeeAllowed(address account, bytes32 id, address token, address payee) external view returns (bool);
    }

    /// A venue's decoder (`CowSwapDecoder`, `OneInchLimitOrderDecoder`,
    /// `SwapRouter02Decoder`). `domainSeparator` is of the two that judge
    /// orders, `swapCall` of the one that judges a swap.
    #[sol(rpc)]
    interface IVenueDecoder {
        function venue() external view returns (address);
        function spender() external view returns (address);
        function domainSeparator() external view returns (bytes32);
        function untouched(address account, bytes calldata order) external view returns (bool);
        function checkConfig(bytes calldata config) external view returns (bool);
        function swapCall(address account, bytes calldata order) external view returns (bytes memory);
        function judge(address account, bytes calldata config, bytes calldata order)
            external
            view
            returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest);
    }

    /// AgentPolicy's trading side (issue #80).
    #[sol(rpc)]
    interface IAgentPolicyTrading {
        function period(address account, bytes32 id) external view returns (uint32 seconds_, uint48 seen);
        function venue(address account, bytes32 id, address decoder) external view returns (bytes32 codeHash, bytes32 configHash);
        function orderRegister(address decoder, bytes calldata config, bytes calldata order) external;
        event OrderRegistered(address indexed account, address indexed decoder, bytes order);
    }

    /// AgentPolicy's limits per id of an ERC-6909 contract (issue #186): the
    /// key an id's limit is read under through `tokenLimit`. An AgentPolicy
    /// without them reverts.
    #[sol(rpc)]
    interface IAgentPolicyIds {
        function idAsset(address token, uint256 id) external pure returns (address);
    }

    #[sol(rpc)]
    interface IErc20Allowance {
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address owner) external view returns (uint256);
    }

    /// The EIP-3009 side of a token (USDC FiatToken v2.2).
    #[sol(rpc)]
    interface IEip3009Token {
        function DOMAIN_SEPARATOR() external view returns (bytes32);
        function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    /// AgentPolicy's guardian (#251, decision 2): named by the owner for a
    /// mandate, it may pause one of the mandate's modules. An AgentPolicy
    /// from before the division reverts.
    #[sol(rpc)]
    interface IAgentPolicyGuardian {
        function setGuardian(bytes32 id, address guardian) external;
        function pause(address account, bytes32 id, address module, bool paused) external;
        function guardian(address account, bytes32 id) external view returns (address);
        function paused(address account, bytes32 id, address module) external view returns (bool);
        error NotTheGuardian();
        error NotAModule();
        error NotInitialized(address smartAccount);
    }

    /// AgentPolicy's x402 entry points.
    interface IAgentPolicyX402 {
        function x402Authorize(
            address token,
            address from,
            address to,
            uint256 value,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce
        ) external;
        function x402Reclaim(
            bytes32 id,
            address token,
            address to,
            uint256 value,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce
        ) external;
    }

    interface X402Events {
        event X402Authorized(
            address indexed account,
            address indexed token,
            address indexed to,
            uint256 value,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce
        );
    }

    #[sol(rpc)]
    interface IErc1271 {
        function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    }

    // P256Validator, and P256RecoveryValidator which inherits it: the key the
    // account's root (or recovery) path verifies against.
    #[sol(rpc)]
    interface IP256ValidatorView {
        function publicKeys(address account) external view returns (bytes32 x, bytes32 y);
    }

    #[sol(rpc)]
    interface IP256SignerView {
        function publicKeys(bytes32 id, address account) external view returns (bytes32 x, bytes32 y);
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
