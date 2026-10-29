//! Talking to the chain: the account's address, its funding, and sending a
//! UserOperation. We bundle ourselves — `EntryPoint.handleOps` from the gas
//! wallet — so no third party sits between the agent and the chain.

use std::path::Path;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolEvent};
use anyhow::{bail, Context, Result};

use crate::abi::{IDemoCounter, IEntryPoint, IKernel, IKernelFactory, ISafeNonceAssert, IWhitelistPaymaster};
use crate::agent::{open_signer, parse32, AgentConfig, Deployments, Role};
use crate::bundler::Bundler;
use crate::kernel::{self, PermissionId};

/// Secrets come from the environment (optionally a `.env` file), never from
/// the agent config: `BASE_SEPOLIA_RPC_URL` (or `RPC_URL`) and, optionally,
/// `GAS_WALLET_KEYFILE`, a file holding the hex key of a small hot wallet that
/// submits `handleOps` itself and funds things. Without it, operations go
/// through a bundler and the wallet-paid commands are unavailable.
pub struct Env {
    pub rpc_url: String,
    pub gas_key: Option<[u8; 32]>,
    /// `BUNDLER_URL`: when set (or overridden by `--bundler`), operations go
    /// through an ERC-4337 bundler instead of our own `handleOps`.
    pub bundler_url: Option<String>,
}

impl Env {
    pub fn load(env_file: Option<&Path>, bundler_override: Option<&str>) -> Result<Self> {
        if let Some(path) = env_file {
            dotenvy::from_path(path).with_context(|| format!("loading {}", path.display()))?;
        }
        let rpc_url = std::env::var("BASE_SEPOLIA_RPC_URL")
            .or_else(|_| std::env::var("RPC_URL"))
            .context("set BASE_SEPOLIA_RPC_URL or RPC_URL")?;
        let gas_key = match std::env::var("GAS_WALLET_KEYFILE") {
            Ok(keyfile) => {
                let hex = std::fs::read_to_string(&keyfile).with_context(|| format!("reading {keyfile}"))?;
                Some(parse32(hex.trim())?)
            }
            Err(_) => None,
        };
        let bundler_url = bundler_override.map(str::to_owned).or_else(|| std::env::var("BUNDLER_URL").ok());
        if gas_key.is_none() && bundler_url.is_none() {
            bail!("set BUNDLER_URL (operations go through a bundler) or GAS_WALLET_KEYFILE (submit them ourselves)");
        }
        Ok(Self { rpc_url, gas_key, bundler_url })
    }
}

/// The permission the config describes and, when the owner's public key is
/// configured, the account's `initialize` data. Only public keys are needed —
/// and the owner's comes from the config, never from opening the owner's key:
/// the agent's operations must run where that key cannot be reached
/// (docs/KEY_POLICY.md rule 3). Root operations open it, in `send_raw_at`.
pub fn account_material(
    cfg: &AgentConfig,
    dep: &Deployments,
    domains: &std::collections::HashMap<Address, B256>,
) -> Result<(Bytes, Option<Bytes>)> {
    let agent_key = match &cfg.agent_public_key {
        Some(pk) => pk.parse()?,
        None => open_signer(&cfg.agent, Role::Agent)?.public_key()?,
    };
    let perm = cfg.permission_id()?;
    let permission_data =
        kernel::permission_data(dep.agent_policy, &cfg.policy_params(domains)?, dep.p256_signer, &agent_key);
    let init_data = match &cfg.owner_public_key {
        Some(pk) => Some(kernel::init_data(dep.p256_validator, &pk.parse()?, perm, permission_data.clone())),
        None => None,
    };
    Ok((permission_data, init_data))
}

/// Which key signs an operation, and on which validation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAs {
    /// The agent key under its permission (the mandate applies).
    Agent,
    /// The owner key on the root path.
    Owner,
    /// The recovery key on its own validator: `changeRootValidator` only.
    Recovery,
    /// The recovery key on the root path, after it took root over.
    RecoveryAsRoot,
}

impl SignAs {
    fn from_root(as_root: bool) -> Self {
        if as_root {
            SignAs::Owner
        } else {
            SignAs::Agent
        }
    }
}

pub struct Session {
    pub provider: DynProvider,
    /// The hot wallet that submits `handleOps` and pays for funding, if any.
    pub gas_wallet: Option<Address>,
    /// Set when operations are delivered through a bundler RPC.
    pub bundler: Option<Bundler>,
    pub cfg: AgentConfig,
    pub dep: Deployments,
    /// Kernel `initialize` data, known only when the config carries the
    /// owner's public key. Needed to derive an unpinned account and to
    /// deploy one; never obtained by opening the owner's key.
    init_data: Option<Bytes>,
    /// The agent permission described by the config (installed at creation,
    /// or the next one for a rotation).
    pub permission_data: Bytes,
    pub account: Address,
    /// `account` came from the config rather than from the factory.
    pub pinned: bool,
    /// EIP-712 domain separators of the mandate's x402 tokens.
    pub token_domains: std::collections::HashMap<Address, B256>,
}

impl Session {
    pub async fn open(env: &Env, cfg: AgentConfig, base: &Path) -> Result<Self> {
        let (provider, gas_wallet) = match &env.gas_key {
            Some(key) => {
                let signer = PrivateKeySigner::from_slice(key).context("gas wallet key")?;
                let address = signer.address();
                let provider =
                    ProviderBuilder::new().wallet(signer).connect(&env.rpc_url).await.context("connecting to RPC")?.erased();
                (provider, Some(address))
            }
            None => (ProviderBuilder::new().connect(&env.rpc_url).await.context("connecting to RPC")?.erased(), None),
        };

        let dep = cfg.load_deployments(base)?;
        let chain_id = provider.get_chain_id().await?;
        if chain_id != dep.chain_id {
            bail!("RPC is chain {chain_id} but deployments are for {}", dep.chain_id);
        }
        let bundler = match &env.bundler_url {
            Some(url) => {
                let rpc = ProviderBuilder::new().connect(url).await.context("connecting to the bundler")?.erased();
                let bundler = Bundler::new(rpc, dep.entry_point);
                bundler.check_entry_point().await?;
                Some(bundler)
            }
            None => None,
        };

        // EIP-712 domains of the tokens this mandate may pay x402 in: part of
        // the mandate, read here because the policy cannot read them itself.
        let mut token_domains = std::collections::HashMap::new();
        for token in cfg.x402_tokens() {
            let ds = crate::abi::IEip3009Token::new(token, provider.clone())
                .DOMAIN_SEPARATOR()
                .call()
                .await
                .with_context(|| format!("reading DOMAIN_SEPARATOR() of x402 token {token}"))?;
            token_domains.insert(token, ds);
        }
        let (permission_data, init_data) = account_material(&cfg, &dep, &token_domains)?;

        let (account, pinned) = match cfg.account {
            Some(pinned) => {
                if provider.get_code_at(pinned).await?.is_empty() {
                    bail!("config pins account {pinned} but nothing is deployed there");
                }
                (pinned, true)
            }
            None => {
                let Some(init_data) = &init_data else {
                    bail!("the config neither pins `account` nor gives `ownerPublicKey`: cannot derive the account");
                };
                let factory = IKernelFactory::new(dep.kernel_factory, provider.clone());
                (factory.getAddress(init_data.clone(), cfg.salt()?).call().await?, false)
            }
        };

        Ok(Self { provider, gas_wallet, bundler, cfg, dep, init_data, permission_data, account, pinned, token_domains })
    }

    /// Kernel `initialize` data for this account (needs `ownerPublicKey`).
    pub fn init_data(&self) -> Result<&Bytes> {
        self.init_data
            .as_ref()
            .context("deploying the account needs the owner's public key: set `ownerPublicKey` in the config")
    }

    pub async fn is_deployed(&self) -> Result<bool> {
        Ok(!self.provider.get_code_at(self.account).await?.is_empty())
    }

    pub async fn print_status(&self) -> Result<()> {
        let ep = IEntryPoint::new(self.dep.entry_point, self.provider.clone());
        println!("chain:          {}", self.dep.chain_id);
        println!("kernel impl:    {}", self.dep.kernel);
        println!("account:        {} ({})", self.account, if self.pinned { "pinned in config" } else { "derived from keys + mandate" });
        println!("deployed:       {}", self.is_deployed().await?);
        println!("balance:        {} wei", self.provider.get_balance(self.account).await?);
        println!("ep deposit:     {} wei", ep.balanceOf(self.account).call().await?);
        match self.gas_wallet {
            Some(w) => {
                println!("gas wallet:     {w}");
                println!("gas balance:    {} wei", self.provider.get_balance(w).await?);
            }
            None => println!("gas wallet:     (none — operations go through the bundler)"),
        }
        match self.dep.whitelist_paymaster {
            Some(pm) => {
                let paymaster = IWhitelistPaymaster::new(pm, self.provider.clone());
                // A paymaster deployed before per-account limits has no
                // `sponsorships`; fall back to its plain whitelist flag.
                let sponsorship = match paymaster.sponsorships(self.account).call().await {
                    Ok(s) => format!("gas budget left = {} wei, max per op = {} wei", s.remaining, s.maxPerOp),
                    Err(_) => format!("sponsored = {}, no per-account limits", paymaster.sponsored(self.account).call().await?),
                };
                println!(
                    "paymaster:      {pm} ({sponsorship}, deposit = {} wei, owner = {})",
                    paymaster.getDeposit().call().await?,
                    self.dep.paymaster_owner.map(|o| o.to_string()).unwrap_or_else(|| "?".into())
                );
            }
            None => println!("paymaster:      (not in deployments)"),
        }
        println!("demo counter:   {} (count = {})", self.dep.demo_counter, self.counter().await?);
        Ok(())
    }

    fn paymaster(&self) -> Result<Address> {
        self.dep
            .whitelist_paymaster
            .context("no whitelistPaymaster in deployments; run script/Deploy.s.sol")
    }

    /// The gas wallet, for commands that send a transaction from it.
    fn require_gas_wallet(&self, what: &str) -> Result<Address> {
        self.gas_wallet
            .with_context(|| format!("{what} sends a transaction from the gas wallet: set GAS_WALLET_KEYFILE"))
    }

    /// Top up the paymaster's EntryPoint deposit from the gas wallet.
    pub async fn paymaster_deposit(&self, amount: U256) -> Result<B256> {
        self.require_gas_wallet("paymaster deposit")?;
        let paymaster = IWhitelistPaymaster::new(self.paymaster()?, self.provider.clone());
        let receipt = paymaster.deposit().value(amount).send().await?.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// List (or delist) this account for sponsorship. Only the paymaster's
    /// owner — the gas wallet that deployed it — may do this.
    pub async fn sponsor(&self, budget: u128, max_per_op: u128) -> Result<B256> {
        self.require_gas_wallet("paymaster sponsor")?;
        let paymaster = IWhitelistPaymaster::new(self.paymaster()?, self.provider.clone());
        let receipt = paymaster.setSponsored(self.account, budget, max_per_op).send().await?.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Stake the paymaster in the EntryPoint so public bundlers relay its
    /// operations (owner only).
    pub async fn paymaster_stake(&self, amount: U256, unstake_delay_sec: u32) -> Result<B256> {
        self.require_gas_wallet("paymaster stake")?;
        let paymaster = IWhitelistPaymaster::new(self.paymaster()?, self.provider.clone());
        let receipt = paymaster.addStake(unstake_delay_sec).value(amount).send().await?.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    pub async fn counter(&self) -> Result<U256> {
        Ok(IDemoCounter::new(self.dep.demo_counter, self.provider.clone()).count().call().await?)
    }

    /// Read the counter as of `block`. Public RPC endpoints load-balance over
    /// replicas that can lag a block or two behind the one that returned our
    /// receipt, so pin the read and retry until a replica has the block.
    pub async fn counter_at(&self, block: u64) -> Result<U256> {
        let counter = IDemoCounter::new(self.dep.demo_counter, self.provider.clone());
        for _ in 0..15 {
            if let Ok(v) = counter.count().block(BlockId::number(block)).call().await {
                return Ok(v);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("no replica served block {block} within 15s")
    }

    /// Send ETH from the gas wallet to the (possibly counterfactual) account.
    /// Before funding an undeployed address, simulate `createAccount` with
    /// our init data: ETH sent to an address that can never be deployed is
    /// gone for good.
    pub async fn fund(&self, amount: U256) -> Result<B256> {
        self.require_gas_wallet("account fund")?;
        if !self.is_deployed().await? {
            let factory = IKernelFactory::new(self.dep.kernel_factory, self.provider.clone());
            let simulated = factory
                .createAccount(self.init_data()?.clone(), self.cfg.salt()?)
                .call()
                .await
                .context("createAccount simulation reverted; refusing to fund an address that cannot be deployed")?;
            if simulated != self.account {
                bail!("createAccount simulation returned {simulated}, expected {}", self.account);
            }
        }
        let tx = TransactionRequest::default().with_to(self.account).with_value(amount);
        let receipt = self.provider.send_transaction(tx).await?.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Build, sign in hardware, and submit one `execute(single)` operation.
    ///
    /// `pinned` fixes the EntryPoint nonce instead of taking the next free
    /// one. A caller that may resend the *same* logical action (a retry after
    /// a timeout) pins the nonce of its first attempt: at most one of the
    /// copies can ever be included, and a resend after inclusion fails fast.
    pub async fn send_op(
        &self,
        target: Address,
        value: U256,
        data: Bytes,
        as_root: bool,
        sponsored: bool,
        pinned: Option<U256>,
    ) -> Result<Included> {
        self.send_raw_at(kernel::execute_calldata(target, value, &data), SignAs::from_root(as_root), sponsored, pinned).await
    }

    /// A Safe transaction (`execTransaction` calldata for `safe`) as the only
    /// shape AgentPolicy admits: a batch whose first call asserts that the
    /// Safe's nonce is `safe_nonce`. A replay — a retry after the first copy
    /// went through — then reverts on-chain instead of executing twice.
    pub async fn send_safe_guarded(
        &self,
        safe: Address,
        value: U256,
        exec_transaction: Bytes,
        safe_nonce: U256,
        as_root: bool,
        sponsored: bool,
        pinned: Option<U256>,
    ) -> Result<Included> {
        let assert = self
            .dep
            .safe_nonce_assert
            .context("no safeNonceAssert in deployments; run script/Deploy.s.sol")?;
        let check: Bytes = ISafeNonceAssert::checkCall { safe, expected: safe_nonce }.abi_encode().into();
        let calls = vec![(assert, U256::ZERO, check), (safe, value, exec_transaction)];
        self.send_raw_at(kernel::execute_batch_calldata(calls), SignAs::from_root(as_root), sponsored, pinned).await
    }

    fn recovery_validator(&self) -> Result<Address> {
        self.dep
            .p256_recovery_validator
            .context("no p256RecoveryValidator in deployments; run script/Deploy.s.sol")
    }

    /// Whether `validator` is installed on the account (Kernel keeps its
    /// first key: re-pointing root at an installed validator keeps that key).
    pub async fn is_installed(&self, validator: Address) -> Result<bool> {
        let kernel = IKernel::new(self.account, self.provider.clone());
        let cfg = kernel.validationConfig(kernel::validator_id(validator)).call().await?;
        Ok(cfg.hook != Address::ZERO)
    }

    /// The operation's hash, computed locally by `owner-core` and checked
    /// against `EntryPoint.getUserOpHash`. A difference means the shared
    /// formula — the one the phone will trust — disagrees with the chain,
    /// and nothing is signed (docs/MOBILE_OWNER_DESIGN.md §8.3).
    async fn user_op_hash_checked<P: alloy::providers::Provider + Clone>(
        &self,
        ep: &IEntryPoint::IEntryPointInstance<P>,
        op: &IEntryPoint::PackedUserOperation,
    ) -> Result<B256> {
        let local = owner_core::user_op::user_op_hash(
            &owner_core::user_op::PackedUserOp {
                sender: op.sender,
                nonce: op.nonce,
                init_code: op.initCode.clone(),
                call_data: op.callData.clone(),
                account_gas_limits: op.accountGasLimits,
                pre_verification_gas: op.preVerificationGas,
                gas_fees: op.gasFees,
                paymaster_and_data: op.paymasterAndData.clone(),
            },
            self.dep.entry_point,
            self.dep.chain_id,
        );
        let on_chain = ep.getUserOpHash(op.clone()).call().await?;
        if local != on_chain {
            bail!("userOpHash mismatch: computed {local}, EntryPoint says {on_chain}; not signing");
        }
        Ok(local)
    }

    /// Owner operation: install the cold recovery key and grant it only
    /// `changeRootValidator`.
    pub async fn add_recovery(&self, key: &hw_signer::PublicKey, sponsored: bool) -> Result<Included> {
        let validator = self.recovery_validator()?;
        if self.is_installed(validator).await? {
            bail!("a recovery key is already installed ({validator})");
        }
        let nonce = self.install_nonce_for(kernel::validator_id(validator)).await?;
        let call = kernel::add_recovery_calldata(self.account, validator, key, nonce);
        self.send_raw_at(call, SignAs::Owner, sponsored, None).await
    }

    /// Recovery operation: the recovery key makes itself root (the owner's
    /// device is lost or broken).
    pub async fn recover(&self, sponsored: bool) -> Result<Included> {
        let call = kernel::change_root_calldata(self.recovery_validator()?, None);
        self.send_raw_at(call, SignAs::Recovery, sponsored, None).await
    }

    /// Root operation: hand root to `validator` holding `key`, and retire
    /// the validator of a lost (or replaced) owner key so it can sign
    /// nothing any more — not even an ERC-1271 message. `validator` may be
    /// the retired one itself: it is then uninstalled and reinstalled with
    /// the new key. Signed by the current root: the owner key, or the
    /// recovery key after `recover`.
    pub async fn set_root(
        &self,
        validator: Address,
        key: &hw_signer::PublicKey,
        retire: Option<Address>,
        signed_by_recovery: bool,
        sponsored: bool,
    ) -> Result<Included> {
        let reinstall = retire == Some(validator);
        if !reinstall && self.is_installed(validator).await? {
            bail!(
                "{validator} is already installed on this account: Kernel would keep its old key; \
                 pick another validator, or `--retire {validator}` to replace its key"
            );
        }
        if signed_by_recovery && retire.is_none() {
            bail!("after a recovery, retire the lost owner's validator: --retire <its address>");
        }
        let vid = kernel::validator_id(validator);
        // Kernel refuses an install under the nonce the id was installed with
        // before; after an uninstall, the stored nonce is still there.
        let nonce = self.install_nonce_for(vid).await?;
        let install = kernel::install_validator_call(vid, key, nonce);
        let change = kernel::change_root_calldata(validator, None);
        let me = self.account;
        let calls = match retire {
            // the same contract: free it first, then install the new key
            Some(old) if reinstall => vec![
                (me, U256::ZERO, kernel::uninstall_validator_call(old)),
                (me, U256::ZERO, install),
                (me, U256::ZERO, change),
            ],
            // another contract: the old one can go once it is not root
            Some(old) => vec![
                (me, U256::ZERO, install),
                (me, U256::ZERO, change),
                (me, U256::ZERO, kernel::uninstall_validator_call(old)),
            ],
            None => vec![(me, U256::ZERO, install), (me, U256::ZERO, change)],
        };
        let sign_as = if signed_by_recovery { SignAs::RecoveryAsRoot } else { SignAs::Owner };
        self.send_raw_at(kernel::execute_batch_calldata(calls), sign_as, sponsored, None).await
    }

    /// What the chain holds for the config's permission, next to what the
    /// config says. The config is only the owner's *intent*: the chain changes
    /// when the owner signs a root operation (rotate / add / revoke), never
    /// because the file changed.
    pub async fn permission_show(&self) -> Result<()> {
        use crate::abi::{IAgentPolicyView, IP256SignerView};
        let id = self.cfg.permission_id()?;
        let id32 = B256::right_padding_from(id.as_slice());
        let mark = |same: bool| if same { "  ok " } else { "DIFF " };
        let kernel_account = IKernel::new(self.account, self.provider.clone());
        let pc = kernel_account.permissionConfig(id).call().await?;
        println!("account:        {}", self.account);
        println!("permission:     {id}");
        if pc.signer == Address::ZERO {
            println!("on chain:       NOT INSTALLED — the config describes nothing the account enforces");
            return Ok(());
        }
        // signer key
        let signer = IP256SignerView::new(pc.signer, self.provider.clone());
        let on_key = signer.publicKeys(id32, self.account).call().await?;
        let cfg_key = match &self.cfg.agent_public_key {
            Some(pk) => pk.parse()?,
            None => open_signer(&self.cfg.agent, Role::Agent)?.public_key()?,
        };
        let same_key = on_key.x.0 == cfg_key.x && on_key.y.0 == cfg_key.y;
        println!("{}agent key       chain 0x{}… / config 0x{}…", mark(same_key), hex::encode(&on_key.x[..4]), hex::encode(&cfg_key.x[..4]));
        // policies
        for data in &pc.policyData {
            let policy = Address::from_slice(&data[2..]);
            println!("policy module:  {policy}{}", if policy == self.dep.agent_policy { "" } else { " (an older AgentPolicy than deployments.agentPolicy)" });
            // configs(account, id): validUntil, epoch, maxValuePerOp, budget, spent[, validAfter]
            let mut call = Vec::with_capacity(68);
            call.extend_from_slice(&alloy::primitives::keccak256("configs(address,bytes32)")[..4]);
            call.extend_from_slice(&B256::left_padding_from(self.account.as_slice()).0);
            call.extend_from_slice(&id32.0);
            let raw = self
                .provider
                .call(TransactionRequest::default().with_to(policy).with_input(Bytes::from(call)))
                .await?;
            let word = |i: usize| raw.get(i * 32..i * 32 + 32).map(U256::from_be_slice).unwrap_or_default();
            let (until, max, budget, spent, after) = (word(0), word(2), word(3), word(4), word(5));
            let p = &self.cfg.policy;
            println!("{}validUntil      chain {until} / config {}", mark(until == U256::from(p.valid_until)), p.valid_until);
            println!("{}validAfter      chain {after} / config {}", mark(after == U256::from(p.valid_after)), p.valid_after);
            println!("{}maxValuePerOp   chain {max} / config {}", mark(max.to_string() == p.max_value_per_op), p.max_value_per_op);
            println!("{}budget          chain {budget} / config {}", mark(budget.to_string() == p.budget), p.budget);
            println!("      spent           chain {spent}");
            let view = IAgentPolicyView::new(policy, self.provider.clone());
            let params = self.cfg.policy_params(&self.token_domains)?;
            for (target, selector) in params.targets.iter().zip(&params.selectors) {
                let allowed = view.isAllowed(self.account, id32, *target, *selector).call().await?;
                println!("{}allow           {target} {selector}{}", mark(allowed), if allowed { "" } else { "  — in the config, NOT allowed on chain" });
            }
            for (token, max, budget, _) in &params.tokens {
                let limit = view.tokenLimit(self.account, id32, *token).call().await;
                match limit {
                    Ok(l) => println!(
                        "{}token           {token} chain {}/{} (spent {}) / config {max}/{budget}",
                        mark(l.set && l.maxPerOp == *max && l.budget == *budget),
                        l.maxPerOp,
                        l.budget,
                        l.spent
                    ),
                    Err(_) => println!("DIFF token           {token}: this policy version has no token limits"),
                }
            }
        }
        println!("(entries allowed on chain but absent from the config are not listed: the chain keeps no list of them)");
        Ok(())
    }

    /// Root validator and recovery state, for `owner status`.
    pub async fn owner_status(&self) -> Result<()> {
        let kernel = IKernel::new(self.account, self.provider.clone());
        let root = kernel.rootValidator().call().await?;
        println!("account:        {}", self.account);
        println!("root validator: 0x{} (type 0x{:02x})", hex::encode(&root[1..]), root[0]);
        match self.dep.p256_recovery_validator {
            Some(v) => {
                let vid = kernel::validator_id(v);
                let installed = self.is_installed(v).await?;
                let may_take_root = kernel
                    .isAllowedSelector(vid, IKernel::changeRootValidatorCall::SELECTOR.into())
                    .call()
                    .await?;
                let is_root = root == vid;
                println!(
                    "recovery:       {v} (installed = {installed}, may take root = {may_take_root}, is root now = {is_root})"
                );
            }
            None => println!("recovery:       (no p256RecoveryValidator in deployments)"),
        }
        Ok(())
    }

    /// Root operation signed by the owner key: remove the agent permission.
    /// Its signer key and policy entries are uninstalled; its nonce space
    /// stays burned.
    pub async fn revoke_permission(&self, perm: PermissionId, sponsored: bool) -> Result<Included> {
        self.send_raw(kernel::uninstall_permission_calldata(perm), true, sponsored).await
    }

    /// Root operation signed by the owner key: replace permission `old` with
    /// the one the config describes (new agent key and/or mandate) in a
    /// single batch — uninstall, install, grant `execute`.
    pub async fn rotate_permission(&self, old: PermissionId, sponsored: bool) -> Result<Included> {
        let call_data = self.rotate_calldata(old).await?;
        self.send_raw(call_data, true, sponsored).await
    }

    /// The batch a rotation executes, for inspection (`--dry-run`).
    /// Root operation signed by the owner key: install the permission the
    /// config describes *next to* the existing ones (a schedule: each with
    /// its own window, budget and allow-list).
    pub async fn add_permission(&self, sponsored: bool) -> Result<Included> {
        let call = self.add_calldata().await?;
        self.send_raw(call, true, sponsored).await
    }

    pub async fn add_calldata(&self) -> Result<Bytes> {
        let new = self.cfg.permission_id()?;
        let kernel_account = IKernel::new(self.account, self.provider.clone());
        if kernel_account.validationConfig(kernel::permission_vid(new)).call().await?.hook != Address::ZERO {
            bail!("permission {new} is already installed: give the new window its own permissionId");
        }
        let nonce = self.install_nonce(new).await?;
        let calls = vec![
            (self.account, U256::ZERO, kernel::install_permission_calldata(new, self.permission_data.clone(), nonce)),
            (self.account, U256::ZERO, kernel::grant_execute_calldata(new)),
        ];
        Ok(kernel::execute_batch_calldata(calls))
    }

    pub async fn rotate_calldata(&self, old: PermissionId) -> Result<Bytes> {
        let new = self.cfg.permission_id()?;
        let nonce = self.install_nonce(new).await?;
        let calls = vec![
            (self.account, U256::ZERO, kernel::uninstall_permission_calldata(old)),
            (self.account, U256::ZERO, kernel::install_permission_calldata(new, self.permission_data.clone(), nonce)),
            (self.account, U256::ZERO, kernel::grant_execute_calldata(new)),
        ];
        Ok(kernel::execute_batch_calldata(calls))
    }

    /// `callGasLimit` for the execution phase: what the calldata needs when
    /// the EntryPoint calls the account with it, plus a margin. A fixed limit
    /// is a trap — an execution that runs out of gas reverts with no data,
    /// the EntryPoint still charges for it, and nothing says why.
    async fn estimate_call_gas(&self, call_data: &Bytes, deployed: bool) -> Result<u128> {
        const FLOOR: u128 = 150_000;
        if !deployed {
            // No account code to simulate `execute` against yet: estimate each
            // inner call as sent from the account's address (an address without
            // code is a valid `from`, and callees see the same msg.sender), plus
            // Kernel's dispatch overhead per call.
            const PER_CALL_OVERHEAD: u128 = 40_000;
            let Some(calls) = kernel::decode_execute(call_data) else {
                return Ok(FLOOR * 2);
            };
            let mut total: u128 = 0;
            for (target, value, data) in calls {
                let tx = TransactionRequest::default()
                    .with_from(self.account)
                    .with_to(target)
                    .with_value(value)
                    .with_input(data);
                let estimate = self
                    .provider
                    .estimate_gas(tx)
                    .await
                    .context("estimating the first operation's calls (one of them reverts as sent from the account)")?;
                total += estimate as u128 + PER_CALL_OVERHEAD;
            }
            return Ok((total * 13 / 10).max(FLOOR * 2));
        }
        let tx = TransactionRequest::default()
            .with_from(self.dep.entry_point)
            .with_to(self.account)
            .with_input(call_data.clone());
        let estimate = self
            .provider
            .estimate_gas(tx)
            .await
            .context("estimating the execution phase (the call itself reverts; see the message above)")?;
        Ok(((estimate as u128) * 13 / 10).max(FLOOR))
    }

    /// Kernel's rule for `installValidations`: the config nonce must equal
    /// `currentNonce()`, except that re-installing an id whose stored nonce
    /// already equals it bumps `currentNonce` first.
    async fn install_nonce(&self, perm: PermissionId) -> Result<u32> {
        self.install_nonce_for(kernel::permission_vid(perm)).await
    }

    async fn install_nonce_for(&self, vid: kernel::ValidationId) -> Result<u32> {
        let account = IKernel::new(self.account, self.provider.clone());
        let current = account.currentNonce().call().await?;
        let stored = account.validationConfig(vid).call().await?.nonce;
        Ok(if stored == current { current + 1 } else { current })
    }

    /// Sign `call_data` in hardware and submit it through `handleOps`. The
    /// first operation carries `initCode` and deploys the account. With
    /// `sponsored`, the whitelist paymaster pays instead of the account.
    async fn send_raw(&self, call_data: Bytes, as_root: bool, sponsored: bool) -> Result<Included> {
        self.send_raw_at(call_data, SignAs::from_root(as_root), sponsored, None).await
    }

    async fn send_raw_at(
        &self,
        call_data: Bytes,
        sign_as: SignAs,
        sponsored: bool,
        pinned: Option<U256>,
    ) -> Result<Included> {
        // Without a bundler we submit handleOps ourselves: check that we can
        // before the hardware signs anything.
        let beneficiary = match &self.bundler {
            Some(_) => None,
            None => Some(self.require_gas_wallet("submitting without a bundler (no BUNDLER_URL)")?),
        };
        let ep = IEntryPoint::new(self.dep.entry_point, self.provider.clone());
        let deployed = self.is_deployed().await?;
        if !deployed && !sponsored && self.provider.get_balance(self.account).await?.is_zero() {
            bail!("account {} holds no ETH to pay for its deployment; run `account fund` first", self.account);
        }
        // v0.7 layout: paymaster(20) ‖ verificationGasLimit(16) ‖ postOpGasLimit(16) ‖ data
        let paymaster_and_data = if sponsored {
            let mut b = Vec::with_capacity(52);
            b.extend_from_slice(self.paymaster()?.as_slice());
            b.extend_from_slice(&100_000u128.to_be_bytes());
            b.extend_from_slice(&0u128.to_be_bytes());
            Bytes::from(b)
        } else {
            Bytes::new()
        };
        let init_code = if deployed {
            Bytes::new()
        } else {
            kernel::init_code(self.dep.kernel_factory, self.init_data()?, self.cfg.salt()?)
        };

        let key = match sign_as {
            SignAs::Owner | SignAs::RecoveryAsRoot => kernel::root_nonce_key(),
            SignAs::Agent => kernel::permission_nonce_key(self.cfg.permission_id()?),
            SignAs::Recovery => kernel::validator_nonce_key(self.recovery_validator()?),
        };
        let next = ep.getNonce(self.account, key).call().await?;
        // EntryPoint nonces are `key (192 bits) ‖ sequence (64 bits)`.
        let nonce = match pinned {
            None => next,
            Some(n) => {
                if n >> 64 != next >> 64 {
                    bail!("--nonce {n:#x} is not in this path's nonce space (key {:#x})", next >> 64);
                }
                if n < next {
                    bail!("nonce {n:#x} is already used: an operation with it was included (next is {next:#x})");
                }
                n
            }
        };
        eprintln!("nonce:          {nonce:#x}");
        let fees = self.provider.estimate_eip1559_fees().await?;
        let verification_gas: u128 = if deployed { 300_000 } else { 1_500_000 };
        let call_gas = self.estimate_call_gas(&call_data, deployed).await?;
        eprintln!("gas limits:     verification {verification_gas}, call {call_gas}");

        let mut op = IEntryPoint::PackedUserOperation {
            sender: self.account,
            nonce,
            initCode: init_code,
            callData: call_data,
            accountGasLimits: kernel::pack_gas(verification_gas, call_gas),
            preVerificationGas: U256::from(100_000u64),
            gasFees: kernel::pack_gas(fees.max_priority_fee_per_gas, fees.max_fee_per_gas),
            paymasterAndData: paymaster_and_data,
            signature: Bytes::new(),
        };

        // The only place the owner's (or the recovery) key is opened: an
        // owner operation, run where that key lives.
        let signer = match sign_as {
            SignAs::Owner => open_signer(&self.cfg.owner, Role::Owner)?,
            SignAs::Agent => open_signer(&self.cfg.agent, Role::Agent)?,
            SignAs::Recovery | SignAs::RecoveryAsRoot => open_signer(
                self.cfg.recovery.as_ref().context("the config has no `recovery` key")?,
                Role::Recovery,
            )?,
        };
        let frame = |sig: &hw_signer::Signature| match sign_as {
            SignAs::Agent => kernel::permission_signature(sig),
            _ => kernel::root_signature(sig),
        };
        let mut user_op_hash = self.user_op_hash_checked(&ep, &op).await?;
        op.signature = frame(&signer.sign_digest(&user_op_hash.0)?);
        eprintln!(
            "path:           {}",
            match sign_as {
                SignAs::Owner => "root (owner key)",
                SignAs::Agent => "permission (agent key)",
                SignAs::Recovery => "recovery validator (changeRootValidator only)",
                SignAs::RecoveryAsRoot => "root (recovery key)",
            }
        );
        eprintln!("gas paid by:    {}", if sponsored { "paymaster" } else { "the account" });

        if let Some(bundler) = &self.bundler {
            // The bundler's estimate replaces ours; the hash covers the gas
            // fields, so the hardware signs once more.
            let est = bundler.estimate(&mut op).await?;
            eprintln!(
                "bundler est.:   preVerification {}, verification {}, call {}",
                est.pre_verification_gas, est.verification_gas_limit, est.call_gas_limit
            );
            user_op_hash = self.user_op_hash_checked(&ep, &op).await?;
            op.signature = frame(&signer.sign_digest(&user_op_hash.0)?);
            eprintln!("userOpHash:     {user_op_hash}");
            let sent = bundler.send(&op).await?;
            if sent != user_op_hash {
                bail!("bundler reports userOpHash {sent}, we computed {user_op_hash}");
            }
            eprintln!("delivery:       bundler accepted, waiting for inclusion");
            let receipt = bundler.wait(user_op_hash, Duration::from_secs(120)).await?;
            if !receipt.success {
                bail!(
                    "operation {user_op_hash} was included in tx {} but its execution reverted: {}",
                    receipt.receipt.transaction_hash,
                    receipt.reason.unwrap_or_default()
                );
            }
            return Ok(Included {
                user_op_hash,
                nonce,
                tx: receipt.receipt.transaction_hash,
                block: receipt.receipt.block_number.to::<u64>(),
                gas_used: receipt.actual_gas_used.to::<u64>(),
            });
        }
        eprintln!("userOpHash:     {user_op_hash}");
        eprintln!("delivery:       self-bundled via handleOps");

        let beneficiary = beneficiary.expect("checked before signing");
        let pending = match ep.handleOps(vec![op], beneficiary).send().await {
            Ok(p) => p,
            Err(e) => {
                if let Some(decoded) = e.as_decoded_interface_error::<IEntryPoint::IEntryPointErrors>() {
                    // AA2x = account validation, AA1x = initCode, AA3x = paymaster.
                    let reason = match decoded {
                        IEntryPoint::IEntryPointErrors::FailedOp(f) => format!("{} (op {})", f.reason, f.opIndex),
                        IEntryPoint::IEntryPointErrors::FailedOpWithRevert(f) => {
                            format!("{} (op {}), inner revert 0x{}", f.reason, f.opIndex, hex::encode(&f.inner))
                        }
                    };
                    bail!("EntryPoint rejected the operation: {reason}");
                }
                return Err(e).context("sending handleOps");
            }
        };
        let receipt = pending.get_receipt().await?;
        if !receipt.status() {
            bail!("handleOps transaction {} reverted", receipt.transaction_hash);
        }
        // The outer transaction succeeds even when the operation's execution
        // phase reverts: the EntryPoint charges for it and reports through
        // events. Only UserOperationEvent.success == true means it ran.
        let mut executed = None;
        let mut revert_reason = None;
        for log in receipt.logs() {
            if let Ok(ev) = IEntryPoint::UserOperationEvent::decode_log(&log.inner) {
                if ev.userOpHash == user_op_hash {
                    executed = Some(ev.success);
                }
            } else if let Ok(ev) = IEntryPoint::UserOperationRevertReason::decode_log(&log.inner) {
                if ev.userOpHash == user_op_hash {
                    revert_reason = Some(ev.revertReason.clone());
                }
            }
        }
        match executed {
            Some(true) => {}
            Some(false) => bail!(
                "operation {user_op_hash} was included in tx {} but its execution reverted: 0x{}",
                receipt.transaction_hash,
                revert_reason.map(hex::encode).unwrap_or_default()
            ),
            None => bail!("tx {} carries no UserOperationEvent for {user_op_hash}", receipt.transaction_hash),
        }
        Ok(Included {
            user_op_hash,
            nonce,
            tx: receipt.transaction_hash,
            block: receipt.block_number.unwrap_or_default(),
            gas_used: receipt.gas_used,
        })
    }
}

/// An operation's inclusion: its hash, the bundling transaction, its block,
/// and the gas used (the outer transaction's when self-bundled, the
/// operation's actual gas through a bundler).
pub struct Included {
    pub user_op_hash: B256,
    pub nonce: U256,
    pub tx: B256,
    pub block: u64,
    pub gas_used: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENTS: &str = r#"{
        "chainId": 84532,
        "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
        "kernel": "0xd6CEDDe84be40893d153Be9d467CD6aD37875b28",
        "kernelFactory": "0x2577507b78c2008Ff367261CB6285d44ba5eF2E9",
        "p256Validator": "0x0000000000000000000000000000000000000001",
        "p256Signer": "0x0000000000000000000000000000000000000002",
        "agentPolicy": "0x0000000000000000000000000000000000000003",
        "demoCounter": "0x0000000000000000000000000000000000000004"
    }"#;

    /// A valid P-256 point (the key of `vector`'s test scalar is not needed:
    /// any on-curve coordinates do).
    const X: &str = "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const Y: &str = "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    fn config(owner: &str, extra: &str) -> AgentConfig {
        serde_json::from_str(&format!(
            r#"{{
                "deployments": "unused.json",
                "owner": {owner},
                "agent": {{"tpm": "0x81010012"}},
                "permissionId": "0x74727333",
                "agentPublicKey": {{"x": "{X}", "y": "{Y}"}},
                {extra}
                "policy": {{"allow": [], "maxValuePerOp": "0", "budget": "0", "validUntil": 1}}
            }}"#
        ))
        .unwrap()
    }

    /// The agent session's key material never opens the owner key. The owner
    /// here is a software key, which `open_signer` refuses outright for the
    /// owner role in a normal build — so success proves it was not opened.
    #[test]
    fn agent_session_never_opens_the_owner_key() {
        let dep: Deployments = serde_json::from_str(DEPLOYMENTS).unwrap();
        let owner = r#"{"software": "0x0000000000000000000000000000000000000000000000000000000000000001"}"#;
        let cfg = config(owner, &format!(r#""ownerPublicKey": {{"x": "{X}", "y": "{Y}"}},"#));
        let none = std::collections::HashMap::new();
        let (_, init_data) = account_material(&cfg, &dep, &none).unwrap();
        assert!(init_data.is_some(), "the owner's public key from the config derives initData");
        assert_eq!(open_signer(&cfg.owner, Role::Owner).is_err(), !cfg!(feature = "insecure-software-keys"));

        // without the owner's public key there is simply no initData — not a
        // fallback to opening the owner's key
        let cfg = config(owner, "");
        let (_, init_data) = account_material(&cfg, &dep, &none).unwrap();
        assert!(init_data.is_none());
    }

    #[test]
    fn software_keys_are_refused() {
        let key = r#"{"software": "0x0000000000000000000000000000000000000000000000000000000000000001"}"#;
        let spec: crate::agent::KeySpec = serde_json::from_str(key).unwrap();
        for role in [Role::Owner, Role::Recovery, Role::Agent] {
            assert_eq!(
                open_signer(&spec, role).is_ok(),
                cfg!(feature = "insecure-software-keys"),
                "{role:?}: only in a test build that opted in"
            );
        }
    }

    #[test]
    fn repository_configs_parse_and_typos_are_rejected() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for name in ["agent.base-sepolia.json", "agent.tropic01.base-sepolia.json", "agent.window-demo.base-sepolia.json"] {
            AgentConfig::load(&dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        }
        let typo = std::fs::read_to_string(dir.join("agent.window-demo.base-sepolia.json"))
            .unwrap()
            .replace("\"validAfter\"", "\"validafter\"");
        assert!(serde_json::from_str::<AgentConfig>(&typo).is_err(), "a misspelled field must be an error");
    }

    #[test]
    fn protected_tpm_key_parses() {
        let spec: crate::agent::KeySpec =
            serde_json::from_str(r#"{"tpm": {"handle": "0x81010013", "authFile": "/etc/tpm_sign/owner.auth"}}"#).unwrap();
        assert!(matches!(
            spec,
            crate::agent::KeySpec::Tpm(crate::agent::TpmKey::Protected { ref auth_file, .. })
                if auth_file.to_str() == Some("/etc/tpm_sign/owner.auth")
        ));
    }
}
