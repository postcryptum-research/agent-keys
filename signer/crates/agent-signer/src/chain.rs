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
use alloy::sol_types::SolEvent;
use anyhow::{bail, Context, Result};

use crate::abi::{IDemoCounter, IEntryPoint, IKernel, IKernelFactory, IWhitelistPaymaster};
use crate::agent::{open_signer, parse32, AgentConfig, Deployments};
use crate::bundler::Bundler;
use crate::kernel::{self, PermissionId};

/// Secrets come from the environment (optionally a `.env` file), never from
/// the agent config: `BASE_SEPOLIA_RPC_URL` (or `RPC_URL`) and
/// `GAS_WALLET_KEYFILE`, a file holding the bundler EOA's hex key.
pub struct Env {
    pub rpc_url: String,
    pub gas_key: [u8; 32],
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
        let keyfile = std::env::var("GAS_WALLET_KEYFILE").context("set GAS_WALLET_KEYFILE")?;
        let hex = std::fs::read_to_string(&keyfile).with_context(|| format!("reading {keyfile}"))?;
        let bundler_url = bundler_override.map(str::to_owned).or_else(|| std::env::var("BUNDLER_URL").ok());
        Ok(Self { rpc_url, gas_key: parse32(hex.trim())?, bundler_url })
    }
}

pub struct Session {
    pub provider: DynProvider,
    pub gas_wallet: Address,
    /// Set when operations are delivered through a bundler RPC.
    pub bundler: Option<Bundler>,
    pub cfg: AgentConfig,
    pub dep: Deployments,
    pub init_data: Bytes,
    /// The agent permission described by the config (installed at creation,
    /// or the next one for a rotation).
    pub permission_data: Bytes,
    pub account: Address,
    /// `account` came from the config rather than from the factory.
    pub pinned: bool,
}

impl Session {
    pub async fn open(env: &Env, cfg: AgentConfig, base: &Path) -> Result<Self> {
        let signer = PrivateKeySigner::from_slice(&env.gas_key).context("gas wallet key")?;
        let gas_wallet = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(&env.rpc_url)
            .await
            .context("connecting to RPC")?
            .erased();

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

        // Only public keys are needed to derive the account.
        let owner_key = open_signer(&cfg.owner)?.public_key()?;
        let agent_key = open_signer(&cfg.agent)?.public_key()?;
        let perm = cfg.permission_id()?;
        let permission_data =
            kernel::permission_data(dep.agent_policy, &cfg.policy_params()?, dep.p256_signer, &agent_key);
        let init_data = kernel::init_data(dep.p256_validator, &owner_key, perm, permission_data.clone());

        let (account, pinned) = match cfg.account {
            Some(pinned) => {
                if provider.get_code_at(pinned).await?.is_empty() {
                    bail!("config pins account {pinned} but nothing is deployed there");
                }
                (pinned, true)
            }
            None => {
                let factory = IKernelFactory::new(dep.kernel_factory, provider.clone());
                (factory.getAddress(init_data.clone(), cfg.salt()?).call().await?, false)
            }
        };

        Ok(Self { provider, gas_wallet, bundler, cfg, dep, init_data, permission_data, account, pinned })
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
        println!("gas wallet:     {}", self.gas_wallet);
        println!("gas balance:    {} wei", self.provider.get_balance(self.gas_wallet).await?);
        match self.dep.whitelist_paymaster {
            Some(pm) => {
                let paymaster = IWhitelistPaymaster::new(pm, self.provider.clone());
                println!(
                    "paymaster:      {pm} (sponsored = {}, deposit = {} wei, owner = {})",
                    paymaster.sponsored(self.account).call().await?,
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

    /// Top up the paymaster's EntryPoint deposit from the gas wallet.
    pub async fn paymaster_deposit(&self, amount: U256) -> Result<B256> {
        let paymaster = IWhitelistPaymaster::new(self.paymaster()?, self.provider.clone());
        let receipt = paymaster.deposit().value(amount).send().await?.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// List (or delist) this account for sponsorship. Only the paymaster's
    /// owner — the gas wallet that deployed it — may do this.
    pub async fn sponsor(&self, allowed: bool) -> Result<B256> {
        let paymaster = IWhitelistPaymaster::new(self.paymaster()?, self.provider.clone());
        let receipt = paymaster.setSponsored(self.account, allowed).send().await?.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Stake the paymaster in the EntryPoint so public bundlers relay its
    /// operations (owner only).
    pub async fn paymaster_stake(&self, amount: U256, unstake_delay_sec: u32) -> Result<B256> {
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
        if !self.is_deployed().await? {
            let factory = IKernelFactory::new(self.dep.kernel_factory, self.provider.clone());
            let simulated = factory
                .createAccount(self.init_data.clone(), self.cfg.salt()?)
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
    pub async fn send_op(
        &self,
        target: Address,
        value: U256,
        data: Bytes,
        as_root: bool,
        sponsored: bool,
    ) -> Result<Included> {
        self.send_raw(kernel::execute_calldata(target, value, &data), as_root, sponsored).await
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
            // nothing to simulate against yet; the first call is the demo's
            return Ok(FLOOR * 2);
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
        let account = IKernel::new(self.account, self.provider.clone());
        let current = account.currentNonce().call().await?;
        let stored = account.validationConfig(kernel::permission_vid(perm)).call().await?.nonce;
        Ok(if stored == current { current + 1 } else { current })
    }

    /// Sign `call_data` in hardware and submit it through `handleOps`. The
    /// first operation carries `initCode` and deploys the account. With
    /// `sponsored`, the whitelist paymaster pays instead of the account.
    async fn send_raw(&self, call_data: Bytes, as_root: bool, sponsored: bool) -> Result<Included> {
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
            kernel::init_code(self.dep.kernel_factory, &self.init_data, self.cfg.salt()?)
        };

        let key = if as_root {
            kernel::root_nonce_key()
        } else {
            kernel::permission_nonce_key(self.cfg.permission_id()?)
        };
        let nonce = ep.getNonce(self.account, key).call().await?;
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

        let signer = open_signer(if as_root { &self.cfg.owner } else { &self.cfg.agent })?;
        let frame = |sig: &hw_signer::Signature| {
            if as_root {
                kernel::root_signature(sig)
            } else {
                kernel::permission_signature(sig)
            }
        };
        let mut user_op_hash = ep.getUserOpHash(op.clone()).call().await?;
        op.signature = frame(&signer.sign_digest(&user_op_hash.0)?);
        eprintln!("path:           {}", if as_root { "root (owner key)" } else { "permission (agent key)" });
        eprintln!("gas paid by:    {}", if sponsored { "paymaster" } else { "the account" });

        if let Some(bundler) = &self.bundler {
            // The bundler's estimate replaces ours; the hash covers the gas
            // fields, so the hardware signs once more.
            let est = bundler.estimate(&mut op).await?;
            eprintln!(
                "bundler est.:   preVerification {}, verification {}, call {}",
                est.pre_verification_gas, est.verification_gas_limit, est.call_gas_limit
            );
            user_op_hash = ep.getUserOpHash(op.clone()).call().await?;
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
                tx: receipt.receipt.transaction_hash,
                block: receipt.receipt.block_number.to::<u64>(),
                gas_used: receipt.actual_gas_used.to::<u64>(),
            });
        }
        eprintln!("userOpHash:     {user_op_hash}");
        eprintln!("delivery:       self-bundled via handleOps");

        let pending = match ep.handleOps(vec![op], self.gas_wallet).send().await {
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
    pub tx: B256,
    pub block: u64,
    pub gas_used: u64,
}
