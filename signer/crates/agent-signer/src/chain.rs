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
use anyhow::{bail, Context, Result};

use crate::abi::{IDemoCounter, IEntryPoint, IKernelFactory};
use crate::agent::{open_signer, parse32, AgentConfig, Deployments};
use crate::kernel;

/// Secrets come from the environment (optionally a `.env` file), never from
/// the agent config: `BASE_SEPOLIA_RPC_URL` (or `RPC_URL`) and
/// `GAS_WALLET_KEYFILE`, a file holding the bundler EOA's hex key.
pub struct Env {
    pub rpc_url: String,
    pub gas_key: [u8; 32],
}

impl Env {
    pub fn load(env_file: Option<&Path>) -> Result<Self> {
        if let Some(path) = env_file {
            dotenvy::from_path(path).with_context(|| format!("loading {}", path.display()))?;
        }
        let rpc_url = std::env::var("BASE_SEPOLIA_RPC_URL")
            .or_else(|_| std::env::var("RPC_URL"))
            .context("set BASE_SEPOLIA_RPC_URL or RPC_URL")?;
        let keyfile = std::env::var("GAS_WALLET_KEYFILE").context("set GAS_WALLET_KEYFILE")?;
        let hex = std::fs::read_to_string(&keyfile).with_context(|| format!("reading {keyfile}"))?;
        Ok(Self { rpc_url, gas_key: parse32(hex.trim())? })
    }
}

pub struct Session {
    pub provider: DynProvider,
    pub gas_wallet: Address,
    pub cfg: AgentConfig,
    pub dep: Deployments,
    pub init_data: Bytes,
    pub account: Address,
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

        // Only public keys are needed to derive the account.
        let owner_key = open_signer(&cfg.owner)?.public_key()?;
        let agent_key = open_signer(&cfg.agent)?.public_key()?;
        let perm = cfg.permission_id()?;
        let permission_data =
            kernel::permission_data(dep.agent_policy, &cfg.policy_params()?, dep.p256_signer, &agent_key);
        let init_data = kernel::init_data(dep.p256_validator, &owner_key, perm, permission_data);

        let factory = IKernelFactory::new(dep.kernel_factory, provider.clone());
        let account = factory.getAddress(init_data.clone(), cfg.salt()?).call().await?;

        Ok(Self { provider, gas_wallet, cfg, dep, init_data, account })
    }

    pub async fn is_deployed(&self) -> Result<bool> {
        Ok(!self.provider.get_code_at(self.account).await?.is_empty())
    }

    pub async fn print_status(&self) -> Result<()> {
        let ep = IEntryPoint::new(self.dep.entry_point, self.provider.clone());
        println!("chain:          {}", self.dep.chain_id);
        println!("kernel impl:    {}", self.dep.kernel);
        println!("account:        {}", self.account);
        println!("deployed:       {}", self.is_deployed().await?);
        println!("balance:        {} wei", self.provider.get_balance(self.account).await?);
        println!("ep deposit:     {} wei", ep.balanceOf(self.account).call().await?);
        println!("gas wallet:     {}", self.gas_wallet);
        println!("gas balance:    {} wei", self.provider.get_balance(self.gas_wallet).await?);
        println!("demo counter:   {} (count = {})", self.dep.demo_counter, self.counter().await?);
        Ok(())
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

    /// Build, sign in hardware, and submit one operation through `handleOps`.
    /// The first operation carries `initCode` and deploys the account.
    pub async fn send_op(&self, target: Address, value: U256, data: Bytes, as_root: bool) -> Result<Included> {
        let ep = IEntryPoint::new(self.dep.entry_point, self.provider.clone());
        let deployed = self.is_deployed().await?;
        if !deployed && self.provider.get_balance(self.account).await?.is_zero() {
            bail!("account {} holds no ETH to pay for its deployment; run `account fund` first", self.account);
        }
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

        let mut op = IEntryPoint::PackedUserOperation {
            sender: self.account,
            nonce,
            initCode: init_code,
            callData: kernel::execute_calldata(target, value, &data),
            accountGasLimits: kernel::pack_gas(verification_gas, 200_000),
            preVerificationGas: U256::from(100_000u64),
            gasFees: kernel::pack_gas(fees.max_priority_fee_per_gas, fees.max_fee_per_gas),
            paymasterAndData: Bytes::new(),
            signature: Bytes::new(),
        };

        let user_op_hash = ep.getUserOpHash(op.clone()).call().await?;
        let signer = open_signer(if as_root { &self.cfg.owner } else { &self.cfg.agent })?;
        let sig = signer.sign_digest(&user_op_hash.0)?;
        op.signature = if as_root { kernel::root_signature(&sig) } else { kernel::permission_signature(&sig) };
        println!("userOpHash:     {user_op_hash}");
        println!("path:           {}", if as_root { "root (owner key)" } else { "permission (agent key)" });

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
        Ok(Included {
            tx: receipt.transaction_hash,
            block: receipt.block_number.unwrap_or_default(),
            gas_used: receipt.gas_used,
        })
    }
}

/// An operation's inclusion: the bundling transaction, its block, and the
/// gas the outer transaction used.
pub struct Included {
    pub tx: B256,
    pub block: u64,
    pub gas_used: u64,
}
