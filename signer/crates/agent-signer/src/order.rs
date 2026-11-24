//! Orders at a trading venue under the mandate (issue #80).
//!
//! An order is not a call the agent makes at the venue. The agent registers
//! it with the policy (`AgentPolicy.orderRegister`): the policy asks the
//! venue's decoder whether the order is within the owner's terms, charges
//! the sold amount to the token's budget, and from then on the account
//! vouches for exactly that order when the venue asks (ERC-1271). The venue
//! takes the tokens through the allowance the owner gave with the mandate.
//!
//! `order sell` registers an order and prints it with the agent's signature,
//! in the form the venue's order book takes. It sends it nowhere: handing the
//! order to an order book is what makes it live.

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::sol_types::SolEvent;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::abi::{IAgentPolicyTrading, IErc1271, IErc20Allowance};
use crate::agent::{open_signer, Role, VenueEntry};
use crate::chain::{Session, VenueOnChain};
use crate::kernel::{self, CowSellOrder};

const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// A registered order, ready for the venue.
pub struct Placed {
    pub order: CowSellOrder,
    pub digest: B256,
    /// CoW's order uid: digest ‖ owner ‖ validTo.
    pub uid: Bytes,
    pub signature: Bytes,
    pub tx: B256,
    pub account: Address,
}

impl Placed {
    /// The order as CoW's order book takes it (`POST /api/v1/orders`).
    pub fn json(&self) -> Value {
        let o = &self.order;
        json!({
            "sellToken": o.sell_token.to_string(),
            "buyToken": o.buy_token.to_string(),
            "receiver": Address::ZERO.to_string(),
            "sellAmount": o.sell_amount.to_string(),
            "buyAmount": o.buy_amount.to_string(),
            "validTo": o.valid_to,
            "appData": o.app_data.to_string(),
            "feeAmount": "0",
            "kind": "sell",
            "partiallyFillable": false,
            "sellTokenBalance": "erc20",
            "buyTokenBalance": "erc20",
            "signingScheme": "eip1271",
            "signature": self.signature.to_string(),
            "from": self.account.to_string(),
            "uid": self.uid.to_string(),
            "registeredIn": self.tx.to_string(),
        })
    }
}

impl Session {
    /// The config's venue: the named one, or the only one.
    fn venue(&self, decoder: Option<Address>) -> Result<(&VenueEntry, &VenueOnChain)> {
        let venues = &self.cfg.policy.venues;
        let v = match decoder {
            Some(d) => venues.iter().find(|v| v.decoder == d).with_context(|| format!("{d} is not a venue decoder of this config"))?,
            None if venues.len() == 1 => &venues[0],
            None if venues.is_empty() => bail!("the config's mandate has no `venues`"),
            None => bail!("the config has several venues: name one with --venue <decoder>"),
        };
        Ok((v, self.venues.get(&v.decoder).context("venue not read from the chain")?))
    }

    /// Register a sell order under the mandate and sign it. Checked here
    /// first against the config's terms, so that an order the policy would
    /// refuse costs no operation; the policy's own check is the one that
    /// counts.
    pub async fn order_sell(
        &self,
        decoder: Option<Address>,
        sell_token: Address,
        buy_token: Address,
        sell_amount: U256,
        buy_amount: U256,
        valid_for: u32,
        sponsored: bool,
    ) -> Result<Placed> {
        let (v, on) = self.venue(decoder)?;
        let config = v.config()?;
        let pair = v
            .pairs
            .iter()
            .find(|p| p.sell_token == sell_token && p.buy_token == buy_token)
            .with_context(|| format!("selling {sell_token} for {buy_token} is not a pair of this mandate"))?;
        let (min_buy, per_sell): (U256, U256) = (pair.min_buy.parse().context("minBuy")?, pair.per_sell.parse().context("perSell")?);
        let enough = match (buy_amount.checked_mul(per_sell), sell_amount.checked_mul(min_buy)) {
            (Some(offered), Some(least)) => offered >= least,
            _ => bail!("the amounts are too large to compare with the lowest price"),
        };
        if !enough {
            bail!("{buy_amount} for {sell_amount} is below the mandate's lowest price ({min_buy} per {per_sell})");
        }
        if sell_amount.is_zero() {
            bail!("an order that sells nothing");
        }
        if valid_for == 0 || valid_for > v.max_life {
            bail!("an order may live at most {} s under this mandate (--valid-for {valid_for})", v.max_life);
        }
        let token = IErc20Allowance::new(sell_token, self.provider.clone());
        let allowed = token.allowance(self.account, on.spender).call().await.context("reading the venue's allowance")?;
        if allowed < sell_amount {
            bail!(
                "the account lets the venue's spender {} take {allowed} of {sell_token}, less than this order sells: the owner gives the allowance with the mandate and renews it with `permission allowance`",
                on.spender
            );
        }
        let balance = token.balanceOf(self.account).call().await.context("reading the account's balance")?;
        if balance < sell_amount {
            bail!("the account holds {balance} of {sell_token}, less than this order sells");
        }

        // Under a budget per period an order ends with the period it is
        // charged in: the policy refuses one that could be filled later.
        let now = self.chain_time().await?;
        let mut until = now.checked_add(u64::from(valid_for)).context("the order's last second does not fit a timestamp")?;
        if let Some(next) = self.period_next().await? {
            const LEAST_LIFE_SECS: u64 = 60;
            // the period's seconds left; none if the chain's clock is already past its end
            let left = next.saturating_sub(now);
            if left <= LEAST_LIFE_SECS {
                bail!("this budget period ends in {left} s, and an order ends with the period it is charged in: place it after the renewal");
            }
            let last = next.saturating_sub(1);
            if until > last {
                until = last;
                eprintln!("order:          lives {} s, to the end of this budget period, not the {valid_for} s asked for", until.saturating_sub(now));
            }
        }
        let valid_to = u32::try_from(until).context("validTo")?;
        let order = CowSellOrder { sell_token, buy_token, sell_amount, buy_amount, valid_to, app_data: v.app_data };
        let digest = order.digest(on.domain);
        eprintln!("order:          sell {sell_amount} of {sell_token} for at least {buy_amount} of {buy_token}, until {valid_to}");

        let policy = self.installed_policy().await?;
        // An order is its digest: the same amounts until the same second are
        // the same order, and the policy registers one once.
        let mut q = alloy::primitives::keccak256("x402Pending(address,bytes32,bytes32)")[..4].to_vec();
        q.extend_from_slice(&B256::left_padding_from(self.account.as_slice()).0);
        q.extend_from_slice(&B256::right_padding_from(self.cfg.permission_id()?.as_slice()).0);
        q.extend_from_slice(&digest.0);
        let pending = self.provider.call(TransactionRequest::default().to(policy).input(Bytes::from(q).into())).await?;
        if pending.len() >= 32 && !U256::from_be_slice(&pending[..32]).is_zero() {
            bail!("this order (the same tokens and amounts, until {valid_to}) is already registered under the mandate: an order differs by an amount or by its lifetime (--valid-for)");
        }
        // 1. sign it under the permission first: the signature does not depend on
        // the registration, and a signer that fails then has charged nothing
        let wrapped = kernel::kernel_wrapped_hash(self.account, self.dep.chain_id, digest);
        let sig = open_signer(&self.cfg.agent, Role::Agent)?.sign_digest(&wrapped.0)?;
        let signature = kernel::permission_1271_signature(self.cfg.permission_id()?, &sig);

        // 2. register: the mandate judges it like any other operation
        let call = kernel::order_register_calldata(v.decoder, &config, &order.encode());
        let inc = self.send_op(policy, U256::ZERO, call, false, sponsored, None).await?;
        eprintln!("registered:     tx {} (block {})", inc.tx, inc.block);

        // 3. ask the account the way the venue will
        let magic = IErc1271::new(self.account, self.provider.clone())
            .isValidSignature(digest, signature.clone())
            .call()
            .await
            .context("isValidSignature reverted")?;
        if magic.0 != ERC1271_MAGIC {
            bail!("the account does not vouch for this order (isValidSignature = {magic}), although it is registered (tx {}) and charged to the budget: it comes back with `order reclaim` after its end ({valid_to})", inc.tx);
        }
        let uid = [digest.as_slice(), self.account.as_slice(), &valid_to.to_be_bytes()].concat().into();
        Ok(Placed { order, digest, uid, signature, tx: inc.tx, account: self.account })
    }
}
