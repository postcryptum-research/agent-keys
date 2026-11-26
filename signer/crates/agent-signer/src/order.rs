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
//!
//! A swap is the other kind of venue: a call the account makes itself, at a
//! router, in the same operation that registers it. `order swap` sends both
//! as one operation; nothing is left to be filled later. `order call` does
//! the same for a call at a venue of rules, where the owner wrote a rule for
//! every argument word of each function the agent may call.

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::abi::{IErc1271, IErc20Allowance};
use rand_core::{OsRng, RngCore};

use crate::agent::{open_signer, Role, VenueEntry, VenueKind};
use crate::chain::{ask_again, Session, VenueOnChain, ASK_AGAIN, ASK_EVERY};
use crate::kernel::{self, CowSellOrder, OneInchOrder, SwapOrder};

const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// An order in its venue's own form.
pub enum VenueOrder {
    Cow(CowSellOrder),
    OneInch(OneInchOrder),
}

/// A swap as the chain has it.
pub struct Swapped {
    pub tx: B256,
    pub block: u64,
    /// The amount sold, as asked.
    pub sold: U256,
    /// By how much the account's balance of the bought token grew in the swap's block.
    pub bought: U256,
    /// The least the router was told to pay, or revert.
    pub least: U256,
    /// The router the swap was made at: the venue's own contract.
    pub router: Address,
}

impl Swapped {
    pub fn json(&self) -> Value {
        json!({
            "tx": self.tx.to_string(),
            "block": self.block,
            "sold": self.sold.to_string(),
            "bought": self.bought.to_string(),
            "leastBought": self.least.to_string(),
            "router": self.router.to_string(),
        })
    }
}

/// A call at a venue of rules as the chain has it.
pub struct Called {
    pub tx: B256,
    pub block: u64,
    /// The contract the call was made at: the venue's own.
    pub venue: Address,
    /// The token the call's charged word is in; zero where its function charges nothing.
    pub token: Address,
    /// The amount charged to that token's budget.
    pub charged: U256,
}

impl Called {
    pub fn json(&self) -> Value {
        json!({
            "tx": self.tx.to_string(),
            "block": self.block,
            "venue": self.venue.to_string(),
            "chargedToken": self.token.to_string(),
            "charged": self.charged.to_string(),
        })
    }
}

/// A registered order, ready for the venue.
pub struct Placed {
    pub order: VenueOrder,
    pub digest: B256,
    pub signature: Bytes,
    pub tx: B256,
    pub account: Address,
}

impl Placed {
    /// The order as its venue takes it.
    pub fn json(&self) -> Value {
        match &self.order {
            VenueOrder::Cow(o) => self.cow_json(o),
            VenueOrder::OneInch(o) => self.one_inch_json(o),
        }
    }

    /// As 1inch's order book takes an order (`POST /orderbook/v4.1/<chain>`):
    /// its hash, the signature and the eight fields, with no extension.
    /// `order` is the same eight words ABI-encoded, for a taker that fills at
    /// the router itself (`fillContractOrder(order, signature, makingAmount, 1 << 255)`).
    fn one_inch_json(&self, o: &OneInchOrder) -> Value {
        json!({
            "orderHash": self.digest.to_string(),
            "signature": self.signature.to_string(),
            "data": {
                "salt": o.salt.to_string(),
                "maker": o.maker.to_string(),
                "receiver": Address::ZERO.to_string(),
                "makerAsset": o.maker_asset.to_string(),
                "takerAsset": o.taker_asset.to_string(),
                "makingAmount": o.making_amount.to_string(),
                "takingAmount": o.taking_amount.to_string(),
                "makerTraits": o.traits().map(|t| t.to_string()),
                "extension": "0x",
            },
            "order": o.encode().map(|b| b.to_string()),
            "expiration": o.expiration,
            "registeredIn": self.tx.to_string(),
        })
    }

    /// As CoW's order book takes an order (`POST /api/v1/orders`). Its uid
    /// is digest ‖ owner ‖ validTo.
    fn cow_json(&self, o: &CowSellOrder) -> Value {
        let uid: Bytes = [self.digest.as_slice(), self.account.as_slice(), &o.valid_to.to_be_bytes()].concat().into();
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
            "uid": uid.to_string(),
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

    /// A sale against the config's terms and the account's funds, before
    /// anything is signed: the pair is listed, the price is not under its
    /// lowest, something is sold, and the venue's allowance and the
    /// account's balance cover it. `what` is "order" or "swap".
    async fn check_sale(
        &self,
        v: &VenueEntry,
        on: &VenueOnChain,
        what: &str,
        sell_token: Address,
        buy_token: Address,
        sell_amount: U256,
        buy_amount: U256,
    ) -> Result<()> {
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
            bail!("an {what} that sells nothing");
        }
        let token = IErc20Allowance::new(sell_token, self.provider.clone());
        let allowed = token.allowance(self.account, on.spender).call().await.context("reading the venue's allowance")?;
        if allowed < sell_amount {
            bail!(
                "the account lets the venue's spender {} take {allowed} of {sell_token}, less than this {what} sells: the owner gives the allowance with the mandate and renews it with `permission allowance`",
                on.spender
            );
        }
        let balance = token.balanceOf(self.account).call().await.context("reading the account's balance")?;
        if balance < sell_amount {
            bail!("the account holds {balance} of {sell_token}, less than this {what} sells");
        }
        Ok(())
    }

    /// Swap at a router under the mandate, at a venue of kind `uniswap`: one
    /// operation of two calls, the swap's registration with the policy and
    /// the router call the venue's decoder builds (`SwapRouter02Decoder`):
    /// the bought token to the account, no native value, no price limit.
    /// The policy admits that call only as the leg after its registration.
    ///
    /// Checked here first against the config's terms; the policy's own check
    /// is the one that counts. The amount sold is charged to the token's
    /// budget when the operation is validated: a swap that reverts when it
    /// runs (the market moved under `buy_amount`) was charged all the same,
    /// and the charge returns when the budget period turns. The operation's
    /// calls are run before anything is sent, so a swap that would revert
    /// now is found then and costs nothing; one that reverts because the
    /// pool moved in between is the case that is charged.
    pub async fn order_swap(
        &self,
        decoder: Option<Address>,
        sell_token: Address,
        buy_token: Address,
        sell_amount: U256,
        buy_amount: U256,
        fee: u32,
        sponsored: bool,
    ) -> Result<Swapped> {
        let (v, on) = self.venue(decoder)?;
        match v.kind {
            VenueKind::Uniswap => {}
            VenueKind::Rules => bail!("the venue {} takes calls, not swaps: `order call`", v.decoder),
            VenueKind::Cowswap | VenueKind::OneInch => bail!("the venue {} takes orders, not swaps: `order sell`", v.decoder),
        }
        let config = v.config()?;
        self.check_sale(v, on, "swap", sell_token, buy_token, sell_amount, buy_amount).await?;
        let swap = SwapOrder { token_in: sell_token, token_out: buy_token, fee, amount_in: sell_amount, amount_out_minimum: buy_amount };
        let fits = "the fee tier does not fit the router's 24 bits";
        let (encoded, call) = (swap.encode().context(fits)?, swap.call(self.account).context(fits)?);
        // The decoder's own word on the call: it builds the bytes the policy
        // will hold the next leg to. Other bytes here would be refused there,
        // after the gas was spent on finding out.
        let d = crate::abi::IVenueDecoder::new(v.decoder, self.provider.clone());
        let theirs = d.swapCall(self.account, encoded.clone()).call().await.context("asking the venue's decoder for the swap's call")?;
        if theirs != call {
            bail!("the decoder {} builds another call for this swap than this tool does: nothing was sent", v.decoder);
        }
        eprintln!("swap:           sell {sell_amount} of {sell_token} for at least {buy_amount} of {buy_token}, in the pool of fee tier {fee}");

        let policy = self.installed_policy().await?;
        let bought = IErc20Allowance::new(buy_token, self.provider.clone());
        let before = bought.balanceOf(self.account).call().await.context("reading the account's balance of the bought token")?;
        // the registration, then the call it admits: two legs of one operation
        let batch = vec![(policy, U256::ZERO, kernel::order_register_calldata(v.decoder, &config, &encoded)), (on.place, U256::ZERO, call)];
        let inc = self
            .send_batch(batch, false, sponsored, None)
            .await
            .context("the swap was not made. If nothing was sent (the calls were run first and one reverted, or the mandate refused), nothing was charged. If the operation was included and its execution reverted, the amount sold was charged to the token's budget all the same, and returns when the budget period turns")?;
        // the receipt's node has the block; another may lag behind it
        let mut after = None;
        for _ in 0..15 {
            if let Ok(b) = bought.balanceOf(self.account).block(alloy::eips::BlockId::number(inc.block)).call().await {
                after = Some(b);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        let after = after.with_context(|| format!("the swap is in tx {} (block {}), and no node served that block within 15 s to read what was bought", inc.tx, inc.block))?;
        Ok(Swapped { tx: inc.tx, block: inc.block, sold: sell_amount, bought: after.saturating_sub(before), least: buy_amount, router: on.place })
    }

    /// A call at a venue of rules (kind `rules`, `CallRulesDecoder`): one
    /// operation of two calls, the call's registration with the policy and
    /// the call itself, at the venue's one contract. The decoder holds every
    /// argument word of `data` to the owner's rule for it.
    ///
    /// The decoder is asked first, so that a call the rules refuse costs no
    /// operation; the policy asks it again, and that is the check that
    /// counts. Where the function charges a word, the amount is charged to
    /// the token's budget when the operation is validated: a call that
    /// reverts when it runs was charged all the same, and the charge returns
    /// when the budget period turns.
    pub async fn order_call(&self, decoder: Option<Address>, data: Bytes, sponsored: bool) -> Result<Called> {
        let (v, on) = self.venue(decoder)?;
        if v.kind != VenueKind::Rules {
            bail!("the venue {} is not a venue of rules: `order sell` places an order, `order swap` makes a swap", v.decoder);
        }
        let config = v.config()?;
        let d = crate::abi::IVenueDecoder::new(v.decoder, self.provider.clone());
        let judged = d
            .judge(self.account, config.clone(), data.clone())
            .call()
            .await
            .with_context(|| format!("the rules of the venue {} refuse this call: its function is not listed, it is not as long as its rules, or an argument does not pass its rule", v.decoder))?;
        // what the function charges, if it charges: the venue's allowance and the account's balance cover it
        if !judged.mostSold.is_zero() {
            let token = IErc20Allowance::new(judged.sellToken, self.provider.clone());
            let allowed = token.allowance(self.account, on.spender).call().await.context("reading the venue's allowance")?;
            if allowed < judged.mostSold {
                bail!(
                    "the account lets the venue's spender {} take {allowed} of {}, less than this call is charged: the owner gives the allowance with the mandate and renews it with `permission allowance`",
                    on.spender,
                    judged.sellToken
                );
            }
            let balance = token.balanceOf(self.account).call().await.context("reading the account's balance")?;
            if balance < judged.mostSold {
                bail!("the account holds {balance} of {}, less than this call is charged", judged.sellToken);
            }
        }
        eprintln!("call:           {} bytes to {}, charged {} of {}", data.len(), on.place, judged.mostSold, judged.sellToken);

        let policy = self.installed_policy().await?;
        // the registration, then the call it admits: two legs of one operation
        let batch = vec![(policy, U256::ZERO, kernel::order_register_calldata(v.decoder, &config, &data)), (on.place, U256::ZERO, data)];
        let inc = self
            .send_batch(batch, false, sponsored, None)
            .await
            .context("the call was not made. If nothing was sent (the calls were run first and one reverted, or the mandate refused), nothing was charged. If the operation was included and its execution reverted, what the call is charged was charged to the token's budget all the same, and returns when the budget period turns")?;
        Ok(Called { tx: inc.tx, block: inc.block, venue: on.place, token: judged.sellToken, charged: judged.mostSold })
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
        match v.kind {
            VenueKind::Uniswap => bail!("the venue {} takes swaps, not orders: `order swap`", v.decoder),
            VenueKind::Rules => bail!("the venue {} takes calls, not orders: `order call`", v.decoder),
            VenueKind::Cowswap | VenueKind::OneInch => {}
        }
        self.check_sale(v, on, "order", sell_token, buy_token, sell_amount, buy_amount).await?;
        if valid_for == 0 || valid_for > v.max_life {
            bail!("an order may live at most {} s under this mandate (--valid-for {valid_for})", v.max_life);
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
        // the order in its venue's form, the bytes its decoder reads, and the digest the venue will ask for
        let (order, encoded, digest) = match v.kind {
            VenueKind::Cowswap => {
                let app_data = v.app_data.context("the CoW Swap venue names no `appData`")?;
                let o = CowSellOrder { sell_token, buy_token, sell_amount, buy_amount, valid_to, app_data };
                let (encoded, digest) = (o.encode(), o.digest(on.domain));
                (VenueOrder::Cow(o), encoded, digest)
            }
            VenueKind::OneInch => {
                // The router keeps one bit per maker and nonce for an order
                // filled whole: two live orders of one nonce would fill once
                // between them. So a nonce from the system's random source,
                // one whose bit the router still has clear.
                let d = crate::abi::IVenueDecoder::new(v.decoder, self.provider.clone());
                let mut found = None;
                for _ in 0..8 {
                    let (mut salt, mut nonce) = ([0u8; 32], [0u8; 8]);
                    OsRng.fill_bytes(&mut salt);
                    OsRng.fill_bytes(&mut nonce[3..]);
                    let o = OneInchOrder {
                        salt: U256::from_be_bytes(salt),
                        maker: self.account,
                        maker_asset: sell_token,
                        taker_asset: buy_token,
                        making_amount: sell_amount,
                        taking_amount: buy_amount,
                        expiration: u64::from(valid_to),
                        nonce: u64::from_be_bytes(nonce),
                    };
                    let encoded = o.encode().context("the order's expiration does not fit a 1inch order")?;
                    if d.untouched(self.account, encoded.clone()).call().await.context("reading the order's bit at the router")? {
                        let digest = o.digest(on.domain).context("the order's expiration does not fit a 1inch order")?;
                        found = Some((VenueOrder::OneInch(o), encoded, digest));
                        break;
                    }
                }
                found.context("eight random nonces were all used at the router: try again")?
            }
            VenueKind::Uniswap => bail!("the venue {} takes swaps, not orders: `order swap`", v.decoder),
            VenueKind::Rules => bail!("the venue {} takes calls, not orders: `order call`", v.decoder),
        };
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
        let call = kernel::order_register_calldata(v.decoder, &config, &encoded);
        let inc = self.send_op(policy, U256::ZERO, call, false, sponsored, None).await?;
        eprintln!("registered:     tx {} (block {})", inc.tx, inc.block);

        // 3. ask the account the way the venue will; a refusal is asked again
        // for a while, since the node that answers may not have the block yet
        let erc1271 = IErc1271::new(self.account, self.provider.clone());
        let magic = ask_again(
            || {
                let (erc1271, signature) = (&erc1271, signature.clone());
                async move { erc1271.isValidSignature(digest, signature).call().await }
            },
            |answer| matches!(answer, Ok(m) if m.0 == ERC1271_MAGIC),
            ASK_AGAIN,
            ASK_EVERY,
        )
        .await
        .context("isValidSignature reverted")?;
        if magic.0 != ERC1271_MAGIC {
            bail!("the account does not vouch for this order (isValidSignature = {magic}), although it is registered (tx {}) and charged to the budget: it comes back with `order reclaim` after its end ({valid_to})", inc.tx);
        }
        Ok(Placed { order, digest, signature, tx: inc.tx, account: self.account })
    }
}
