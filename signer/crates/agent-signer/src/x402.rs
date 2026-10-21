//! x402 payments from the agent account (docs/ERC1271.md, "x402").
//!
//! An x402 server answers `402 Payment Required` and wants an EIP-3009
//! `TransferWithAuthorization` signed by the payer. The payer here is a smart
//! account, so the facilitator checks the signature with ERC-1271 — and
//! AgentPolicy vouches for exactly the authorizations the agent registered
//! first, in an ordinary operation held to the mandate:
//!
//! 1. register: an agent operation calls `AgentPolicy.x402Authorize(...)`;
//!    validation books its amount against the token budget;
//! 2. sign: the agent key signs the authorization digest (Kernel-wrapped);
//! 3. pay: the request is retried with the `PAYMENT-SIGNATURE` header.
//!
//! An authorization that expires unused is returned to the budget with
//! `x402 reclaim`.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::http::reqwest;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

use crate::abi::{IAgentPolicyX402, IEip3009Token, IErc1271, IKernel, X402Events};
use crate::agent::{open_signer, Role};
use crate::chain::Session;
use crate::kernel;

/// `isValidSignature` magic value.
const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
/// Shortest authorization lifetime we sign, whatever the server asks: the
/// registration has to be included before the payment can be presented.
const MIN_LIFETIME_SECS: u64 = 120;

/// One EIP-3009 authorization, as registered and as signed.
#[derive(Debug, Clone)]
pub struct Authorization {
    pub token: Address,
    pub to: Address,
    pub value: U256,
    pub valid_after: U256,
    pub valid_before: U256,
    pub nonce: B256,
}

/// What a paid request ended with.
pub struct Paid {
    pub status: u16,
    pub body: String,
    /// The decoded `PAYMENT-RESPONSE` header (settlement), if any.
    pub settlement: Option<Value>,
    pub authorization: Option<Authorization>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn header_json(resp: &reqwest::Response, name: &str) -> Result<Option<Value>> {
    let Some(h) = resp.headers().get(name) else { return Ok(None) };
    let raw = B64.decode(h.as_bytes()).with_context(|| format!("{name}: not base64"))?;
    Ok(Some(serde_json::from_slice(&raw).with_context(|| format!("{name}: not JSON"))?))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).with_context(|| format!("payment requirement without `{key}`"))
}

impl Session {
    /// The AgentPolicy module this file's permission was installed with.
    pub async fn installed_policy(&self) -> Result<Address> {
        let pc = IKernel::new(self.account, self.provider.clone())
            .permissionConfig(self.cfg.permission_id()?)
            .call()
            .await?;
        let data = pc.policyData.first().context("the permission is not installed on the account")?;
        Ok(Address::from_slice(&data[2..]))
    }

    /// GET `url`; on `402`, pay with one of the mandate's x402 tokens and
    /// retry. `max_amount` (base units) is a local guard on top of the
    /// on-chain `maxPerOp`.
    pub async fn x402_fetch(&self, url: &str, max_amount: Option<U256>, sponsored: bool) -> Result<Paid> {
        let http = reqwest::Client::new();
        let first = http.get(url).send().await.with_context(|| format!("GET {url}"))?;
        if first.status().as_u16() != 402 {
            let status = first.status().as_u16();
            return Ok(Paid { status, body: first.text().await?, settlement: None, authorization: None });
        }
        // v2 carries the requirements in a header; v1 servers in the body.
        let required = match header_json(&first, "PAYMENT-REQUIRED")? {
            Some(v) => v,
            None => first.json::<Value>().await.context("402 without PAYMENT-REQUIRED and without a JSON body")?,
        };
        if required.get("x402Version").and_then(Value::as_u64) != Some(2) {
            bail!("only x402 version 2 is supported; the server sent {}", required.get("x402Version").unwrap_or(&Value::Null));
        }
        let network = format!("eip155:{}", self.dep.chain_id);
        let accepts = required.get("accepts").and_then(Value::as_array).context("402 without `accepts`")?;
        let accepted = accepts
            .iter()
            .find(|a| {
                a.get("scheme").and_then(Value::as_str) == Some("exact")
                    && a.get("network").and_then(Value::as_str) == Some(network.as_str())
                    && a.get("asset")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse::<Address>().ok())
                        .is_some_and(|t| self.token_domains.contains_key(&t))
            })
            .with_context(|| {
                format!("no `exact` payment option on {network} in a token this mandate pays x402 in; offered: {accepts:?}")
            })?
            .clone();

        let token: Address = str_field(&accepted, "asset")?.parse()?;
        let to: Address = str_field(&accepted, "payTo")?.parse()?;
        let value: U256 = str_field(&accepted, "amount")?.parse().context("`amount`")?;
        if let Some(max) = max_amount {
            if value > max {
                bail!("the server asks {value} base units of {token}, more than --max-amount {max}");
            }
        }
        let timeout = accepted.get("maxTimeoutSeconds").and_then(Value::as_u64).unwrap_or(0);
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let auth = Authorization {
            token,
            to,
            value,
            valid_after: U256::ZERO,
            valid_before: U256::from(now() + timeout.max(MIN_LIFETIME_SECS)),
            nonce: B256::from(nonce),
        };
        eprintln!("x402:           pay {value} of {token} to {to}, valid until {}", auth.valid_before);

        // 1. register — the mandate judges it like any other operation
        let policy = self.installed_policy().await?;
        let call = IAgentPolicyX402::x402AuthorizeCall {
            token,
            from: self.account,
            to,
            value,
            validAfter: auth.valid_after,
            validBefore: auth.valid_before,
            nonce: auth.nonce,
        };
        let inc = self.send_op(policy, U256::ZERO, call.abi_encode().into(), false, sponsored, None).await?;
        eprintln!("registered:     tx {} (block {})", inc.tx, inc.block);

        // 2. sign the authorization under the permission
        let signature = self.x402_sign(&auth).await?;

        // 3. pay
        let payload = json!({
            "x402Version": 2,
            "resource": required.get("resource"),
            "accepted": accepted,
            "payload": {
                "signature": signature.to_string(),
                "authorization": {
                    "from": self.account.to_string(),
                    "to": to.to_string(),
                    "value": value.to_string(),
                    "validAfter": auth.valid_after.to_string(),
                    "validBefore": auth.valid_before.to_string(),
                    "nonce": auth.nonce.to_string(),
                },
            },
        });
        let header = B64.encode(serde_json::to_vec(&payload)?);
        let resp = http.get(url).header("PAYMENT-SIGNATURE", header).send().await?;
        let status = resp.status().as_u16();
        let settlement = header_json(&resp, "PAYMENT-RESPONSE")?;
        if status == 402 {
            // refused: the server says why in a fresh PAYMENT-REQUIRED
            if let Some(why) = header_json(&resp, "PAYMENT-REQUIRED")?.as_ref().and_then(|v| v.get("error")) {
                eprintln!("refused:        {why}");
            }
        }
        let body = resp.text().await?;
        Ok(Paid { status, body, settlement, authorization: Some(auth) })
    }

    /// The agent's ERC-1271 signature for `auth`, checked on-chain the way
    /// the facilitator will check it before it leaves this machine.
    async fn x402_sign(&self, auth: &Authorization) -> Result<Bytes> {
        let domain = *self.token_domains.get(&auth.token).context("not an x402 token of this mandate")?;
        let digest = kernel::transfer_with_authorization_digest(
            domain,
            self.account,
            auth.to,
            auth.value,
            auth.valid_after,
            auth.valid_before,
            auth.nonce,
        );
        let wrapped = kernel::kernel_wrapped_hash(self.account, self.dep.chain_id, digest);
        let sig = open_signer(&self.cfg.agent, Role::Agent)?.sign_digest(&wrapped.0)?;
        let signature = kernel::permission_1271_signature(self.cfg.permission_id()?, &sig);
        let magic = IErc1271::new(self.account, self.provider.clone())
            .isValidSignature(digest, signature.clone())
            .call()
            .await
            .context("isValidSignature reverted")?;
        if magic.0 != ERC1271_MAGIC {
            bail!("the account does not vouch for this authorization (isValidSignature = {magic}); was it registered?");
        }
        Ok(signature)
    }

    /// Return to the token budget every authorization of this permission
    /// that expired unused. Registrations are found from the policy's
    /// `X402Authorized` events since `from_block`.
    pub async fn x402_reclaim(&self, from_block: Option<u64>, sponsored: bool) -> Result<Vec<(Authorization, B256)>> {
        let policy = self.installed_policy().await?;
        let id = self.cfg.permission_id()?;
        let id32 = B256::right_padding_from(id.as_slice());
        let latest = self.provider.get_block_number().await?;
        let start = from_block.unwrap_or(latest.saturating_sub(50_000));
        let pending_sel = alloy::primitives::keccak256("x402Pending(address,bytes32,bytes32)");
        let ts = now();
        let mut done = Vec::new();
        let base = Filter::new()
            .address(policy)
            .event_signature(X402Events::X402Authorized::SIGNATURE_HASH)
            .topic1(B256::left_padding_from(self.account.as_slice()));
        let logs = scan_in_chunks(start, latest, |lo, hi| {
            let filter = base.clone().from_block(lo).to_block(hi);
            async move { Ok(self.provider.get_logs(&filter).await?) }
        })
        .await?;
        {
            for log in logs {
                let ev = X402Events::X402Authorized::decode_log_data(log.data())?;
                let auth = Authorization {
                    token: ev.token,
                    to: ev.to,
                    value: ev.value,
                    valid_after: ev.validAfter,
                    valid_before: ev.validBefore,
                    nonce: ev.nonce,
                };
                if auth.valid_before > U256::from(ts) {
                    continue; // still live: it may yet settle
                }
                let Some(domain) = self.token_domains.get(&auth.token) else { continue };
                let digest = kernel::transfer_with_authorization_digest(
                    *domain,
                    self.account,
                    auth.to,
                    auth.value,
                    auth.valid_after,
                    auth.valid_before,
                    auth.nonce,
                );
                // x402Pending(account, id, digest).value: zero when this
                // permission has no such record (another permission's, or done)
                let mut q = Vec::with_capacity(100);
                q.extend_from_slice(&pending_sel[..4]);
                q.extend_from_slice(&B256::left_padding_from(self.account.as_slice()).0);
                q.extend_from_slice(&id32.0);
                q.extend_from_slice(&digest.0);
                let tx = alloy::rpc::types::TransactionRequest::default().to(policy).input(Bytes::from(q).into());
                let out = self.provider.call(tx).await?;
                if out.len() < 32 || U256::from_be_slice(&out[..32]).is_zero() {
                    continue;
                }
                let settled = IEip3009Token::new(auth.token, self.provider.clone())
                    .authorizationState(self.account, auth.nonce)
                    .call()
                    .await?;
                if settled {
                    eprintln!("settled:        {digest} — paid, nothing to reclaim");
                    continue;
                }
                let call = IAgentPolicyX402::x402ReclaimCall {
                    id: id32,
                    token: auth.token,
                    to: auth.to,
                    value: auth.value,
                    validAfter: auth.valid_after,
                    validBefore: auth.valid_before,
                    nonce: auth.nonce,
                };
                let inc = self.send_op(policy, U256::ZERO, call.abi_encode().into(), false, sponsored, None).await?;
                eprintln!("reclaimed:      {} of {} — tx {}", auth.value, auth.token, inc.tx);
                done.push((auth, inc.tx));
            }
        }
        Ok(done)
    }
}

/// `eth_getLogs` over `[start, end]` in chunks. Public RPCs cap the block
/// range of one request (Base Sepolia's: 200 blocks), so a refused chunk is
/// halved and retried; the size that worked is kept for the next chunks.
/// Below `MIN_CHUNK` the RPC's own error is returned.
pub async fn scan_in_chunks<T, F, Fut>(start: u64, end: u64, mut fetch: F) -> Result<Vec<T>>
where
    F: FnMut(u64, u64) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>>>,
{
    const FIRST_CHUNK: u64 = 10_000;
    const MIN_CHUNK: u64 = 50;
    let mut out = Vec::new();
    let mut chunk = FIRST_CHUNK;
    let mut lo = start;
    while lo <= end {
        let hi = (lo + chunk - 1).min(end);
        match fetch(lo, hi).await {
            Ok(mut logs) => {
                out.append(&mut logs);
                lo = hi + 1;
            }
            Err(e) if chunk > MIN_CHUNK => {
                chunk = (chunk / 2).max(MIN_CHUNK);
                eprintln!("eth_getLogs refused {} blocks ({e:#}); retrying in chunks of {chunk}", hi - lo + 1);
            }
            Err(e) => return Err(e.context(format!("eth_getLogs over blocks {lo}..{hi}"))),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn shrinks_to_what_the_rpc_accepts_and_covers_every_block() {
        // A public-RPC-like cap: at most 200 blocks per request.
        let calls = RefCell::new(Vec::new());
        let blocks = block_on(scan_in_chunks(1_000, 3_499, |lo, hi| {
            calls.borrow_mut().push((lo, hi));
            async move {
                if hi - lo + 1 > 200 {
                    bail!("block range too large");
                }
                Ok((lo..=hi).collect::<Vec<u64>>())
            }
        }))
        .unwrap();
        assert_eq!(blocks, (1_000..=3_499).collect::<Vec<u64>>(), "every block once, in order");
        let accepted: Vec<_> = calls.borrow().iter().copied().filter(|(lo, hi)| hi - lo + 1 <= 200).collect();
        assert!(accepted.iter().all(|(lo, hi)| hi - lo + 1 <= 200));
        // after shrinking it stays shrunk: no request above the cap once one was accepted
        let first_ok = calls.borrow().iter().position(|(lo, hi)| hi - lo + 1 <= 200).unwrap();
        assert!(calls.borrow()[first_ok..].iter().all(|(lo, hi)| hi - lo + 1 <= 200));
    }

    #[test]
    fn a_permanent_failure_is_reported() {
        let err = block_on(scan_in_chunks::<u64, _, _>(0, 100, |_, _| async { bail!("rpc down") })).unwrap_err();
        assert!(format!("{err:#}").contains("rpc down"));
    }

    #[test]
    fn an_unrestricted_rpc_takes_one_request_per_10k() {
        let calls = RefCell::new(0);
        let n = block_on(scan_in_chunks(0, 24_999, |lo, hi| {
            *calls.borrow_mut() += 1;
            async move { Ok(vec![(lo, hi)]) }
        }))
        .unwrap()
        .len();
        assert_eq!((n, *calls.borrow()), (3, 3));
    }
}
