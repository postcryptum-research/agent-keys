# ChatGPT Wallet (OpenAI, 2026-11): how the card networks bound an agent that pays

*Researched 2026-11-17. The question: how does this product solve the
problem agent-keys solves, an agent that pays within a mandate? Where is the
mandate, where is the agent's credential, who can stop it. And the owner's
hypothesis to test: perhaps it does not solve it at all, which would make
it the next candidate for an adaptation like those in `examples/`.*

Marks: **V** read at the linked primary source; **I** from press or a
secondary source. OpenAI's announcement, help article and terms refused
automated reading (HTTP 403), so everything attributed to them is **I**,
through the press that quotes them. OpenAI's developer pages and Visa's
developer pages were read directly.

## 1. Answer

**It does solve it, by other means. The hypothesis is not supported.**

- At launch there is no standing mandate to bound: **every purchase is
  approved by the user with a biometric check on their own device** (I),
  and the agent is then handed a payment token **for that one
  transaction** (I). The agent never holds the card.
- The limit is not kept by OpenAI's service alone. The token is issued and
  checked by the **card network**, a party the agent's host does not
  control. That is the place `AgentPolicy` has in our design, held by a
  trusted company instead of a contract.
- The standing mandate, which is our case proper, is announced and not
  shipped: purchases pre-approved within spending, category or time limits,
  "with enhanced safeguards" (I). The networks' specifications for it
  exist (§3).

So this is not a stack with a key in a file whose wallet layer we could
replace. What it leaves open, and the one place our work could touch it,
are in §5 and §6.

## 2. What was launched

- 2026-11-13, with American Express, Mastercard and Visa (one report adds
  Chase). US only, Pro subscribers over 18, US-issued credit cards; no
  debit or virtual cards (I).
- Only in conversations with "dots", OpenAI's always-on agents. The dot
  shops in **OpenAI's cloud browser**, through the merchant's ordinary
  checkout page; no integration is asked of the merchant (V, developer
  pages).
- The user saves a card once. For each purchase they review items, total
  and card, and approve with Face ID or a fingerprint; a device without
  biometrics approves through a link or QR code on one that has them (I).
- After approval "payment networks give the dot a payment token with a
  scoped card number, security code, and expiration date tied to a single
  transaction" (I, CNBC). The merchant receives a **network token**, links
  it to the account by the Payment Account Reference, and is told the
  customer "consents only to the specific transaction", so the credential
  must not be saved or reused (V).
- Card rewards and dispute rights stay as for any card purchase; OpenAI
  takes no cut at launch (I).
- The merchant recognises the agent's browser by **Web Bot Auth**: HTTP
  Message Signatures (RFC 9421), `Signature-Agent: "https://chatgpt.com"`,
  public keys at `chatgpt.com/.well-known/http-message-signatures-directory`
  (V). The signature says "this request is from ChatGPT". It says nothing
  about the user or the purchase (V), and where the private key is kept is
  not stated.
- Known weak point by OpenAI's own account: merchants' bot and fraud
  filters decline legitimate agent purchases; United and Amazon block
  agents outright (I).

## 3. The rails underneath

OpenAI does not say which network programs carry the Wallet. The fit with
the two below is our inference (I); what the programs themselves say is V
for Visa and I for Mastercard.

**Visa Intelligent Commerce** (V, developer documentation):
- A **payment instruction** is "the agreed purchase intent between
  consumer and agent"; the consumer authorizes it with an authentication
  recorded as assurance data: FIDO2 biometric or device-based, app-based,
  one-time passcode, or a token-service step-up. Visa Payment Passkeys are
  the FIDO path.
- An instruction holds up to 10 **mandates**: a decline threshold (per
  transaction and in total), an expiry, an optional merchant name, an
  optional recurrence. No endpoint modifies one: cancel and create anew.
  The default expiry is 30 days.
- The agent asks Visa for a credential per purchase and gets a network
  token with a **single-use cryptogram, valid 72 hours**. Visa checks the
  request against the instruction before it answers. At most 15
  cryptograms per token in 24 hours.
- The agent's side authenticates with mutual TLS and, for registered
  providers, a signature over each credential request with its own key
  (**Ed25519, RS256 or ES256**), checked against Visa's agent registry.
  Where that key is kept is the provider's business.
- The issuer or Visa can revoke the token at any time, without notice to
  the agent.

**Mastercard Agent Pay** (I): Agentic Tokens on the same tokenization as
contactless wallets, and **Verifiable Intent**, a signed record of what
the human authorized: an SD-JWT chain issuer → user → agent with amount
bounds, merchant allow-lists, budget caps and recurrence (V for the
outline, at verifiableintent.dev: draft v0.1; contributed to the FIDO
Alliance in 2026-04, I). Not yet part of Agent Pay's interfaces at the
time of the sources (I).

## 4. Side by side

| | ChatGPT Wallet at launch | agent-keys |
|---|---|---|
| What is bounded | one purchase per approval | a standing mandate: targets, cap per operation, budget, expiry |
| Who enforces | the card network and the issuer | the `AgentPolicy` contract |
| What the agent holds | a token for one transaction; no card | a P-256 key in hardware that cannot be exported |
| If the agent's host is taken over | nothing to spend without a new approval; the token in hand buys the approved purchase | the attacker spends inside the mandate while present, until the owner revokes |
| How the owner approves | a biometric on their device, per purchase (a passkey, if the Visa path is the one used: I) | the owner's hardware key, once per mandate |
| Can the agent read the approval channel | no: a biometric, not a code in a mailbox | no: a key the agent's host does not hold |
| Who can stop it | the issuer and the network; the user through them and through OpenAI (how, not read) | the owner, on-chain, and nobody else |
| After a wrong payment | chargeback: the payment can be reversed | none: a transfer is final; the bound is all there is |
| Who may use it | OpenAI's own agents, US, credit cards | any agent on a machine with a supported key store, EVM networks with the contracts |
| Trust | OpenAI, the network, the issuer, the merchant's processor | the contracts and the key stores |

The Circle Agent Wallets failure (`INCIDENTS.md`: the agent read the
e-mailed code and raised its own cap) does not carry over: the limit is
with the network, and the approval is a biometric the agent cannot
produce. In that respect it is the same answer as ours, reached from the
other side.

## 5. What it does not settle

Stated as open, not as faults found; none of it was tested.

1. **What the biometric approves.** The review screen is OpenAI's. Whether
   the passkey assertion is bound to the amount and merchant shown, and
   who checks that binding, is not in anything we could read. It is our T1
   and T5 (the owner is shown one operation and approves another), with
   the app's vendor in the place of the phone's operating system.
2. **The merchant check is a name.** Visa compares the transaction's
   merchant name with the one in the mandate. That is weaker than an
   address in an allow-list.
3. **The standing mandate.** Once purchases are pre-approved, the agent's
   own credential starts to matter: whoever can sign credential requests
   as the agent can spend inside the mandates. For the Wallet that key is
   in OpenAI's cloud, and nothing says how it is kept. It is then the
   position of our agent key, with the network in the place of the
   contract.
4. **Revocation by the user** was not readable (the help article). The
   issuer's and the network's revocation is documented.

## 6. For agent-keys

- **In scope: nothing to build.** The product is closed, runs OpenAI's
  agents only, and holds no key that we could move into hardware from the
  outside. It is not a candidate for `examples/`.
- **What it confirms.** The two rules the design rests on are the ones the
  card networks chose: the limit lives with a party the agent's host does
  not control, and the approval comes from a device key the agent cannot
  reach. The difference is who that party is, and that their payments can
  be reversed while ours cannot.
- **One point of contact, not verified and not proposed.** Visa accepts
  ES256, which is P-256, for the agent's request signature, and RFC 9421
  allows `ecdsa-p256-sha256` for Web Bot Auth. An independent agent
  provider on those rails could keep that signing key in a TPM with the
  `hw-signer` crate as it is. That would be a different product from this
  one (card rails, no account abstraction), and only worth a look if the
  owner wants the signer used outside EVM.
- **For the comparison table in `LANDSCAPE.md`.** It belongs in a class
  that page does not have yet: the mandate held by a payment network, not
  by a vendor's service (§2a there) and not by a contract (§2b).

## 7. Sources

Press, for OpenAI's own statements:
[CNBC, 2026-11-13](https://www.cnbc.com/2026/11/13/openai-chatgpt-wallet-dot-purchases.html),
[Digital Commerce 360, 2026-11-16](https://www.digitalcommerce360.com/2026/11/16/openai-chatgpt-wallet-for-ai-purchases-through-retailer-checkouts/),
[Decrypt](https://decrypt.co/383278/openai-chatgpt-wallet-ai-agents-shop-without-crypto).
OpenAI, not readable by us:
[the announcement](https://openai.com/index/introducing-chatgpt-wallet/),
[the help article](https://help.openai.com/en/articles/20001654-making-purchases-with-chatgpt-wallet),
[the terms](https://openai.com/policies/chatgpt-wallet-terms/).
OpenAI, read:
[Accept payments](https://developers.openai.com/commerce/guides/accept-payments),
[Agent Access](https://developers.openai.com/commerce/agent-access),
[cloud browser access](https://developers.openai.com/commerce/guides/enable-browser-access).
Networks:
[Visa Intelligent Commerce, concepts](https://developer.visa.com/docs/visa-intelligent-commerce/concepts),
[Verifiable Intent](https://verifiableintent.dev)
([source](https://github.com/agent-intent/verifiable-intent)),
[Mastercard on Verifiable Intent](https://www.mastercard.com/global/en/news-and-trends/stories/2026/verifiable-intent.html)
(not readable by us).
