# Related products and projects

What else exists next to TPM_sign, and how it compares. Written so that a
reader can tell, for any product, **where the key lives**, **who enforces the
spending rules**, and **what it would take to reuse it here**.

| Page | What it covers |
|---|---|
| [`CUPCAKE.md`](CUPCAKE.md) | Cake Wallet's Cupcake — "your old phone as a hardware wallet" — read from its source: what it actually does, and where the marketing and the code differ |
| [`LANDSCAPE.md`](LANDSCAPE.md) | the wider field: other old-phone and air-gapped signers; agent-wallet products (TEE and MPC custodians, on-chain policy modules); device-key P-256 smart accounts; the open-source projects closest to TPM_sign; the Circle Agent Wallets case (I-HITL) |
| [`BTCPAY.md`](BTCPAY.md) | BTCPay Server's hot-wallet sweep (2026-11): every integration option, which ones fit this project (a USDC-on-Base plugin with a mandate-bounded store wallet, #13) and which need a server TEE and belong elsewhere |
| [`INCIDENTS.md`](INCIDENTS.md) | the ledger of incidents that argue for the design (DarkSword on iOS, Circle Agent Wallets, BTCPay): root cause, where the key lived, what TPM_sign answers and what it does not |

Evidence marks, as in `HARDWARE_WISHLIST.md`: **V** — verified at the linked
source (or read in the code); **I** — inferred from documentation or product
descriptions, not tested. Dates are when the page was researched; products
move fast.
