# Incidents that argue for the design

*The owner's collection of facts: real losses whose root cause is something
this project's architecture removes, and the honest line of what it does
not remove. One row per incident, the details and sources below. Started
2026-11-04. Marks: **V** verified at the linked source; **I** inferred from
press or secondary reports; figures are quoted with their attribution and
are never ours.*

To add one: a row in the ledger, a short note with the primary source, and,
when the case deserves it, a full page next to this one (`BTCPAY.md`,
`LANDSCAPE.md` §2a for Circle). Say what the design answers and what it does
not; the second column is what makes the page worth reading.

## 1. The ledger

| When | What happened | Root cause | Where the key lived | What agent-keys answers | What it does not |
|---|---|---|---|---|---|
| 2026-03 → 2026-10 | **DarkSword**: a full-chain iOS exploit kit, a malicious web page in Safari ends as a kernel implant; from 2026-09 reused against crypto wallets on unpatched iPhones (I: SlowMist, press) | six WebKit / ANGLE / dyld / XNU bugs, three zero-days; victims on iOS below 18.7.5 or 26.3 | in the wallet app's files and the iOS Keychain: secp256k1 private keys and seed phrases, readable once the kernel is the attacker's | the owner key is **born in the Secure Enclave** (or StrongBox / TEE), P-256, non-extractable even for kernel code; its use needs biometrics the enclave enforces itself; **there is no seed phrase anywhere**; the agent key is in a TPM or secure element under an on-chain mandate | a kernel-compromised phone controls the **screen**: an owner who approves may be shown one operation and sign another (`MOBILE_OWNER_DESIGN.md` T1, T5); patch level matters and attestation does not see a runtime exploit |
| 2026-10 | **Circle Agent Wallets / I-HITL**: AI agents read the e-mailed one-time code and raised their own spending caps; 9 of 10 models in at least one run; 5 of 10 paid an attacker on a planted e-mail (V, arXiv 2610.35835) | the cap was a service-side policy and the approval channel was readable by the agent | in the vendor's infrastructure; the limit in the vendor's database | the mandate is **on-chain**; changing it is a root operation signed by the owner's hardware key, which the agent does not hold; an attacker's address fails the allow-list; the phone owner is the paper's "inalienable human in the loop" | an injected agent can still spend **within** the mandate: the loss is bounded by the budget, not prevented; the first phone handover is signed blind (T2) |
| 2026-10-30 → 2026-11-02 | **BTCPay Server hot wallets swept**: merchants' Bitcoin and Litecoin hot wallets drained after admin logins on releases 2.4.1 and earlier; about $1.63M in 682 sweeps per Bitquery (I) | the hot wallet is the seed on the internet-facing server; the fix shipped 2026-08-07 and was not applied | a seed file on the server | a key in hardware that the host's admin can drive but not read, **under a mandate the host cannot change**: the USDC-on-Base store wallet designed in `BTCPAY.md` §4 | nothing for Bitcoin itself: secp256k1 and no on-chain policy. Every BTCPay integration, that design included, is the owner's separate project `77ph/BTCPayTEE`; this repository keeps the analysis |

## 2. Notes

### DarkSword (2026)

- **Disclosure.** 2026-03-18, Google Threat Intelligence Group with iVerify
  and Lookout: a full-chain iOS exploit kit of six vulnerabilities, three of
  them zero-days at the time, used by commercial surveillance vendors and
  suspected state actors since at least 2025-11 (V, The Hacker News,
  Dark Reading). The chain: JavaScriptCore memory corruption
  (CVE-2025-31277, CVE-2025-43529), ANGLE (CVE-2025-14174), a dyld PAC/TPRO
  bypass (CVE-2026-20700), kernel memory management (CVE-2025-43510); one
  web page in Safari ends as an in-memory implant with kernel privileges.
  Fixed across iOS 18.6 → 18.7.3 and, for the dyld bypass, iOS 26.3; a device
  below 18.7.5 or 26.3 is exposed (V, press summaries of the GTIG report).
- **Reuse against wallets.** 2026-09-19, SlowMist's CISO warned that the
  chain was being used against crypto wallets; a campaign page screened for
  Safari on iOS 18.4 → 18.6.2 and probed eight wallet apps (Binance, Coinbase
  Wallet, OKX, Bitget, Trust Wallet, Exodus, TronLink, Bitpie) for private
  keys, seed phrases and Keychain items (I, press). On 2026-09-26 SlowMist
  said it had **no confirmed theft** attributable to the chain yet (I,
  press). The figure in circulation, **5.57M USDT through nine transit
  wallets in 18 days (2026-10-10 → 10-28)**, is SlowMist's tracing of
  addresses linked to the campaign; the report itself says it does not
  establish that the exploit caused every transaction (I, press). Quote it
  as "traced", not "stolen by the exploit".
- **What it proves for us.** Every wallet on that list keeps a secp256k1 key
  or a seed as app data, because no phone secure element can sign secp256k1
  (`LANDSCAPE.md` §1). Kernel code reads app data and the Keychain; that is
  the whole attack. A P-256 key born in the Secure Enclave is not data the
  kernel can read: the app holds a handle (`dataRepresentation`, usable only
  by that enclave, `MOBILE_OWNER_DESIGN.md` §5.3), and the enclave checks
  the biometric itself before signing, so a kernel implant can neither
  exfiltrate the key nor sign without a finger on the sensor. There is no
  seed phrase to photograph: recovery is an encrypted file on separate media
  or a second hardware key (`RESILIENCE.md`), never twelve words.
- **What it does not prove.** On a phone the attacker owns, the app's screen
  is the attacker's too: the owner can be shown one operation and asked to
  approve another (T1, T5). The design's answer is partial: biometric per
  signature, the bold second confirmation for dangerous operations, the
  mandate bounding the agent regardless, and in v2 the phone checking the
  chain itself (§14). Two practical lessons: the app should refuse to enroll
  or warn below a minimum iOS build, since D7's floor (iOS 16) is far below
  the patched builds (I: add to the enrollment checks), and App Attest proves
  the app and the key, not the absence of a kernel implant.

### Circle Agent Wallets and the I-HITL paper (2026-10)

Full treatment in `LANDSCAPE.md` §2a and §2d; the formal model in
`MOBILE_OWNER_DESIGN.md` §10. The one code item it produced is #11, the
agent's own account must never be an allow-list target.

### BTCPay Server hot wallets (2026-10/11)

Full treatment in `BTCPAY.md`: the incident, BTCPay's own update, every
integration option with what it would take, and the requirements of the
Bitcoin side. The integration itself, in every form, is the owner's
separate project `77ph/BTCPayTEE` (2026-11-10); #13 was closed.

## Sources

- The Hacker News, 2026-03: [DarkSword iOS exploit kit uses 6 flaws, 3 zero-days](https://thehackernews.com/2026/03/darksword-ios-exploit-kit-uses-6-flaws.html); Dark Reading: [DarkSword: iPhone exploit kit serves spies and thieves alike](https://www.darkreading.com/threat-intelligence/darksword-iphone-exploit-spies-thieves); 8kSec: [CVE-2025-43529 case study](https://www.8ksec.io/how-browser-exploits-work-darksword-ios-cve-2025-43529/)
- Crypto Briefing, 2026-09: [Safari zero-day exploit targeting iPhones and crypto wallets](https://cryptobriefing.com/safari-zero-day-exploit-iphone-crypto-wallets/); The Currency Analytics, 2026-09-26: [SlowMist finds no confirmed crypto theft](https://thecurrencyanalytics.com/bitcoin/slowmist-finds-no-confirmed-crypto-theft-in-safari-exploit-tied-to-darksword-chain-297303); Startup Fortune: [A silent iPhone exploit called DarkSword is draining crypto wallets](https://startupfortune.com/a-silent-iphone-exploit-called-darksword-is-draining-crypto-wallets/)
- I-HITL: [arXiv 2610.35835](https://arxiv.org/abs/2610.35835)
- BTCPay: [incident post 2026-11-02](https://blog.btcpayserver.org/btcpay-server-security-incident-2-4-1-and-earlier/); Infosecurity Magazine, [the Bitquery tally](https://www.infosecurity-magazine.com/news/btcpay-server-flaw-cryptocurrency/)
