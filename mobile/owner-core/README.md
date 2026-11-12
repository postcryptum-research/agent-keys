# owner-core

The Rust core shared by `agent-signer` (the laptop) and the mobile owner
apps (the phone): byte-exact Kernel v3.3 encodings, the AgentPolicy mandate
layout, the ERC-4337 v0.7 `userOpHash`, and, as the mobile work proceeds,
the request format, decoding and display text of
[`docs/MOBILE_OWNER_DESIGN.md`](../../docs/MOBILE_OWNER_DESIGN.md) §7.

No network, no async, no hardware backends: it builds for
`aarch64-linux-android`, `armv7-linux-androideabi` and `aarch64-apple-ios`
as well as for the laptop.

**Licence: not decided.** The licence of the mobile owner apps and of this
crate is a separate study, to be done before P5 and before any of the apps'
code is published (`docs/MOBILE_OWNER_PLAN.md`, decision 3). Until then this
crate has no `license` field and `publish = false`. Code moved here from
`agent-signer` (`kernel.rs`) was Apache-2.0 there and stays Apache-2.0,
whatever the study decides for the rest of the crate.

What the phone knows by itself is in `src/facts.rs` (design §6.7): the
canonical `contracts/deployments/84532.json`, embedded with `include_str!`
and parsed by `build.rs` so a broken file fails the build, and a small
token table (USDC on Base Sepolia, with its EIP-712 domain). Features:
`ffi` is the `uniffi` surface for the apps (`src/ffi.rs`); `test-chains`
adds the facts of the CLI's local anvil chain for development builds and
marks the version `+test-chains` wherever it is shown — never ship it, and
never let a phone with such a build hold a key for a real account: it
trusts Base Sepolia's addresses on whatever chain calls itself 31337.

Tests: `cargo test` in this directory, and again with `--features ffi` and
`--features ffi,test-chains`. `cargo check --target aarch64-linux-android`
type-checks the phone build.
