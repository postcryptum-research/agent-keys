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

Tests: `cargo test` in this directory. `cargo check --target
aarch64-linux-android` type-checks the phone build.
