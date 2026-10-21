# Key policy

## Premises (the project owner's)

1. Signing is **automatic** — no human confirmation. Otherwise no AI agent
   can act autonomously and the whole system is pointless.
2. An attacker can reach the file system: a private key that is a file can
   be read.
3. There is no reliable way to tell an attacker running user-level code
   (as the *nix user of the agent) from the agent itself.
4. If the agent can escalate to root, the attacker most likely can too.
5. Whether access to a secure chip can be granted per process is unclear,
   and it would not port across TPM / Secure Enclave / other elements.

## What follows

From 3–5: while an attacker is on the agent's host, they can ask the chip to
sign exactly as the agent does. The chip does not prevent misuse during a
compromise. What it does guarantee:

- the key cannot be read or copied (premise 2 is closed: there is no file);
- the attacker signs only while present; once the host is cleaned, nothing
  they took lets them sign again;
- every action they take is on-chain and attributable.

## The rules

1. **The agent key** lives in the agent host's secure element and signs
   automatically.
2. **The damage bound is on-chain only.** During a compromise the attacker
   *is* the agent; `AgentPolicy` — allow-list, per-operation value cap,
   budget, expiry — is the limit. Gaps in it are the critical class of bugs.
3. **The owner key is out of the agent's reach.** From 3–4, an owner key
   the agent's user can use would give an attacker root over the account,
   with no bound at all. Acceptable placements, strongest first:
   - **a separate device or machine** — a hardware wallet, another host's
     TPM, an owner Safe;
   - **the same chip, behind physical presence** — a Secure Enclave key
     that requires Touch ID, a Windows Hello–protected key: user-level
     malware cannot touch the sensor;
   - **the same chip, behind the root/user boundary** — on Linux, an owner
     TPM key with an authValue kept in a file only root can read
     (`authFile`, mode 0600), the agent running as an ordinary user without
     sudo; on Windows, a machine key whose ACL admits only Administrators /
     SYSTEM. One chip suffices — but this placement **relaxes premise 4**
     rather than following from it: its whole safety rests on the agent
     genuinely being unable to become root (an ordinary user, no sudo, no
     container misconfiguration, no local privilege escalation). That is a
     deployment invariant to verify and monitor, not to assume; if it ever
     breaks, the owner key is as reachable as the agent key. The first two
     placements carry no such assumption — for the Secure Enclave, the
     presence check must be the enclave-enforced access control
     (`userPresence` / biometry), so user-level code cannot skip it.
   Owner operations — rotation, revocation, changing the mandate — are rare
   and not part of the agent's autonomous loop, so a human in that loop does
   not contradict premise 1.
4. **No reliance on per-process access control** to the chip (premise 5).
   Anything the agent's own user can do, the attacker can do: an authValue
   the agent's user can read, file permissions on `/dev/tpmrm0` or PCR
   sealing do not separate them. (The `authFile` in rule 3 works only
   because root, not the agent's user, can read it.) PCR sealing guards
   against booting another OS or firmware, not against a compromise of the
   running system.
5. **No private key at rest in plaintext, and none on the agent's host.**
   The software backend exists for tests and test vectors only. One
   exception, for the owner side only: an **encrypted** owner or recovery
   key on removable media (a USB drive), under all of these conditions:
   - encrypted with a memory-hard KDF (scrypt N ≥ 2^18, or argon2id with
     ≥ 256 MiB) and an AEAD cipher;
   - the passphrase is typed when the key is used and never stored;
   - it is decrypted only on a machine that is not the agent's host
     (preferably an offline one), held in locked memory and zeroized after
     signing;
   - the medium is plugged in only for an owner operation;
   - it signs root operations only — never the agent's.
   Its weakness is the moment of use: whatever host decrypts it holds the
   key itself, not just a signing oracle. That is why it suits a cold
   recovery owner, used rarely and away from the agent, rather than a daily
   one ([`OWNER_DEVICES.md`](OWNER_DEVICES.md), section 6).
6. **Testnet exception:** on Base Sepolia the owner and agent keys share one
   TPM, the owner key without an authValue, for the demo. This violates
   rule 3 knowingly and is acceptable only where nothing of value is at
   stake.

## Hardening (not enforced)

The project does **not** refuse a configuration where the owner key shares
the agent's host: that would exclude every user without a separate device.
Placement is the deployer's choice (rule 3, strongest first: separate
device → same chip behind enclave-enforced presence → same chip behind the
root/user boundary). What a value-bearing deployment should do instead:

### Checklist: owner key on the agent's chip (placement iii)

Placement (iii) relaxes premise 4; its safety is exactly the invariants
below. Treat them as preconditions, verified at setup and re-checked —
not as advice.

- [ ] The owner key was **created** with an authValue
      (`key create --handle … --auth-file …`), and the config references it
      as `{"tpm": {"handle": …, "authFile": …}}` — not a bare handle.
- [ ] The auth file is `root:root`, mode `0600`, and the agent's user
      cannot read it: `sudo -u <agent-user> cat <authFile>` must fail.
- [ ] The agent runs as an ordinary user: not root, not in `sudoers`, no
      `sudo` rules (`sudo -l -U <agent-user>` lists nothing), no container
      privileges that reach `/dev/tpmrm0` as root.
- [ ] The agent's config carries `ownerPublicKey`, so its operations never
      open the owner key (`account status` works as the agent's user).
- [ ] Owner operations run as root by a human
      (`sudo agent-signer permission …`), never from the agent's process.
- [ ] Drift is monitored: changes to `sudoers`, the auth file's ownership or
      mode, the agent user's groups, and kernel patch level (local privilege
      escalation) raise an alert.

If any item fails, the owner key is as reachable as the agent key.

### Further hardening

- **An owner device with a presence check** (touch, button, biometric), so
  a host compromise during an owner operation cannot sign more than the
  human confirms. Candidate devices: [`OWNER_DEVICES.md`](OWNER_DEVICES.md).
- **A mainnet check in the deployment's own tooling** — a wrapper or CI step
  that flags an unprotected co-located owner key when the chain id is a
  mainnet. The project leaves this, and whether it warns or blocks, to the
  deployer.

## What the code must allow

- The agent's operations must not need the owner key at all — neither open
  it nor require access to it — so the owner key can actually live
  elsewhere. Only its public key may be needed (to derive the account
  address), and that comes from the config. Root operations run where the
  owner key is (for the root/user placement: `sudo agent-signer permission …`).
- A TPM owner key can carry an authValue read from a root-only file.
- Selecting a software key must be an explicit test-only choice: a build
  feature (`insecure-software-keys`) that release builds never enable.
  Without it a software key is refused in every role; with it — in the
  integration tests on a local chain only — any role may use one. Keep the
  flag on the command line only: never in a manifest dependency, a default,
  a cargo alias or config, or a release/deploy pipeline (Cargo unifies
  features across a build, so any of those would leak it into a shipped
  binary); a deploy pipeline should assert that the shipped binary refuses
  a software owner key. An encrypted key file (rule 5's exception)
  is accepted for owner and recovery operations only, never for the agent.
