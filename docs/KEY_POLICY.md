# Key policy

> **Кратко по-русски.** Чип не мешает злоумышленнику, захватившему хост
> агента, подписывать — пока тот на хосте; он гарантирует, что ключ нельзя
> украсть и унести. Предел ущерба во время захвата задаёт только мандат на
> цепи (`AgentPolicy`). Ключ владельца недоступен агенту: на отдельном
> устройстве, либо в том же чипе за физическим присутствием (Touch ID,
> Windows Hello), либо за границей root/user (пароль ключа в файле только
> для root) — один чип, без второго устройства.

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
5. **No plaintext private key, anywhere outside tests.** The software
   backend exists for tests and test vectors only.
6. **Testnet exception:** on Base Sepolia the owner and agent keys share one
   TPM, the owner key without an authValue, for the demo. This violates
   rule 3 knowingly and is acceptable only where nothing of value is at
   stake.

## What the code must allow

- The agent's operations must not need the owner key at all — neither open
  it nor require access to it — so the owner key can actually live
  elsewhere. Only its public key may be needed (to derive the account
  address), and that comes from the config. Root operations run where the
  owner key is (for the root/user placement: `sudo agent-signer permission …`).
- A TPM owner key can carry an authValue read from a root-only file.
- Selecting a software key must be an explicit test-only choice, never
  available to the owner role.
