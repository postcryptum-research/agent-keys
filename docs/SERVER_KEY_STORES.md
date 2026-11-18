# Key stores on a server: vTPMs and their relatives — study

*Draft, 2026-11-14, for issue #42. The question: what plays the part of
"the TPM" when the agent runs on a remote server or a cloud VM. The
process does not change: a P-256 key that cannot be exported signs
ERC-4337 UserOperations, the on-chain `AgentPolicy` bounds it, the owner's
key is elsewhere. TEEs and confidential VMs are out of scope. Which role
such a key may hold was the owner's decision; this page gathers the facts
and ends with the questions put to the owner and the decisions (§10,
2026-11-19).*

Evidence marks: **F** first-hand, run by us (§8). **D** stated by a
primary source: the vendor's documentation, a specification, or the
vendor's published source code, read on 2026-11-14. **I** inferred, or
from a secondary source.

**One cloud was run: Azure, on 2026-11-18 (§8.4).** Where that run
settled a point, the mark is now F and the text says so. For AWS and
Google every mark is still D or I. Every sentence quoted
word for word from a documentation page was checked against that page a
second time. The other comparison facts (§4 to §6) were read once, part
of them through a text extractor: re-read the source before relying on a
figure from them.

Which rented machines have a TPM 2.0 at all, clouds and physical servers
by price, is in §12.

## 1. Summary

1. **The `tpm` backend needs nothing new for a vTPM.** It ran unchanged
   against the software TPM that QEMU, libvirt and Proxmox put behind a
   VM (F). What it asks of a TPM (§2) is in every vTPM looked at, by
   documentation or source. On an Azure Trusted Launch VM it ran unchanged
   too, once the storage parent was created (F, §8.4).
2. **On a vTPM, "non-exportable" is a promise of the host, not a property
   of a chip.** The guest cannot read the key, its root included: that is
   the property [`KEY_POLICY.md`](KEY_POLICY.md) builds on, and it holds.
   But the whole vTPM is data the host keeps, and whoever copies that
   data has the key: a copy of the state signed with the same key (F).
3. **A new party appears: the cloud account.** Whoever administers the
   subscription can run commands as root in the VM (all three clouds, D).
   That is the server's form of "whoever holds the machine". On Azure the
   vTPM state also travels with snapshots, restore points and Site
   Recovery, and has an export call (D); AWS and Google document that the
   state stays with the instance (D). **An Azure copy signs with our
   key:** a VM made from a snapshot, and one made from a restore point,
   both did (F, §8.4).
4. **The on-chain bound does not change; one guarantee of the chip gets
   weaker.** "Once the host is cleaned, nothing they took lets them sign
   again" becomes "unless they took a copy of the VM". The remedy is the
   one the FAQ already gives: after a compromise, revoke or rotate the
   agent's permission, never only clean up.
5. **Cost.** vTPMs and a chip in a rented server: no code, a line in the
   FAQ (in this change) and the run on Azure. A cloud key service or an
   HSM: a new backend each, and another trust model (§6, §9).

| Kind | Backend unchanged? | Who else can use the key | Who can copy it | Evidence for a third party |
|---|---|---|---|---|
| **Azure Trusted Launch vTPM** | **yes (F)**, with room for three persistent objects of ours | Microsoft's host (D); the subscription, through Run Command (D, F) | the state is in snapshots, restore points and Site Recovery replicas (D); the export call returns the blob (F); **a copy signs (F)** | an attestation-key certificate under Microsoft's vTPM root (D); no EK certificate (I) |
| AWS NitroTPM | expected (I); P-256 and the SHA-256 bank are not documented | AWS says its staff cannot reach customer content (D, not the vTPM by name); the account, through Systems Manager (D) | not in snapshots (D); no export call (I) | a document signed by the hypervisor over PCRs and caller data (D); no EK certificate (I) |
| Google Shielded VM vTPM | expected (I); P-256 is there (D) | Google's host: the state is plain text in host memory (D); the project, through a startup script (D) | "permanently associated with the VM" (D); no export call (I) | EK and AK public keys from the API (D); an AK certificate signed by Google (D for confidential VMs, not established for a plain Shielded VM) |
| swtpm: QEMU, libvirt, Proxmox | **yes (F)** | the host's root | the host's root: the state file is the key (D, F); a Proxmox clone and backup carry it (D) | none: the EK certificate is from the operator's own CA (D) |
| VMware vSphere vTPM | expected (I): the guest is given a TPM 2.0 device | vCenter administrators hold the encryption keys (D) | **a clone duplicates the vTPM and its secrets, by default** (D) | none beyond the operator's CA (D) |
| Hyper-V vTPM, own server | not looked at for a Linux guest | the host's administrator, unless the VM is shielded under a guardian service (D) | not established | no published root (I) |
| A chip in a rented server | yes: the case we run today | the provider's staff, by starting another system (an unsealed key) | nobody, from a discrete chip (I) | the manufacturer's EK certificate (D) |
| Cloud key service (KMS, managed HSM) | **no: a new backend** | any principal the key's policy admits, from anywhere (D) | the provider replicates it, by design (D) | key attestation on Azure Managed HSM and Google Cloud HSM only (D) |
| YubiHSM 2 inside the server | no: a new backend | whoever is on the host, which holds the device's password (I) | nobody, unless exported under a wrap key (D) | Yubico's attestation chain (D) |

## 2. What the backend asks of a TPM

Read from `signer/crates/hw-signer/src/tpm.rs`; this is the whole list.

- A TPM 2.0 reached through tpm2-tss: `/dev/tpmrm0`, or the address in
  `TPM2TOOLS_TCTI`.
- A storage parent persisted at `0x81000001` (`--parent` names another).
- `TPM2_Create` of an unrestricted ECDSA P-256 signing key (fixedTPM,
  fixedParent, sensitiveDataOrigin), `TPM2_Load`, and `TPM2_EvictControl`
  in the owner hierarchy, whose authorization is empty.
- `TPM2_Sign` over a digest the host computed.
- Optional: an authValue on the key, or `TPM2_PolicyPCR` over the SHA-256
  bank.

No endorsement key, no certificate, no NV index, no clock. So a TPM 2.0
with P-256 and a SHA-256 PCR bank fits.

## 3. Azure: the vTPM of a Trusted Launch VM

### 3.1 What it is

- TPM 2.0, one instance per VM: "compliant with the TPM2.0 spec", "runs
  in a secure environment outside the reach of any VM" (D). It is hosted
  by "the paravisor", an environment that "runs inside the VM" (D). Which
  implementation a given VM size gets is not documented; the open-source
  one is OpenHCL, and the marks "source" below are readings of its code.
- Its state is in the **VM guest state** blob: "a blob managed by Azure",
  and "the lifecycle of the VMGS blob is tied to that of the OS disk"
  (D). Whether that blob is encrypted beyond the storage's own
  encryption, and under whose key, is not documented.
- Default for new Gen2 VMs, at no extra price (D).

### 3.2 Does the backend run against it? (question 1)

| Needed (§2) | On Azure | Mark |
|---|---|---|
| `/dev/tpmrm0` in a Linux guest | Azure's pages do not name the device; Microsoft's own guest test tool opens it | I |
| a storage parent at `0x81000001` | not provisioned: the open-source paravisor reserves the handle and reports "SRK not found". systemd 255 and later create one only on a measured boot | I, D |
| ECDSA P-256, unrestricted | not stated; the Microsoft reference TPM the paravisor builds on enables it. Azure's own keys in the vTPM are RSA | I |
| the SHA-256 PCR bank | not stated; Microsoft's attestation client reads that bank | D (source) |
| PCRs 0, 2, 4, 7 for sealing | PCR 0 to 7 are reported to Azure Attestation; PCR 7 follows the Secure Boot variables, PCR 4 the boot loader and kernel. Whether Microsoft's own firmware updates change them is not documented | D |
| free handles | Azure keeps its attestation key at `0x81000003` and a certificate at NV `0x01C101D0`; ours are `0x8101xxxx` | D |

It works unchanged, with the storage parent created once, as the FAQ
describes: every row of this table was seen first-hand on 2026-11-18
(§8.4), except what Microsoft's firmware updates do to the PCRs. One
thing the table did not foresee: the vTPM has room for few persistent
objects (§8.4, point 2).

### 3.3 Who can use or copy the key? (question 2)

**Use.**
- Whoever is root in the guest, as on a chip.
- **Microsoft's host.** Microsoft's own design guidance for Trusted
  Launch says so: "Everything above trusts the host. If you can't trust
  the hypervisor, run the workload on a Confidential VM", and its table
  answers "Protects asset from the host / hypervisor" with "No (accepted
  risk)" (D).
- **The subscription.** The same page lists what the subscription's owner
  can do: "`az vm run-command`, custom script extensions, OS disk
  snapshot and swap, serial console, managed-identity token theft via
  IMDS—all without SSH" (D). Run Command needs the Virtual Machine
  Contributor role and runs "as an elevated user on Linux" (D). Root in
  the guest opens `/dev/tpmrm0` and reads an `authFile`.

**Copy.** The state is in the guest state blob, and that blob:

| Operation | What happens to the vTPM state | Mark |
|---|---|---|
| Restart; deallocate and start; redeploy; resize | kept: the keys signed after each (§8.4) | F |
| Live migration | not documented; expected kept | I |
| Reimage or service healing, **ephemeral** OS disk | keys made after creation "might not be persisted" | D |
| OS disk snapshot, restore point | included | D |
| A VM made from that snapshot or restore point | gets the state, our keys and the storage parent included; the endorsement key and Azure's attestation key are new (§8.4) | F |
| Site Recovery | "replicates the VM guest state" to the other region | D |
| Export | `beginGetAccess` with `getSecureVMGuestStateSAS` returns a download address for the blob (F: 4 MiB, readable with that address alone); a new disk can be made from such a blob (D) | D, F |
| Gallery image of kind `TrustedLaunchSupported` | "does not contain the VMGS blob": a new vTPM | D |
| Gallery image of kind `TrustedLaunch` (captured from a VM) | not documented | — |
| Restore of the same VM from a backup | expected: the vTPM goes back to the backup's day | I |
| Deleting the OS disk | expected: the keys go with it | I |

The export call needs the right `disks/beginGetAccess/action`. Virtual
Machine Contributor does not have it; Contributor and Owner do, and so do
the disk backup and snapshot roles (D for the roles listed, I for the
wildcard).

**Does a copy sign with our key?** Azure does not say. **It does (F,
§8.4).** What pointed to it beforehand:
- a copied state did, on the software TPM (F);
- the paravisor's source, when the host signals a new VM identity,
  renews the endorsement and platform seeds and the attestation key, and
  leaves the storage hierarchy alone (I, from reading the code; which
  operations send that signal is not documented). The run agrees: on
  both copies the endorsement key and the attestation key had new names,
  and the storage parent and our keys were the same.

### 3.4 What evidence is there? (question 3)

- **No EK certificate** is documented, and the paravisor's source does
  not persist an EK (D, source). The manufacturer's statement "this is a
  genuine chip" has no equivalent.
- **An attestation key** (RSA, restricted) at `0x81000003`, its
  certificate at NV `0x01C101D0`, issued under the "Azure Virtual TPM
  Root Certificate Authority 2023", which the FAQ publishes (D).
- **What a verifier could do with it, without calling Microsoft:** check
  that certificate, then have the attestation key certify our key
  (`TPM2_Certify`). That shows: this P-256 key is an object in a vTPM
  whose attestation key Microsoft certified. Microsoft's client does this
  for a key of its own (D, source); for a user's key it is not a
  documented procedure (I).
- **What the verifier must also check:** that the key is `fixedTPM` and
  `sensitiveDataOrigin`, in the public area that the certified name
  commits to. Without that, "an object in a vTPM" does not mean
  "generated there".
- **What that does not show:** that the key exists once (copies), that
  the host cannot use it, or which VM it is (the certificate's fields are
  not documented).
- **Azure Attestation** signs a statement about the boot (the Secure
  Boot claim, PCR 0 to 7). It is about the system that started, not about
  our key.

To whom it matters: our CLI checks no evidence for a TPM key today, chip
or not. The precedents are the YubiKey's `key attest` and the phone's
attestation. Somebody who made the key on their own VM learns nothing
from the certificate; a third party asked to trust that an agent's key is
not a file would.

## 4. The other clouds, for comparison

| | AWS NitroTPM | Google Shielded VM vTPM |
|---|---|---|
| State | location and encryption not documented | encrypted at rest and in transit; plain text in host memory while the VM runs (D) |
| P-256, SHA-256 bank | neither documented; the attestation document uses SHA-384 | P-256 yes (D); SHA-1, SHA-256, SHA-384 banks (D for confidential VMs, I here) |
| Stop and start | "persists through stop/starts" (D); the measurements change (D) | not stated; expected kept (I) |
| Snapshot | "The NitroTPM state is not included in Amazon EBS snapshots" (D) | "you can restore a snapshot … but you can't decrypt it because the vTPM … isn't available" (D) |
| Images, backup | no sentence; expected a new vTPM (I). Root volume replacement: two AWS pages disagree | machine images list UEFI variables, not the vTPM (I) |
| Export call | none found (I) | none found (I) |
| Operators | "no technical means or APIs available to AWS personnel to read, copy, extract" customer content (D, service terms; the design was reviewed by an outside firm) | access needs "an end user permission ticket" (D, 2018) |
| The account | Systems Manager gives "root or SYSTEM permissions" (D) | whoever may set metadata runs a startup script as root (D) |
| Evidence | a document signed by the hypervisor: PCRs and up to 1 kB of caller data (D, since 2025-09); an EK public key from the API, no certificate (I) | EK and AK public keys from the API (D); an AK certificate under a Google root, naming the instance (D for confidential VMs, not established here) |
| To get one | the image must be registered with TPM support; "There are no preconfigured AMIs" for Linux; only at launch (D) | on by default (D) |

The other clouds, and the low-priced VPS hosts, are in §12.1.

## 5. Our own hypervisor, and a chip in a rented server

**swtpm** (the software TPM under QEMU, libvirt, Proxmox, XCP-ng).
- The state is a file on the host, plain unless a key is given; its
  author: "Whoever can access those files can extract its secrets" (D).
  With a key, the copy needs that key too (F), and the key is on the same
  host. The state holds the hierarchy seeds (I, from the source).
- Proxmox starts it without a key, clones the state with the VM and
  includes it in backups (D). libvirt's `virt-clone` gives the clone an
  empty one (I).
- A snapshot that is reverted takes the vTPM back with it (I).

**VMware vSphere.** The state is in the VM's `.nvram`, under VM
encryption, whose keys the administrators hold (D). "Cloning a virtual
machine duplicates the entire virtual machine, including the vTPM and its
secrets"; since vSphere 8 a clone can instead be given a new one, and
copying is the default (D).

**Hyper-V on one's own server.** The host's administrator can export the
certificates that protect the state unless the VM is shielded under a
separate guardian service (D for the shielded case, I for the rest).

**A chip in a rented or colocated server.** This is the case the project
already runs, with other hands near the machine.
- Present on some offers and not on others: Oracle and IBM document it
  (IBM: off by default); for Hetzner and OVHcloud there is no official
  page; AWS's `.metal` instances have no NitroTPM (D).
- The provider's staff cannot copy a key out of a discrete chip (I). They
  can **destroy** it: `TPM2_Clear` needs only the platform's authority,
  which firmware and a management controller have (D). And they can
  **use** an unsealed key by starting another system, the row the FAQ has
  for a stolen laptop.
- Between tenants: IBM documents that the chip is cleared (D); nobody
  else does. Evict our keys before giving a machine back.
- Known attacks need the machine in hand (bus interposers; faulTPM on
  AMD's firmware TPM), or are fixed in firmware: TPM-FAIL (2019)
  recovered ECDSA keys by timing from Intel's firmware TPM and an ST chip
  (D). A rented machine's firmware is the provider's to update.

## 6. Other stores, for comparison

They sign a digest we give them with a P-256 key that has no export
call (D for each). What differs from any TPM:

| | TPM or vTPM | AWS KMS · Azure Key Vault / Managed HSM · Google Cloud KMS |
|---|---|---|
| Who may sign | whoever is on the machine | any principal the key's policy admits, **from anywhere** unless the policy also names a network (D) |
| How the server proves itself | it does not; it is there | a token from the metadata service. It is a bearer credential: stolen, it works elsewhere until it expires (D for AWS, I for the others). That is about 24 hours on Azure, and it cannot be cut short (D); about an hour on Google (D, an example value); AWS states no figure |
| Audit of each signature | none | yes: on by default on AWS, to be switched on in Azure and Google (D) |
| Switch off | on-chain only | the administrator disables the key at once (D) |
| Bound to the boot state | PCR policy | no (D for AWS and Azure) |
| Copies | none intended | the provider replicates the key (D) |
| Key attestation | §3.4, §4 | Azure Managed HSM and Google Cloud HSM (D); not for AWS KMS or a Key Vault key (I) |
| Price | none | Azure Premium, an HSM key: $5 a month and $0.15 per 10,000 signatures; Managed HSM $3.20 an hour. AWS: $1 a month and $0.15 per 10,000. Google Cloud HSM: $1 to $2.50 a month per key version, its price per signature not established (D, list prices read 2026-11-14) |
| Signature | raw `(r, s)` | DER on AWS and Google (D), `r ‖ s` on Azure (I) |

**YubiHSM 2**: made for a server's internal USB port; signs a given
digest, attests keys it generated, and is opened with a password the host
holds (D). It answers "a key fob is hard to plug into a server" only for
a machine somebody can open. Row and price:
[`HARDWARE_WISHLIST.md`](HARDWARE_WISHLIST.md). **HashiCorp Vault
Transit** signs a pre-hashed P-256 input, with a software key unless it
delegates to one of the stores above (D).

## 7. What changes in the threat model (question 4)

| What we say today | Where | On a server's vTPM |
|---|---|---|
| "Key cannot be copied or extracted", enforced by the TPM | `ARCHITECTURE.md`, threat table | enforced by the hypervisor, against the guest. Not against the host, nor against whoever may copy the VM (Azure, VMware, Proxmox) |
| "once the host is cleaned, nothing they took lets them sign again" | `KEY_POLICY.md`, What follows | true for an attacker who stayed inside the guest; not for one who reached the cloud account or the hypervisor |
| the owner key on "another host's TPM" is out of the agent's reach | `KEY_POLICY.md`, rule 3 | two VMs in one subscription are one host to that subscription's administrator |
| the owner key on the same chip behind the root/user boundary | `KEY_POLICY.md`, rule 3 | Run Command arrives as root: the cloud account's credentials are owner credentials |
| "PCR sealing guards against booting another OS or firmware" | `KEY_POLICY.md`, rule 4 | still true, and worth less: the administrator needs no other OS, and a copy of the VM starts the same measurements (I) |
| a firmware update or "Clear TPM" wipes the keys | `FAQ.md`, failures; `RESILIENCE.md` §1 | new events: the VM or its OS disk is deleted; a restore takes the vTPM back in time; a clone makes a second holder; an ephemeral OS disk loses keys on reimage (D, Azure) |
| "Dictionary-attack lockout: temporary" | `RESILIENCE.md` §1.1 | the threshold may be 3, not 31 (§8.2) |

**What the on-chain policy still bounds: all of it.** The allow-list,
the cap per operation, the budget, the expiry and the refusal of
ERC-1271 never relied on the chip. A copy of the agent's key can do what
the agent can, out of the same budget, until the permission is revoked.

**The roles, with the consequences.** The owner's decision is in §10:
the agent key only.
- **Agent key.** Inside today's model: `KEY_POLICY.md` rule 2 already
  treats the key's holder as possibly hostile. What changes is the
  procedure after an incident that touched the cloud account: rotate,
  because cleaning the VM no longer ends the attacker's access.
- **Owner key.** Its placement rule is "out of the agent's reach". In a
  VM of the same subscription as the agent it is within reach of one
  stolen cloud credential, with no on-chain bound behind it. In another
  subscription, or with another provider, it is as separate as those
  accounts are.
- **Recovery key.** Its job is to outlive the others. A vTPM's state
  goes with the VM's disk and the subscription, and a restore can take
  it back in time.

## 8. First-hand

### 8.1 The run (2026-11-14)

`scripts/tpm-check.sh --swtpm`, in an Ubuntu 24.04 container on arm64:
swtpm 0.7.3, libtpms 0.9.3, tpm2-tss 4.0.1, tpm2-tools 5.6, rustc 1.94.1;
the tree mounted read-only. No VM and no hypervisor were involved: it is
the TPM that those hypervisors run, reached over its socket.

```
== the TPM
TPM2_PT_FAMILY_INDICATOR: "2.0"
TPM2_PT_MANUFACTURER: "IBM"
TPM2_PT_VENDOR_STRING_1: "SW"
TPM2_PT_VENDOR_STRING_2: "TPM"
TPM2_PT_FIRMWARE_VERSION_1: 0x20191023
P-256: 1 | PCR banks: sha1 sha256 sha384 sha512
persistent handles:
NV indices:
dictionary-attack lockout: 0 failed of 3 allowed, one forgiven every 1000 s; lockoutAuthSet 0, ownerAuthSet 0
== no storage parent yet: what the CLI says
refused, as it must be: Error: backend error: the handle is not correct for the use (associated with handle number 1)
== the backend's hardware tests
test tpm::tests::protected_key_signs_only_with_its_auth ... ok
test tpm::tests::sealed_key_follows_pcr16 ... ok
test tpm::tests::tpm_key_signs_and_verifies ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.05s
== the CLI: a plain key, a key sealed to PCRs 0,2,4,7, a key behind an authValue
OK: 0x8101ff01 signs (0xd359ff6e…)
sealed to PCRs [0, 2, 4, 7]: reference it as {"tpm": {"handle": "0x8101ff02", "pcrs": [0, 2, 4, 7]}}
OK: 0x8101ff03 signs (0x4ea81f92…)
evicted 0x8101ff02
evicted 0x8101ff03
failed authorizations counted now: 0
== a copy of the state directory, opened by a second TPM
OK: 0x8101ff01 signs (0xd359ff6e…)
the copy signs with the same key as the original: {"key":"0x8101ff01","x":"0xd359ff6e…","y":"0x8185abd1…"}
```

Left out above: the PCR values (all zero), the build's warnings, the
keys' JSON, and the tail of the two long public-key values.

That is the run as it was on that day. Since the change for #43 the
refusal reads "no storage parent at 0x81000001: persist one there
first …", the script checks the sealed key too, and it runs the tests
that change added.

### 8.2 What it showed, beyond "it works"

By hand in the same container, all F for libtpms 0.9.3:

1. **A copy of the state is a second holder of the key.** With the state
   encrypted (`--key`), the copy would not open without the key file and
   signed with it.
2. **The storage parent matters only when a key is made.** With
   `0x81000001` evicted, a key persisted earlier still signed.
3. **Lockout after 3 failures, one forgiven per 1000 s.** These are the
   reference defaults; the backend's own test notes 31 for Intel's
   firmware TPM. In lockout a key under it refuses to sign, and no key
   can be made under a parent that is under it. A PCR-sealed key kept
   signing: it authorizes by policy.
4. **An unclean stop counts as a failure.** Each time the TPM was killed
   after a signature with a key under the lockout, without
   `TPM2_Shutdown`, the next start added one: three such stops and it was
   in lockout. Idle periods that ended the same way added nothing, and a
   clean stop did not reset the count.
5. **Which keys are under the lockout** (#43). On 2026-11-14 every key
   was, an empty authValue included. Since #43 a key made without an
   authValue carries `noDA`: it signed through a lockout, and signatures
   with it did not make an unclean stop count. A key behind an authValue
   stays under it, and so do keys made before and a storage parent made
   by the FAQ's command as it was then (it sets `noda` since §10,
   question 6).
6. **Two rough edges in our CLI**, fixed with #43: the message for a
   missing storage parent did not name it, and `key check` could not
   check a PCR-sealed key (it had no `--pcrs`).

Not shown by this run: anything about a hypervisor's handling of the
state, a guest's `/dev/tpmrm0` (the socket has no resource manager, so
the script flushes the tools' objects itself), or PCRs that a firmware
fills (all zero here, so sealing to 0, 2, 4, 7 bound nothing).

### 8.3 The Azure run: what it had to settle

The plan as written before the run; the results are in §8.4.

On a Trusted Launch VM with a **managed** OS disk; the script's
`--make-srk --keep` first, then `--again` after each step.

1. The script passes: the device, P-256, the SHA-256 bank, the three
   tests. Its first lines record the handles and NV indices Azure ships,
   and **the lockout numbers** (3, or something else).
2. PCRs 0, 2, 4, 7: which are filled, and whether they are the same
   after a restart, a deallocate and start, a redeploy, a resize.
3. The key after each of those four.
4. **A VM made from a snapshot of the OS disk: does it sign with the same
   key?** Then the same question for a restore point.
5. A stop that skips the guest's shutdown, three times with a signature
   between: does the count rise as in §8.2, point 4?
6. The export call returns an address for the guest state blob. (Fetching
   and reading the blob is not needed for the conclusion.)

Needs: an Azure subscription and about two hours of a small VM (a
B-series size with 4 GiB, to compile).

### 8.4 The Azure run (2026-11-18)

A throwaway Trusted Launch VM in West Europe: Ubuntu 22.04, Gen2, vTPM
and Secure Boot on, a managed OS disk, size D2s_v3 (the B-series was not
offered to the subscription). `scripts/tpm-check.sh --make-srk --keep`
at master `2a98631`, then the steps of §8.3 by hand. The resource group
was deleted afterwards. All F.

1. **It is the Microsoft reference TPM.** Manufacturer `MSFT`, vendor
   string "TPM Simulator", firmware `0x20200312`. P-256 is there; the
   banks are SHA-1, SHA-256 and SHA-384; `/dev/tpmrm0` belongs to the
   group `tss`. As shipped: persistent handles `0x81000003` (Azure's
   attestation key) and `0x81010001` (the endorsement key), NV index
   `0x01C101D0`, **no storage parent at `0x81000001`**, no owner or
   lockout password.
2. **Room for three persistent objects of ours, no more.** The TPM
   reported three free slots. With the storage parent and two keys in
   place, the third `key create` failed with "insufficient space for NV
   allocation". That is enough for an agent (the parent and one key, one
   slot spare for a rotation) and too few for the script as it was: it
   kept three test keys at once and stopped at the third. The script now
   holds two. A VM where another tool has provisioned a key of its own
   has one slot fewer.
3. **The tests pass.** The three hardware tests, the two of #43 and the
   two CLI tests; a plain key, a key sealed to PCRs 0, 2, 4, 7 and a key
   behind an authValue were created and signed. A plain key carries
   `noDA`.
4. **The key survives the VM's lifecycle.** After a restart, a
   deallocate and start, a redeploy and a resize (D2s_v3 to D4s_v3 and
   back), both keys signed and the handles were the same. The four were
   done twice; the keys were checked at the end of the first round and
   after every step of the second.
5. **PCRs 0, 2 and 4 held through all of that; PCR 7 changed once.** All
   four are non-zero. PCR 7 had one value on the VM's first boot and
   another from the second boot on, the same through every later step.
   The cause was not looked for. What it means: **a key sealed to PCR 7
   on the first boot of a new VM would go silent at the next restart**;
   restart once before sealing. Not tested directly (the sealed key was
   evicted before the first restart, for the room).
6. **A copy signs with the same key.** A VM made from a snapshot of the
   OS disk, and a VM made from a restore point, each taken while the
   original ran: the same public key at the same handle, both keys
   signed, the key behind the authValue included (its file is on the
   disk). On each copy the storage parent's name was the original's;
   the endorsement key and Azure's attestation key had new names.
7. **A copy starts with a clean lockout counter.** The original stood
   at 2 failed authorizations of 3; each copy stood at 0. So the lockout
   does not limit guesses at an authValue for someone who can copy the
   VM: every copy brings three more.
8. **The export call works.** `beginGetAccess` with the guest-state
   option, on a detached copy of the disk, returned two addresses: the
   disk, and the guest state. The second is a blob of 4,194,816 bytes
   that begins `GUESTRTS`; its first 512 bytes were fetched with the
   address alone. The blob was not downloaded or parsed.
9. **Lockout: 3 failures, one forgiven per 1000 s, as in §8.2.** The
   hardware tests leave two failures behind (the script clears them at
   its end; this run stopped before that, at point 2). The count did not
   fall during 23 minutes that held eight restarts.
10. **An unclean stop counts here too.** A power-off that skips the
    guest's shutdown (`az vm stop --skip-shutdown`), after a signature
    with the key behind the authValue, raised the count from 2 to 3 and
    put the TPM in lockout. Clean restarts and deallocations added
    nothing. In lockout, through two more such stops: **the plain key
    (`noDA`) signed every time**, the key behind the authValue was
    refused, and no key could be created under the storage parent, which
    the FAQ's command made without `noDA` until §10, question 6.
11. **The subscription is root.** Before the run, `az vm run-command`
    read the vTPM's properties on a VM we had no login to.

Not done: Site Recovery, a gallery image, a restore of the same VM from
a backup, a Confidential VM, Windows. Not measured: how long a lockout
lasts in wall-clock time across restarts.

## 9. Cost to support (question 5)

| Kind | Cost | Why |
|---|---|---|
| A cloud VM's vTPM, Azure first | no code; the run (§8.3); then a paragraph of guidance in the FAQ | same device, same commands; the storage parent is made once (FAQ, question 1, step 3) |
| A VM under swtpm | nothing (F); the FAQ line in this change | |
| VMware, Hyper-V guests | nothing expected; not run | they present a TPM 2.0 to the guest |
| A chip in a rented server | nothing | the supported case |
| A cloud key service | a new backend each. The signer trait fits (a digest in, `(r, s)` out; DER to unpack on two of three); added: the provider's authentication, and a test account per provider | another trust model (§6). It buys an audit record per signature and a switch |
| YubiHSM 2 | a new backend, and the device | only where somebody can open the machine |
| Vault Transit | not worth it | a software key, or a proxy for one of the above |

## 10. Questions for the owner, and the decisions

Put to the owner with the study; decided on 2026-11-19. They change
documentation only: no code, and nothing on a running machine.

1. **Which roles may a vTPM key hold?** **Decided: the agent key only.**
   Owner and recovery keys are not placed in a cloud VM's vTPM. Whoever
   administers the cloud account runs commands as root in the VM and
   copies it, key included, and every copy starts with a clean lockout
   counter (§8.4, points 6, 7 and 11). The account's login would be the
   owner key, with no presence check and no on-chain bound behind it.
   Recorded in [`KEY_POLICY.md`](KEY_POLICY.md), rule 3; like the other
   placements there, it is not enforced by the CLI.
2. *(Closed: the Azure run was made on 2026-11-18, §8.4.)*
3. **Guidance for a cloud deployment.** **Decided: now, in the FAQ**, as a
   checklist under "Which machines and which networks?", with what the
   run added (§8.4, points 2, 5, 6, 7 and 10).
4. **A check of Azure's attestation-key certificate in the CLI?**
   **Decided: not now.** Besides the reasons in §3.4, the run showed that
   a copy of the VM gets a new endorsement key and attestation key and
   keeps our key (§8.4, point 6). A check would then pass on a copy too:
   it shows "in an Azure vTPM", never "only here" (I: the certificate of
   a copy was not read). To revisit when a third party has to verify
   where an agent's key lives.
5. **A Key Vault backend next to the vTPM?** **Decided: not now.** What
   would change it: a deployment that asks for a record of every
   signature, or for a switch an administrator can throw. Against the
   same adversary, someone with rights in the subscription, Key Vault
   can record each signature and be disabled, while a copy of a vTPM
   signs with nothing recorded.
6. **Existing agent keys and the lockout.** **Decided: on a virtual TPM,
   make a new agent key and rotate onto it, which costs one root
   operation; on a chip that allows 31 failures, leave it.** No key of
   the project's own accounts is on a virtual TPM today (the one TPM
   agent key is on an Intel firmware TPM), so nothing is rotated. With
   it, the FAQ's command for the storage parent sets `noda`: during a
   lockout a key can then still be made under it, a plain one and one
   behind an authValue alike, where the parent made without it refused
   both (F, swtpm 0.7.3, 2026-11-19). An existing parent is kept as it
   is.

## 11. Sources

Azure:
[Trusted Launch](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch),
[its FAQ](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq),
[the key-release pattern](https://learn.microsoft.com/en-us/azure/virtual-machines/secure-key-release-pattern-trusted-launch),
[Disks: Grant Access](https://learn.microsoft.com/en-us/rest/api/compute/disks/grant-access),
[Site Recovery](https://learn.microsoft.com/en-us/azure/site-recovery/concepts-trusted-vm),
[Compute Gallery](https://learn.microsoft.com/en-us/azure/virtual-machines/shared-image-galleries),
[Run Command](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/run-command),
[built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/compute),
[restore points](https://learn.microsoft.com/en-us/azure/virtual-machines/concepts-restore-points),
[reserved NV indices](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design),
[Secure Boot certificate updates](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-for-linux-on-azure-virtual-machines-df51ba85-4e1e-4eda-b1d8-f0881970e997);
source: [openvmm, the TPM device](https://github.com/microsoft/openvmm/tree/main/vm/devices/tpm),
[the reference TPM's profile](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile_Common.h),
[the guest attestation client](https://github.com/Azure/confidential-computing-cvm-guest-attestation/tree/main/client-library/src/Attestation).

AWS:
[NitroTPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html),
[prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html),
[attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-isolated-amis.html),
[replace a root volume](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/replace-root.html),
[the attestation document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html),
[service terms](https://aws.amazon.com/service-terms/),
[SSM Agent](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-restrict-root-level-commands.html).
Google:
[Shielded VM](https://docs.cloud.google.com/compute/shielded-vm/docs/shielded-vm),
[the vTPM, 2018](https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext),
[getShieldedInstanceIdentity](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/getShieldedInstanceIdentity),
[go-tpm-tools](https://github.com/google/go-tpm-tools).

Hypervisors and chips:
[swtpm wiki](https://github.com/stefanberger/swtpm/wiki),
[swtpm(8)](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod),
[libtpms state](https://github.com/stefanberger/libtpms/blob/master/src/tpm2/NVMarshal.c),
[Proxmox QEMU chapter](https://pve.proxmox.com/pve-docs/chapter-qm.html),
[vSphere vTPM](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security/securing-virtual-machines-with-virtual-trusted-platform-module/vtpm-overview.html),
[vSphere: cloning](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security/use-encryption-in-your-vsphere-environment/clone-an-encrypted-virtual-machine.html),
[Hyper-V shielded VMs](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms),
[systemd, NEWS for 255](https://github.com/systemd/systemd/blob/main/NEWS),
[TPM 2.0 Part 3, `TPM2_Clear`](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf),
[EK credential profile](https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf),
[IBM bare metal](https://www.ibm.com/new/announcements/securing-the-boot-process-for-ibm-cloud-bare-metal-servers-for-vpc),
[TPM-FAIL](https://tpm.fail/),
[faulTPM](https://arxiv.org/abs/2304.14717),
[TPM Genie](https://github.com/nccgroup/TPMGenie).

Key services:
[AWS KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html),
[AWS KMS data protection](https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html),
[AWS KMS pricing](https://aws.amazon.com/kms/pricing/),
[Key Vault keys](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details),
[managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations),
[Managed HSM key attestation](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/key-attestation),
[Azure retail prices](https://prices.azure.com/api/retail/prices?$filter=serviceName%20eq%20%27Key%20Vault%27%20and%20armRegionName%20eq%20%27eastus%27),
[Google asymmetricSign](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign),
[Cloud HSM attestation](https://docs.cloud.google.com/kms/docs/attest-key),
[YubiHSM 2 concepts](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html),
[Vault Transit](https://developer.hashicorp.com/vault/api-docs/secret/transit).

## 12. Where there is one: an availability survey

*Added 2026-11-17, at the owner's request. The reader is one person
renting one machine with a card: which machines have a TPM 2.0 for the
`tpm` backend to talk to. Nothing here was rented or run.*

How it was gathered, and what that is worth: by automated reading on
2026-11-17. Manufacturers' manuals and the hosts' order pages were read
directly. **WebHostingTalk and LowEndTalk refused automated reading**, so
their offers are known from search excerpts, not from the threads. Almost
no price page of a cloud could be read; cloud prices are from third-party
price trackers. Quotes were relayed by a text extractor: re-read the
source before citing one. Marks as in the rest of the page; here **D**
means the vendor's or the host's own document, and a forum post, a
reseller or a price tracker is always **I**.

### 12.1 Cloud VMs: who gives the guest a vTPM

| Platform | vTPM | How | Does a copy of the VM carry the state | Cheapest VM with it, per month (I) |
|---|---|---|---|---|
| Azure, Trusted Launch | yes (D) | default for new Gen2 VMs | yes, §3.3 | about $4 (B1ls) |
| AWS, NitroTPM | yes (D) | not default: the image must be registered with TPM support, at launch only | no, §4 | about $4 (t3.nano), plus making the image |
| Google, Shielded VM | yes (D) | default | no, §4 | about $6 to $7 (e2-micro) |
| Oracle Cloud, shielded instances | yes (D) | chosen at creation; listed shapes and images only; not the Always Free shapes; custom images unsupported | no: "the TPM data is not retained during migration" (D) | about $19 to $25; two sources disagree |
| Alibaba Cloud, trusted instances | yes (D) | at creation; listed instance families, a supported image, the key service activated | not documented | about $41 to $46 |
| Huawei Cloud, QingTian TPM | yes (D) | at purchase; C9 / aC9 / aC8 families, **8 vCPU and 16 GiB or more** | no: "not included in image snapshots" (D) | not read; a VM of that size is above $100 |
| Exoscale | yes (D) | a flag at creation (`--tpm`), any instance type; a command exists for an existing instance | not documented | about EUR 6 |
| Gcore | yes (D) | a flavor family, `g2-tpm-…` | not documented | not read |
| Infomaniak Public Cloud (OpenStack) | yes (D, read through a search excerpt) | image properties `hw_tpm_version=2.0`; one's own uploaded image; no live migration | not documented | about EUR 4 to 5 |
| T Cloud Public | GPU family only (D, excerpt) | | not documented | not read |
| **Hetzner Cloud** | **no** (D): "our cloud servers do not support vTPM" (FAQ, 2024-09) | | | |
| IBM Cloud VPC, IONOS Cloud | not documented | secure boot (IBM) and a confidential VM (IONOS) are; a TPM device is not | | |
| DigitalOcean, Vultr, Akamai (Linode), UpCloud, Contabo, Scaleway Instances, OVHcloud Public Cloud and VPS, Tencent Cloud, Kamatera, Hostinger, netcup | not documented | for OVHcloud's VPS and for Scaleway an open customer request for a vTPM exists (I), which reads as "no" | | |

OpenStack can give a guest a software TPM when the operator sets it up;
Infomaniak is the only public one found that documents it for tenants.
Some small hosts on Proxmox attach a vTPM on request (I, forum replies):
that is swtpm, §5.

**What it comes to.** Outside the three large clouds, the low-priced
choices with a documented vTPM are Exoscale and Infomaniak. The popular
low-priced VPS hosts have none, or do not say. Where a copy of the VM
carries the keys is documented only for Azure (yes) and for AWS, Google,
Oracle and Huawei (no).

### 12.2 Rented physical servers: what the hardware is

About 75 offers from about 35 hosts. Only a few hosts name the chassis or
the board (Worldstream, Dediroom, NovoServe, Leaseweb, HostSailor, and
Hetzner for its DX line); for the rest the platform is inferred from the
processor (I). No host named a Supermicro board.

| Per month | What is rented | Whose hardware | A TPM 2.0 in it (§12.3) |
|---|---|---|---|
| **under $100** | Xeon E3 v1 to v6, E5-16xx v2, Xeon D, Atom, 16 to 64 GB (platforms of 2011 to 2017); decommissioned dual E5-26xx v2 to v4 with 128 GB at $65 to $100 | Dell 12G / 13G, HPE Gen8 / Gen9, Supermicro X9 to X11 class (I); OVHcloud's own assembly on Intel, ASUS and ASRock Rack boards (I) | **realistically none.** A header for a module at most, and the module is not fitted; Gen8 and 12G cannot take a 2.0 at all |
| | desktop-class: Ryzen 5 3600, Ryzen 7 5800X, Core i5-13500, i9-9900K, 64 GB (Hetzner AX41 and EX44 from EUR 59, OVHcloud Rise-Game, US budget hosts) | consumer AM4 and LGA1700 boards; for Hetzner an ASRock Rack board made for it (I) | **yes, the processor's firmware TPM**, with no module. It may be switched off: on Hetzner, a free remote-console session to enable it (I) |
| | entry branded 1U at European hosts: Dell R250, HPE DL20 / DL120 Gen9, Fujitsu RX1330 M3 / M4 (EUR 49 to 77) | as named (D) | Dell: only if the module was ordered. HPE Gen9: only if the kit was. Fujitsu: not looked at |
| **$100 to $200** | new single-socket AM5: Ryzen 9 7950X3D / 9900X / 9950X, EPYC 4244P to 4545P, DDR5 (about half of the segment) | ASRock Rack 1U2S-B650 where named (D); otherwise AM5 server or desktop boards (I) | **yes, firmware TPM**; on the ASRock Rack AM5 board the default is "Auto for fTPM" (D) |
| | refurbished 2017 to 2020 servers: Xeon Silver 41xx / 42xx, Gold 6148, EPYC 7402P; dual E5 v3 / v4 in branded chassis | Dell R640, R6515, R730xd, R740; HPE DL360 / DL380 Gen9 and Gen10 (D where named) | **only if the first owner ordered it.** Dell: a plug-in module, and "TPM Security" is Off as shipped. HPE Gen9 / Gen10: a separate kit |
| **over $200** | current server platforms: EPYC 9004 / 9005, Xeon 6, Xeon Scalable 5th generation, 128 to 512 GB | Dell R660xs, R470, Hetzner DX ("Dell PowerEdge"); HPE DL325 Gen11, DL320 Gen12 (D); unnamed boards presumed Supermicro, ASRock Rack or Gigabyte (I) | **likely.** HPE Gen11: embedded (D). Dell 16G: a module, and TPM 2.0 is Dell's default factory option, Off as shipped (D). Unnamed EPYC boards: a header only, so none unless the host fitted one |
| | AM5 with 96 to 256 GB | as in the row above | yes, firmware TPM |

**What it comes to.** Below $100 the way to a TPM 2.0 is a desktop-class
machine and its firmware TPM, not an old server. A refurbished brand-name
server has one only by the luck of how it was first ordered. From about
$200, on current Dell and HPE hardware, it is usually there and has to be
switched on.

### 12.3 The hardware, by vendor and generation

| Hardware | The TPM is | 2.0 | As delivered |
|---|---|---|---|
| Dell 12G (R620, R720) | on the board (I) | no: 1.2 at best (I) | "TPM Security" Off (D) |
| Dell 13G (R630, R730) | a plug-in module, absent unless ordered | yes, the first Dell generation (1.2 and 2.0 are different parts) | "The TPM menu is available only when the TPM module is installed"; Off by default (D) |
| Dell 14G, 15G (R640, R740, R650, R6515) | a plug-in module, bound to the board | yes | to be set to On in System Security (D) |
| Dell 16G (R660, R760) | a plug-in module | 2.0 only | "This option is set to Off by default" (D) |
| HPE Gen8 | a connector and a kit | **no** (D) | |
| HPE Gen9 | a connector and a kit, 1.2 or 2.0 | yes, in UEFI mode only | absent unless the kit was bought; a module can be installed once (D) |
| HPE Gen10, and Gen10 Plus with Xeon Scalable | a connector and a kit; pre-configured Gen10 Plus models include it | yes, UEFI mode only | (D) |
| HPE DL20 Gen10 Plus | embedded | yes | "enabled by default" (D) |
| HPE Gen11 | embedded: "no longer requires TPM module option kit" | yes | default state not stated for the DL380 (D) |
| Lenovo x3650 M5, ThinkSystem SR630 / SR650 V1 | a chip on the board | 1.2 or 2.0, a firmware setting | which is active as shipped: not established (D) |
| Lenovo ThinkSystem V2, V3 | a chip on the board | 2.0 only (D) | |
| Supermicro X9, X10, most X11; H11 to H13 (EPYC) | a header only; the module (AOM-TPM-9665V, -9670V) is sold separately | with the module | no firmware TPM on these, by Supermicro's own list (D); whether EPYC boards expose AMD's: not established |
| Supermicro X12, X13 (Intel) | a header, and Intel's firmware TPM (PTT) in the setup menu | yes without a module | default not established (D) |
| ASRock Rack E3C2xx, EPYCD8, ROMED8 | a header only | with a module | (D) |
| ASRock Rack X470D4U, B550D4U, X570D4U, B650D4U; Gigabyte MC12-LE0 | a header, and AMD's firmware TPM | **yes without a module** | B650D4U: "Auto for fTPM"; MC12-LE0: "Default setting is AMD fTPM" (D) |
| Consumer Ryzen and recent Core boards | the processor's firmware TPM | yes | varies; often to be enabled (I) |

Not looked at: Fujitsu, ASUS and Tyan server boards, HPE's AMD models of
Gen10, Atom C2000 / C3000 and Xeon D boards.

What the hosts themselves say:
- **IBM Cloud bare metal:** "all support TPM 2.0 from Infineon", installed,
  to be enabled (D). **Oracle Cloud bare metal:** a hardware TPM, lost on
  migration to another machine (D).
- **Scaleway Elastic Metal:** a physical TPM on named offers, and a
  statement that modules are fitted on new compatible models; a firmware
  update can reset it (D, read through a search excerpt). Nothing for
  Dedibox.
- **OVHcloud:** no official page. Users on its forum: the current
  non-Eco lines "should have a V2.0 TPM chip", the older Kimsufi and So
  you Start ones may not (I).
- **Hetzner:** its documentation does not mention a TPM (D, by absence).
  A third-party guide: the consumer-grade lines have a firmware TPM, the
  server-grade ones "will most likely lack TPM support" (I).
- **Voxility:** a TPM 2.0 module as a paid extra, about $95 a month (I).

### 12.4 What follows for a key kept there

- **Ask before renting, check after.** `cat
  /sys/class/tpm/tpm0/tpm_version_major` must print 2, and
  `scripts/tpm-check.sh --make-srk` must pass. A setting in the firmware
  setup needs the host's remote console; where no module is fitted, no
  setting exists.
- **The low-priced route is a firmware TPM**, which is what the project
  already runs on a laptop. It is not a separate chip: its state is in the
  board's flash, the known attacks on it need the machine in hand
  (faulTPM, §5), and a rented machine's firmware is the host's to update.
- **A replaced board is a lost key.** Dell's and HPE's modules are bound
  to the system board (D), and a firmware TPM lives on it. Hetzner
  replaced the boards of three AMD lines in 2025 for a design fault (I).
  The agent's key is then gone and the owner grants a new one: the case
  `RESILIENCE.md` already has for a cleared TPM.
- **The previous tenant.** Only IBM documents clearing the chip between
  tenants (§5). On taking a machine over, look at the persistent handles
  before creating keys, and evict ours before giving it back.

### 12.5 Sources for this section

Clouds:
[Oracle shielded instances](https://docs.oracle.com/iaas/Content/Compute/References/shielded-instances.htm),
[Alibaba trusted computing](https://www.alibabacloud.com/help/en/ecs/user-guide/overview-of-trusted-computing-capabilities),
[Huawei QingTian TPM](https://support.huaweicloud.com/intl/en-us/usermanual-ecs/ecs_03_3201.html),
[Exoscale changelog](https://changelog.exoscale.com/tpm-20-support-for-virtual-machines/),
[Gcore VM types](https://docs.gcore.com/cloud/virtual-instances/types-of-virtual-machines),
[Infomaniak](https://docs.infomaniak.cloud/compute/instances/advanced_usage/),
[Hetzner Cloud FAQ](https://docs.hetzner.com/cloud/servers/faq/),
[OVHcloud roadmap request](https://github.com/ovh/infrastructure-roadmap/issues/380),
[OpenStack emulated TPM](https://docs.openstack.org/nova/latest/admin/emulated-tpm.html).

Offers:
[WebHostingTalk, Dedicated Hosting Offers](https://www.webhostingtalk.com/forumdisplay.php?f=36)
(excerpts only),
[Hetzner AX](https://www.hetzner.com/dedicated-rootserver/matrix-ax/),
[EX](https://www.hetzner.com/dedicated-rootserver/matrix-ex/),
[DX](https://www.hetzner.com/dedicated-rootserver/matrix-dx/),
[OVHcloud Kimsufi](https://eco.ovhcloud.com/en/kimsufi/),
[Rise](https://eco.ovhcloud.com/en/rise/),
[Advance](https://www.ovhcloud.com/en/bare-metal/advance/),
[Worldstream](https://www.worldstream.com/en/dedicated-servers/),
[Dediroom](https://www.dediroom.com/cart.php?gid=101),
[NovoServe](https://novoserve.com/dedicated-servers),
[InterServer](https://www.interserver.net/dedicated/),
[ReliableSite](https://www.reliablesite.net/dedicated-servers/),
[Hivelocity](https://www.hivelocity.net/dedicated-servers/),
[Latitude.sh](https://www.latitude.sh/pricing),
[Contabo](https://contabo.com/en/dedicated-servers/).

Hardware:
Dell owner's manuals
([R720](https://dl.dell.com/topicspdf/poweredge-r720_owners-manual_en-us.pdf),
[R730](https://dl.dell.com/topicspdf/poweredge-r730_owners-manual_en-us.pdf),
[R640](https://dl.dell.com/topicspdf/poweredge-r640_owners-manual_en-us.pdf),
[R650](https://dl.dell.com/topicspdf/poweredge-r650_owners-manual_en-us.pdf),
[R6515](https://dl.dell.com/topicspdf/poweredge-r6515_owners-manual_en-us.pdf))
and [Dell on the TPM option](https://www.dell.com/en-us/lp/hmc-trusted-platform-module);
HPE QuickSpecs
([Gen9](https://support.hpe.com/hpesc/public/api/document/c04346247),
[Gen10](https://support.hpe.com/hpesc/public/api/document/a00008180enw),
[DL20 Gen10 Plus](https://support.hpe.com/hpesc/public/api/document/a50002583enw),
[DL380 Gen11](https://support.hpe.com/hpesc/public/api/document/a50004307enw),
[TPM kits](https://support.hpe.com/hpesc/public/api/document/c04939549));
Lenovo Press
([SR650](https://lenovopress.lenovo.com/lp1050.pdf),
[V2](https://lenovopress.lenovo.com/lp1392.pdf),
[V3](https://lenovopress.lenovo.com/lp1601.pdf),
[x3650 M5](https://lenovopress.lenovo.com/lp0068.pdf));
Supermicro
([which boards have PTT](https://www.supermicro.com/support/faqs/faq.cfm?faq=34689),
[the 9670 module](https://supermicro.com/manuals/other/AOM-TPM-9670V_9670H__X12_H12.pdf));
ASRock Rack manuals
([B650D4U](https://download.asrock.com/Manual/B650D4U.pdf),
[B550D4U](https://download.asrock.com/Manual/B550D4U.pdf),
[EPYCD8](https://download.asrock.com/Manual/EPYCD8.pdf));
[Gigabyte MC12-LE0](https://download.gigabyte.com/FileList/Manual/server_manual_MC12-LE0_e_v1.0.pdf).

Hosts on the TPM:
[IBM bare metal](https://www.ibm.com/new/announcements/securing-the-boot-process-for-ibm-cloud-bare-metal-servers-for-vpc),
[Scaleway Elastic Metal](https://www.scaleway.com/en/docs/elastic-metal/reference-content/elastic-metal-security-features/),
[OVHcloud community](https://community.ovhcloud.com/t/which-servers-have-tpm-v2/1278),
[IncusOS on a Hetzner server](https://linuxcontainers.org/incus-os/docs/main/getting-started/installation/cloud-hetzner/),
[Hetzner board replacement](https://docs.hetzner.com/robot/dedicated-server/general-information/mainboard-replacement-for-several-dedicated-servers/).
