# `swarm-treasury` — offline 2-of-3 custody for the SWARM treasury

`swarm-treasury` is an offline, file-based tool for holding a SWARM treasury fund under a 2-of-3
P2SH policy across three separate owner devices, and for disbursing from it.

It is the working form of what tasks T1 and T2 proved: T1 showed that real 2-of-3 signatures
satisfy the maintained script interpreter, T2 showed that a mature treasury coinbase output can be
spent into a real shielded note with a real Halo2 proof, and this tool turns that into a ceremony
three devices can actually run. The construction code is shared: the T2 fixture
(`zebra-consensus/tests/swarm_treasury_shielded_spend.rs`) drives the same
`swarm_treasury::shielded` module the tool uses, so the two cannot drift apart.

It replaces `swarm-keytool` for custody. `swarm-keytool` generates all N secret keys in one process
and writes them to one plaintext JSON file; that is a useful testnet address generator and an
unusable custody tool, because a single machine sees every key. Here each device generates exactly
one key and never sees the other two.

> **This is not an audited custody product.** Read “What this tool does not do”, at the end, before
> putting real value behind it.

---

## The policy it implements

A treasury collector output is a **coinbase** output. Under the preserved consensus rules a
transaction that spends a coinbase output may not have **any** transparent output — not even change
back to the same 2-of-3 address. So the only disbursement shape that is valid is:

> select **whole** mature collector UTXOs, and pay **all** of their value minus the approved fee to
> the intended shielded recipient, with **no change output of any kind**.

`spend propose` implements exactly that and refuses anything else. The consequence is real and
worth stating plainly: **the amount paid is decided by which UTXOs you select, not by a number you
choose.** If you need an exact amount, you cannot get it from this tool without leaving a remainder
somewhere, and leaving a remainder under a single key would quietly abandon 2-of-3 control over it.
Stop and take that decision deliberately instead.

From NU6.3 the Orchard pool is frozen against new inflows, so the mainnet disbursement pays into
**Ironwood** (`--network-upgrade nu6_3`). The v5/Orchard path (`nu5`) exists only as a test path.

## The files

Everything moves between devices as files. Each has a `schema` tag and a `schema_version`, and each
is refused if its schema is not the one expected.

| File | Schema | Holds | Secret? |
| --- | --- | --- | --- |
| `<label>.signer.age` | `swarm-treasury.signer-secret` (inside the `age` file) | one signer's secret key | **yes** |
| `<label>.public.json` | `swarm-treasury.signer-public` | one signer's public key, fingerprint, label | no |
| `policy.json` | `swarm-treasury.policy` | fund, network, threshold, ordered keys, redeem script, script hash, address, policy fingerprint | no |
| `utxos.json` | `swarm-treasury.utxos` | hand-exported unspent outputs | no |
| `proposal.json` | `swarm-treasury.proposal` | unsigned transaction, per-input digests, amounts, recipient | no |
| `<label>.sig.json` | `swarm-treasury.signature` | one signer's DER signatures | no |
| `final.hex` / `final.json` | `swarm-treasury.final` | the raw transaction and its record | no |

The **fingerprint** of a signer is the first 8 bytes of `SHA-256(compressed public key)`. The
**policy fingerprint** is the first 16 bytes of `SHA-256` over the fund, the network, the threshold
and the redeem script — so re-assembling the same policy on another day gives the same fingerprint,
and a changed key, order or threshold gives a different one. The **proposal hash** covers the raw
transaction, the outputs being spent, and the recipient, memo, fee, amounts and expiry a signer
reads on screen.

## The ceremony

### 1. Each device makes its own key

On device A, and separately on devices B and C:

```
swarm-treasury signer new --label A --out /path/to/keys
```

The tool asks for a passphrase (or reads `SWARM_TREASURY_PASSPHRASE`), draws one secp256k1 key from
the OS CSPRNG, and writes two files:

* `A.signer.age` — the key, encrypted with [age](https://c2sp.org/age) using a passphrase (scrypt)
  recipient. This is authenticated encryption from an established, specified format; this tool
  writes no cryptography of its own.
* `A.public.json` — the public key, its fingerprint, the label and the time.

Neither file is ever overwritten: a second `signer new` with the same label fails.

**Share only `A.public.json`.** The `.age` file and its passphrase never leave the device together,
and never reach the other two devices at all.

### 2. The coordinator assembles the policy

Collect the three `*.public.json` files on the coordinator machine, then:

```
swarm-treasury policy assemble --fund Core --threshold 2 --network testnet \
  --public A.public.json --public B.public.json --public C.public.json \
  --out policy.json
```

The key order is the order you give. It is not sorted, and it is what the address commits to.

### 3. Every device verifies the policy

Copy `policy.json` to each device and run, on each:

```
swarm-treasury policy verify policy.json
```

This recomputes the redeem script, the script hash, the address and the policy fingerprint from the
public keys in the file. A swapped key, a reordered key list, a lowered threshold, a wrong address
or an edited fingerprint is refused. Each device should also confirm that its own public key and
fingerprint appear in the printed list, and that the printed **policy fingerprint** is the same on
all three devices. That fingerprint is what every later signature is bound to.

The printed address is where the fund's collector outputs are paid.

### 4. The coordinator proposes a disbursement

Export the fund's unspent outputs from a node **you** run, by hand, into `utxos.json`:

```json
{
  "schema": "swarm-treasury.utxos",
  "schema_version": 1,
  "network": "testnet",
  "utxos": [
    {
      "txid": "…64 hex, the id a block explorer shows…",
      "vout": 0,
      "value": 312500000,
      "height": 4200000,
      "is_coinbase": true,
      "script": "a914…87"
    }
  ]
}
```

`script` must be the policy's P2SH locking script (`a914` + the policy's `script_hash` + `87`); any
other script is refused. Then:

```
swarm-treasury spend propose --policy policy.json --utxos utxos.json \
  --to <unified address, or a raw 43-byte Ironwood receiver in hex> \
  --fee 20000 --expiry-height 4200200 --network-upgrade nu6_3 \
  --memo "Q4 grant" --out proposal.json
```

Every listed UTXO is spent, whole. The tool builds the real Ironwood output with a real Halo2 proof
— which takes a few seconds and needs no signer key — computes the `SIGHASH_ALL` digest for each
input, and refuses if the fee is below the ZIP-317 conventional fee for the transaction it built.

### 5. Two devices read, then sign

Carry `proposal.json` to a signing device. **Read it before you unlock anything:**

```
swarm-treasury spend show proposal.json --policy policy.json
```

`show` re-parses the raw transaction out of the proposal, recomputes every digest from it, and
fails if the proposal's recorded digests do not match. What it prints — the recipient, the total in,
the fee, the amount out, the expiry, the inputs — is derived from the transaction, not copied from
the proposal's own summary. Check the recipient and the amount against what you were told
out-of-band, and check the policy fingerprint against the one you saw in step 3.

Then, on that device:

```
swarm-treasury spend sign --proposal proposal.json --signer A.signer.age \
  --policy policy.json --out A.sig.json
```

It asks for the backup passphrase, decrypts the key in memory, recomputes the digests
independently, signs each input, and writes `A.sig.json`. The secret is never written out and never
printed.

Repeat on a second device, with a different signer. Two of the three is enough; which two does not
matter.

### 6. The coordinator combines and broadcasts

```
swarm-treasury spend combine --proposal proposal.json \
  --sig A.sig.json --sig B.sig.json --policy policy.json --out final.hex
```

`combine` verifies each signature against the digest it recomputed, orders the signatures by the
policy's key order (not by the order the files arrived), assembles the scriptSigs, runs the
maintained script interpreter over every input, and checks the transaction's value balance pays
exactly the approved fee. It refuses a foreign key, the same signer twice, a signature for another
proposal or policy, and any count other than the threshold.

It writes `final.hex` (the raw transaction) and `final.json` (the txid and a record of what was
signed by whom). Broadcast with `sendrawtransaction` on a node you run.

A treasury coinbase output must be **100 blocks old** before it can be spent; the node will reject
the transaction otherwise, and it will also reject it after the expiry height passes.

## Backups and recovery

* Keep **two** encrypted copies of each `<label>.signer.age`, on separate media, in separate
  places. They are useless without the passphrase, so the risk they carry is loss, not disclosure.
* Keep the passphrase **separately from every copy of the backup**, written down, in a place the
  backup is not. A passphrase in the same drawer as the file is one item, not two.
* Never move a `.signer.age` file and its passphrase to the same third-party service.
* Each device's passphrase should be different. One passphrase across all three turns 2-of-3 into
  1-of-1 the moment it leaks.

Test the restore, on a **clean machine**, before the fund holds anything:

```
swarm-treasury signer recover --backup A.signer.age --expect A.public.json
```

This decrypts the backup, recomputes the public key from the secret it holds, and confirms it is
the key `A.public.json` names. It prints the label, the fingerprint and the public key — never the
secret.

To confirm a backup belongs to a fund without opening it any further:

```
swarm-treasury signer check --backup A.signer.age --policy policy.json
```

It says which of the policy's key positions the backup holds, and nothing about the secret.

Losing **one** device is survivable: the other two can still sign. Losing **two** loses the fund.
That is the whole point of the threshold, and no amount of tooling changes it.

## Passphrases, environment and file permissions

* A passphrase is **never** taken from the command line: it would be in the shell history and in
  every process listing on the machine. It comes from `SWARM_TREASURY_PASSPHRASE` if that is set,
  otherwise from a prompt. The prompt reads a whole line from standard input and **the terminal
  echoes it**; for an unattended run, set the environment variable instead.
* `SWARM_TREASURY_SCRYPT_LOG_N` lowers the scrypt work factor. It exists so the test suite is not
  spent in a key derivation function. **Leave it unset for anything real**; `age` then picks a work
  factor targeting about a second on the device.
* On Unix, `signer new` creates both files with mode `0600`.
* **On Windows there is no equivalent call here**, and the files inherit the ACL of the directory
  they are created in. Create the output directory somewhere only your user account can read — a
  folder under your own profile, or better, removable media you keep offline — and check its
  permissions yourself. The tool does not set or check Windows ACLs and does not pretend to.

## What this tool does not do

* **No hardware wallet, no hardware isolation.** The signer key is decrypted into the memory of an
  ordinary process on an ordinary computer. A compromised signing device is a compromised key. The
  separation this tool gives you is between *devices*, not between a device and its own operating
  system.
* **No transparent change, ever.** See “The policy it implements”. An exact-amount payment may be
  impossible; that is a custody decision to take deliberately, not a limitation to work around.
* **Whole UTXOs only.** There is no coin selection: every output listed in `utxos.json` is spent.
* **No network, no node, no broadcast.** The tool never opens a socket. `utxos.json` is a claim you
  made by hand, and the tool checks it against the policy's locking script but cannot check it
  against a chain. Broadcasting is a separate, manual step on a node you run.
* **No anchor or nullifier validation against a live chain.** The shielded bundle is built against
  the empty-tree anchor, and nothing here checks anchor membership or nullifier uniqueness — a
  node does that when it receives the transaction. The offline checks are the script interpreter,
  the value balance and the ZIP-317 fee rule.
* **No maturity or expiry check against a real chain.** The 100-block coinbase maturity rule and
  the expiry height are enforced by the node, not here. `spend show` prints the input heights and
  the expiry so a human can check them.
* **The recipient claim cannot be verified offline.** The note is encrypted; no offline tool can
  prove that a transaction's bundle pays the address a proposal says it pays. What the proposal
  hash does guarantee is that the claim a signer approved is the claim the signature was made
  against, and that editing it afterwards invalidates every signature. Confirm receipt with the
  recipient.
* **`swarmmain` is not encodable in this build.** The SWARM mainnet address prefixes are on another
  branch. `--network swarmmain` is accepted as a name and refused at the point an address would be
  produced, rather than handing back a testnet address for a mainnet policy. When the prefixes
  land, `TreasuryNetwork::address_encoding` in `swarm-treasury/src/network.rs` is the one place to
  change.
* **Not a governance system.** This is sole-owner custody across the owner's own devices, not
  multi-party governance.

## Dependencies

The only dependency outside the workspace and the already-locked set is
[`age`](https://crates.io/crates/age) **0.12.1**
(`sha256 fd290633c2482479f70f6d1d96ae0e9f52c6a26cd5859edd47ee1fe33fc89f26`), with default features
only — no `cli-common`, `plugin`, `ssh` or `armor`. It provides the authenticated encryption for
the signer backups. No encryption is implemented in this crate.
