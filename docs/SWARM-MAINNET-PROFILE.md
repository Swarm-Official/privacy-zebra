# The SwarmMain network profile

`Network::SwarmMain` is the SWARM production network as an explicit variant of the node's
`Network` type. It is **not** upstream Zcash Mainnet and it is **not** a test network, and the
code says so in both directions: `is_a_test_network()` returns `false` for it, and
`self == Network::Mainnet` is still the only way to ask "is this upstream Zcash Mainnet".

The definition lives in `zebra-chain/src/parameters/network/swarm_main.rs`. Everything below is
either a constant in that file or a field the operator must supply. There is no default profile:
`SwarmMainParameters` can only be obtained from `SwarmMainParametersBuilder::finish`, which
returns an error unless the definition is complete. A `Network::SwarmMain` value therefore means
the profile was validated, which is what lets the node check it **before** any listener or
database is opened.

## Fixed values

These are part of the network definition. Changing any of them forks the network, so they are
constants in the source, not configuration.

| Field | Value | Note |
| --- | --- | --- |
| network name | `SwarmMainnet` | the `Display` name |
| chain label | `swarm-mainnet` | what the indexer, wallet and RPC `chain` field compare |
| network magic | `SWMN` = `53 57 4d 4e` | distinct from Zcash main `24 e9 27 64`, Zcash test `fa 1a f9 bf`, SWARM testnet `SWRM` |
| default P2P port | 28233 | |
| default RPC port | 28232 | loopback only, cookie auth |
| SLIP-44 coin type | 9767 | |
| activation heights | every upgrade at height 1 | genesis at 0, NU6.3 rules from 1 |
| transaction domain | `0x53574d31` (`SWM1`) | `DomainRegistry::SWARM_PRODUCTION`, disjoint from every upstream domain |
| accepted transaction versions | V5 and V6 from height 1 | V1 to V4 rejected in blocks and the mempool; the genesis coinbase at height 0 is exempt, see "Transaction versions" |
| target difficulty limit | `07ff…ff` | the reviewed value; the same bound the SWARM testnet uses, deliberately not the Mainnet `2^243 - 1` |
| minimum-difficulty exception | off | the testnet exception is an attack surface on a production chain |
| max block time rule | from height 1 | no start-height exemption |
| coinbase maturity | 100 blocks | |
| unshielded coinbase spends | not allowed | the SWARM testnet relaxes this; production does not |
| slow start interval | 0 | full era-0 subsidy from block 1 |
| halving interval | 1,680,000 blocks (840,000 pre-Blossom) | identical to the SWARM testnet |
| funding stream range | heights 1 to 50,399,999 (exclusive end) | one range covers the whole emission schedule |
| funding stream numerators | 8 / 4 / 8 out of 100 | Core Development, Grants & Ecosystem, Community & Development Reserve; 80% plus all fees to the miner |
| checkpoints | none beyond genesis | SWARM has no history to checkpoint |
| peer seeds | none | the upstream lists name Zcash DNS seeders |
| founders' reward addresses | none | a pre-Canopy Zcash mechanism; no SWARM block is ever subject to it |

## Required configuration

Two things have no reviewed value until the launch ceremony, so they are required inputs:

- **genesis block hash** — generated at the ceremony from a public unpredictable input. There is
  deliberately no placeholder constant: a copied testnet or upstream genesis would make a
  misconfigured node follow the wrong chain. Supplying none fails with
  `SwarmMainParametersError::GenesisHashUnresolved`; supplying Zcash Mainnet's or the SWARM
  testnet's fails with `GenesisHashBelongsToAnotherNetwork`.
- **the three funding stream recipient addresses** — the keys are generated at the same ceremony.
  Only the destinations are configured; the numerators and the height range are fixed above. Each
  address must be a SWARM production pay-to-script-hash address (`s3…`). A missing, malformed,
  wrong-kind or foreign-network address is a separate, named error, and
  `FundingStreamRecipientWrongNetwork` names the network the address actually belongs to.

Optional: the P2P and RPC ports, which default to 28233 and 28232.

The configuration keys under `network.swarm_main.funding_stream_addresses` are
`core_development`, `grants_ecosystem` and `community_reserve`; the mapping from those keys to the
consensus `FundingStreamReceiver` slots is fixed in `swarm_main::FUNDING_STREAM_SLOTS`, so a
configuration cannot move an allocation between slots.

## Transparent addresses

SWARM production uses its own Base58Check version bytes, `0x1C28` for P2PKH (`s1…`) and `0x1C2D`
for P2SH (`s3…`). They are disjoint from every upstream prefix in both directions: a SWARM address
does not decode as a Zcash address and a Zcash address does not decode as a SWARM one.

ZIP-320 TEX addresses are **refused** on SwarmMain. ZIP-320 assigns a TEX address its own
two-byte version prefix per network, and SWARM has no reviewed assignment; the upstream prefixes
would encode a SWARM address that decodes as a Zcash one, and reusing SWARM's own P2PKH prefix
would make a serialized TEX address indistinguishable from a serialized P2PKH address on the same
network. Both decoders refuse it, so no such address is ever constructed. Supporting TEX on SWARM
means adding a reviewed prefix assignment first.

## Selecting it in `zebrad.toml`

```toml
[network]
network = "SwarmMainnet"

[network.swarm_main]
genesis_hash = "<the genesis hash from the launch ceremony>"
# optional; these are the defaults
p2p_port = 28233
rpc_port = 28232

[network.swarm_main.funding_stream_addresses]
core_development  = "s3..."
grants_ecosystem  = "s3..."
community_reserve = "s3..."
```

The whole section is validated while the configuration is deserialized, which is before any
listener is bound and before the state database is opened, so a node whose SwarmMain definition is
incomplete fails to start rather than starting on a half-defined production network. A
`[network.swarm_main]` section is rejected when `network` is anything other than `SwarmMainnet`,
so SWARM destinations cannot sit in the configuration of a node that is quietly running elsewhere.

## Transaction versions

SwarmMain accepts **only V5 and V6, from height 1 onward**. V1 to V4 are rejected in both block
and mempool validation, by `zebra_consensus::transaction::check::transaction_version_allowed`,
with `TransactionError::UnsupportedTransactionVersion`. They carry no `nConsensusBranchId` at all,
so an identical one would be valid on any chain that accepts that version, and the two-way replay
protection the SWARM domain provides would have a hole in it exactly the size of the transparent
transaction set. Upstream networks are unaffected by this check.

The genesis block at height 0 is exempt, because its coinbase is a legacy-version transaction:
the SWARM genesis is produced by the `privacy-miner genesis` tool from an upstream block fixture
whose coinbase is a V4. The exemption is safe for the same reason the rule exists — genesis has no
`nConsensusBranchId` on any network, it is pinned by hash in the network definition and by the
genesis checkpoint, and it spends nothing, so there is no replay to protect against. Height 0 is
`NetworkUpgrade::Genesis` in the SWARM activation list, and the SWARM domain registry deliberately
admits no branch ID for it, so `ConsensusBranchId::current(&swarm_main, Height(0))` is `None`.

## What is not done yet

- **Registry selection at the network-free entry points.** `ZcashSerialize`/`ZcashDeserialize for
  Transaction`, `TxIdBuilder::txid`, `auth_digest` and `PrecomputedTxData::new` have no network in
  scope and are still pinned to `DomainRegistry::UPSTREAM`, so a SwarmMain V5/V6 transaction
  cannot yet be serialized or hashed through them, and `zebra-consensus`'s
  `check::consensus_branch_id` still compares against the upstream table. The network-aware paths
  (`Transaction::to_librustzcash_in`, `PrecomputedTxData::new_in`, `ConsensusBranchId::current`,
  the ZIP-221 history domain and note decryption) already resolve through
  `Network::domain_registry()`. Changing the network-free ones means deciding whether an upstream
  node should keep rejecting a SWARM-domain transaction at decode or start rejecting it at
  validation. That is an observable change on upstream networks, so it needs its own review and
  its own commit. **Until it lands, a node configured for SwarmMain can be constructed and
  validated but cannot sync a chain.**
