//! Separation of consensus *rule* selection from transaction *domain* selection.
//!
//! Zcash conflates two different things in a single value. A [`NetworkUpgrade`] selects the
//! consensus rules in force at a height, while the `nConsensusBranchId` field that V5 and V6
//! transactions commit to selects the *replay domain* those transactions belong to (ZIP-200).
//! Upstream these are in bijection, so upstream code derives one from the other. A chain that
//! wants its own two-way replay protection needs a second domain for the same rules, so the
//! derivation has to become a lookup in an explicit table.
//!
//! This module introduces that table ([`DomainRegistry`]) and the validated pairing it produces
//! ([`ConsensusContext`]). Nothing here changes any existing result: the production registry is
//! exactly the closed upstream table in [`CONSENSUS_BRANCH_IDS`], so
//! [`DomainRegistry::context_at`] reproduces `NetworkUpgrade::current(network, height)` paired
//! with `NetworkUpgrade::branch_id()`, value for value.
//!
//! # Production domains
//!
//! No SWARM production consensus branch ID is admitted by [`DomainRegistry::UPSTREAM`], and this
//! module deliberately provides no way to add one at runtime.
//!
//! [`SWARM_PRODUCTION_DOMAIN`] is the SWARM chain's own domain, `0x53574d31`, and
//! [`DomainRegistry::SWARM_PRODUCTION`] is the registry that admits it and nothing else. The two
//! registries are disjoint in both directions, which is exactly the two-way replay protection
//! ZIP 200 domains exist for: an upstream transaction is rejected under the SWARM registry and a
//! SWARM transaction is rejected under the upstream one.
//!
//! Selection now happens in two places, and they are deliberately different. Every entry point
//! that has a network in scope -- the ZIP-221 history domain, note decryption, the sighash and
//! `PrecomputedTxData` construction inside verification, and every consensus check -- resolves
//! its registry through [`Network::domain_registry`], so it admits one family and rejects the
//! other. The four entry points that have no network in scope --
//! `ZcashSerialize`/`ZcashDeserialize` for `Transaction`, `TxIdBuilder::txid` and `auth_digest`
//! -- use [`DomainRegistry::ADMITTED`], the union of the two production families, so that one
//! binary can decode and hash transactions of either family. The replay protection is unchanged
//! in substance: it is enforced by validation, which compares a transaction's raw domain against
//! the one its network's registry resolves at that height.
//!
//! The remaining non-upstream domain defined here is [`FIXTURE_NU6_3_DOMAIN`], which is
//! `#[cfg(test)]` test data.

use crate::block;
use crate::parameters::{ConsensusBranchId, Network, NetworkUpgrade, CONSENSUS_BRANCH_IDS};

/// The consensus rules in force together with the transaction domain that transactions under
/// those rules must commit to.
///
/// # Correctness
///
/// The two fields are private and the pairing is not constructible from untrusted data. A context
/// can only be obtained from a [`DomainRegistry`], which is a closed table, or from
/// [`ConsensusContext::from_parts_for_test`] behind test features. In particular a context is
/// never built from a raw `nConsensusBranchId` read off the wire without looking that ID up in a
/// registry first.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConsensusContext {
    /// The consensus rules in force.
    rules: NetworkUpgrade,
    /// The transaction domain, serialized as `nConsensusBranchId` by V5 and V6 transactions.
    branch: ConsensusBranchId,
}

impl ConsensusContext {
    /// Returns the consensus rules in force in this context.
    pub fn rules(&self) -> NetworkUpgrade {
        self.rules
    }

    /// Returns the transaction domain of this context.
    pub fn branch(&self) -> ConsensusBranchId {
        self.branch
    }

    /// Builds a context from its parts without consulting a registry.
    ///
    /// # Correctness
    ///
    /// This is test scaffolding. It exists so that fixtures can express a rule set paired with a
    /// domain that no production registry admits. It must never be reachable from production
    /// code, which is why it is gated on test features.
    #[cfg(any(test, feature = "proptest-impl"))]
    pub fn from_parts_for_test(rules: NetworkUpgrade, branch: ConsensusBranchId) -> Self {
        Self { rules, branch }
    }
}

/// A deliberately fake consensus branch ID used only by `zebra-chain`'s own tests.
///
/// This is test data, not a candidate value: `0x7E57_0001` reads as "TEST 0001" and is not a
/// SWARM production domain, nor a proposal for one. It exists so that tests can exercise the case
/// of two domains selecting the same rule set (NU6.3), which upstream cannot express because its
/// table is a bijection. It is not admitted by [`DomainRegistry::UPSTREAM`], so it is rejected by
/// every production decode, encode and conversion path.
#[cfg(test)]
pub(crate) const FIXTURE_NU6_3_DOMAIN: ConsensusBranchId = ConsensusBranchId(0x7E57_0001);

/// The test-only domains added on top of the upstream table by [`DomainRegistry::FIXTURE`].
#[cfg(test)]
const FIXTURE_DOMAINS: &[(NetworkUpgrade, ConsensusBranchId)] =
    &[(NetworkUpgrade::Nu6_3, FIXTURE_NU6_3_DOMAIN)];

/// The SWARM production transaction domain: `0x53574d31`, the ASCII bytes `SWM1`.
///
/// This is the `nConsensusBranchId` (ZIP 200) that SWARM production V5 and V6 transactions commit
/// to. SWARM runs the NU6.3 (Ironwood) rule revision from height 1, so it needs the same *rules*
/// as upstream NU6.3 but a different *domain*, otherwise transactions would replay between the
/// two chains in both directions.
///
/// # Correctness
///
/// This value is disjoint from every entry in [`CONSENSUS_BRANCH_IDS`], and it is admitted only
/// by [`DomainRegistry::SWARM_PRODUCTION`]. It is the same value as
/// `zcash_protocol::consensus::BranchId::SwarmMain`, which the vendored protocol crate admits so
/// that the ZIP-244 digests can be computed over it; the test
/// `swarm_production_domain_matches_the_vendored_protocol_crate` pins the two together.
pub const SWARM_PRODUCTION_DOMAIN: ConsensusBranchId = ConsensusBranchId(0x5357_4d31);

/// The `(rules, domain)` table of the SWARM production profile.
///
/// # Correctness
///
/// SWARM activates every network upgrade at height 1, so `NetworkUpgrade::current` returns
/// `Genesis` at height 0 and the NU6.3 rules at every height from 1 on, exactly as the SWARM
/// testnet schedule behaves today. `Genesis` and `BeforeOverwinter` have no consensus branch ID
/// in any registry, including the upstream one, so a single NU6.3 entry covers the whole
/// schedule; no pre-NU6.3 entry is reachable, and adding one would be worse than useless, because
/// admitting an upstream domain here would break replay protection in the inbound direction.
const SWARM_PRODUCTION_DOMAINS: &[(NetworkUpgrade, ConsensusBranchId)] =
    &[(NetworkUpgrade::Nu6_3, SWARM_PRODUCTION_DOMAIN)];

/// A closed table mapping admitted transaction domains to the consensus rules they select.
///
/// # Correctness
///
/// A registry is a `const` table, not a runtime collection: there is no way to insert a domain
/// into one. `base` always holds the upstream table. `extra` holds additional domains and is
/// empty in every registry that exists in a non-test build.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DomainRegistry {
    /// A short name used in diagnostics.
    name: &'static str,
    /// The profile's closed `(rules, domain)` table: the upstream table for every upstream
    /// registry, and the SWARM table for [`DomainRegistry::SWARM_PRODUCTION`].
    base: &'static [(NetworkUpgrade, ConsensusBranchId)],
    /// Extra admitted domains. Empty in every registry that exists in a non-test build.
    extra: &'static [(NetworkUpgrade, ConsensusBranchId)],
}

impl DomainRegistry {
    /// The production registry: the closed upstream table and nothing else.
    ///
    /// # Correctness
    ///
    /// This is the only registry reachable from production code. It admits exactly the domains in
    /// [`CONSENSUS_BRANCH_IDS`], so every lookup here returns the same value the pre-existing
    /// `NetworkUpgrade::try_from` / `NetworkUpgrade::branch_id` pair returns. No SWARM production
    /// ID is admitted.
    pub const UPSTREAM: &'static DomainRegistry = &DomainRegistry {
        name: "upstream",
        base: CONSENSUS_BRANCH_IDS,
        extra: &[],
    };

    /// The SWARM production registry: the SWARM domain under the NU6.3 rules, and nothing else.
    ///
    /// # Correctness
    ///
    /// This registry and [`DomainRegistry::UPSTREAM`] are disjoint in both directions. It admits
    /// [`SWARM_PRODUCTION_DOMAIN`] and no upstream domain, so an upstream NU6.3 transaction is
    /// rejected under it; and [`DomainRegistry::UPSTREAM`] does not admit
    /// [`SWARM_PRODUCTION_DOMAIN`], so a SWARM transaction is rejected under that one. That pair
    /// of rejections is the two-way replay protection.
    ///
    /// No production entry point selects this registry yet. It is reachable only by explicitly
    /// naming it, which at this point only tests do; the network-driven selection is the next
    /// slice and needs the SWARM network variant.
    pub const SWARM_PRODUCTION: &'static DomainRegistry = &DomainRegistry {
        name: "swarm-production",
        base: SWARM_PRODUCTION_DOMAINS,
        extra: &[],
    };

    /// The registry the network-free entry points admit: the union of the two production
    /// families, and nothing else.
    ///
    /// # Why a union, and why it is not a weakening
    ///
    /// `ZcashSerialize`/`ZcashDeserialize for Transaction`, `TxIdBuilder::txid` and
    /// `auth_digest` have no network in scope: they are reached from the block and transaction
    /// codecs, from Merkle root construction and from `Transaction::hash()`, none of which can
    /// name a network. Pinning them to [`DomainRegistry::UPSTREAM`] meant a SwarmMain node could
    /// not decode or hash its own transactions at all. Pinning them per-network would mean
    /// threading a `&Network` through every one of those call sites, including trait methods
    /// whose signatures are fixed by the serialization traits.
    ///
    /// So these four admit both closed families, and *validation* decides which one a given
    /// network accepts. That moves the SWARM/upstream rejection from decode time to validation
    /// time, and nowhere else:
    ///
    /// * `zebra_consensus::transaction::check::consensus_branch_id` requires every V5/V6
    ///   transaction's raw domain to equal `network.domain_registry().context_at(network,
    ///   height)`, for block and mempool verification alike.
    /// * `Block::check_transaction_network_upgrade_consistency` applies the same equality over a
    ///   whole block, and is called from both the block verifier and the state.
    /// * the sighash/`PrecomputedTxData` construction inside verification resolves its context
    ///   from the network, never from the transaction's own claim, and
    ///   `Transaction::to_librustzcash_in` then refuses a transaction whose stored domain differs
    ///   from that context.
    ///
    /// # Correctness
    ///
    /// This is still a closed `const` table with no runtime insertion. It admits exactly
    /// [`CONSENSUS_BRANCH_IDS`] plus [`SWARM_PRODUCTION_DOMAIN`]; the `#[cfg(test)]` fixture
    /// domain and every other unknown ID are still rejected at decode.
    ///
    /// Because the upstream table is listed first, `context_for_rules` on this registry returns
    /// the *upstream* domain for the NU6.3 rules. That makes it the wrong registry to ever
    /// *choose* a domain with. It is only ever used to ask whether a domain read off the wire is
    /// one of the two production families, and which rules that domain selects. Production code
    /// that produces or validates a domain resolves it through `Network::domain_registry`
    /// instead.
    pub const ADMITTED: &'static DomainRegistry = &DomainRegistry {
        name: "admitted",
        base: CONSENSUS_BRANCH_IDS,
        extra: SWARM_PRODUCTION_DOMAINS,
    };

    /// A `#[cfg(test)]` registry that also admits [`FIXTURE_NU6_3_DOMAIN`] under the NU6.3 rules.
    ///
    /// # Correctness
    ///
    /// Test data only. Because the fixture domain is listed *after* the upstream table, looking
    /// rules up in this registry still returns the upstream domain, so contexts derived from a
    /// height are identical to the ones [`DomainRegistry::UPSTREAM`] returns.
    #[cfg(test)]
    pub(crate) const FIXTURE: &'static DomainRegistry = &DomainRegistry {
        name: "test-fixture",
        base: CONSENSUS_BRANCH_IDS,
        extra: FIXTURE_DOMAINS,
    };

    /// Returns this registry's name, for diagnostics.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the admitted `(rules, domain)` entries, upstream first.
    fn entries(&self) -> impl Iterator<Item = &'static (NetworkUpgrade, ConsensusBranchId)> {
        self.base.iter().chain(self.extra.iter())
    }

    /// Returns the context in force on `network` at `height`.
    ///
    /// Returns `None` for heights whose network upgrade has no consensus branch ID, that is for
    /// Genesis and BeforeOverwinter, exactly as `NetworkUpgrade::branch_id` does.
    ///
    /// # Correctness
    ///
    /// For [`DomainRegistry::UPSTREAM`] this is `NetworkUpgrade::current(network, height)` paired
    /// with that upgrade's `branch_id()`, which is what every caller computed before this type
    /// existed.
    pub fn context_at(&self, network: &Network, height: block::Height) -> Option<ConsensusContext> {
        self.context_for_rules(NetworkUpgrade::current(network, height))
    }

    /// Returns the context this registry uses when *producing* transactions under `rules`.
    ///
    /// When several domains select the same rules, the first admitted domain wins, so the
    /// upstream domain is always preferred.
    pub fn context_for_rules(&self, rules: NetworkUpgrade) -> Option<ConsensusContext> {
        self.entries()
            .find(|(nu, _)| *nu == rules)
            .map(|(rules, branch)| ConsensusContext {
                rules: *rules,
                branch: *branch,
            })
    }

    /// Resolves a raw `nConsensusBranchId` to a context.
    ///
    /// Returns `None` for a domain this registry does not admit; there is no fallback and no
    /// guess about what rules an unknown ID might mean.
    pub fn context_for_branch(&self, branch: ConsensusBranchId) -> Option<ConsensusContext> {
        self.entries()
            .find(|(_, id)| *id == branch)
            .map(|(rules, branch)| ConsensusContext {
                rules: *rules,
                branch: *branch,
            })
    }

    /// Returns true if this registry admits `branch` as a transaction domain.
    ///
    /// # Correctness
    ///
    /// For [`DomainRegistry::UPSTREAM`] this is exactly
    /// `NetworkUpgrade::try_from(u32::from(branch)).is_ok()`, so the wire-level recognition gate
    /// is unchanged.
    pub fn admits(&self, branch: ConsensusBranchId) -> bool {
        self.context_for_branch(branch).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every height on every existing network resolves to exactly the rules and domain the
    /// pre-existing pairing resolved to.
    #[test]
    fn upstream_registry_reproduces_the_existing_pairing() {
        let _init_guard = zebra_test::init();

        for network in [Network::Mainnet, Network::new_default_testnet()] {
            let mut heights: Vec<block::Height> = vec![block::Height(0), block::Height(1)];
            for (height, _) in network.full_activation_list() {
                heights.push(height);
                if let Ok(before) = height.previous() {
                    heights.push(before);
                }
                if let Ok(after) = height.next() {
                    heights.push(after);
                }
            }

            for height in heights {
                let expected_rules = NetworkUpgrade::current(&network, height);
                let expected_branch = ConsensusBranchId::current(&network, height);

                let context = DomainRegistry::UPSTREAM.context_at(&network, height);

                assert_eq!(
                    context.map(|ctx| ctx.rules()),
                    expected_branch.map(|_| expected_rules),
                    "{network} height {height:?}: rules must match, and a context must exist \
                     exactly when a branch ID does"
                );
                assert_eq!(
                    context.map(|ctx| ctx.branch()),
                    expected_branch,
                    "{network} height {height:?}: domain must match"
                );
            }
        }
    }

    /// The production registry admits exactly the closed upstream table.
    #[test]
    fn upstream_registry_admits_exactly_the_upstream_table() {
        for (rules, branch) in CONSENSUS_BRANCH_IDS {
            assert!(DomainRegistry::UPSTREAM.admits(*branch));
            assert_eq!(
                DomainRegistry::UPSTREAM
                    .context_for_branch(*branch)
                    .map(|ctx| ctx.rules()),
                Some(*rules)
            );
            assert_eq!(
                DomainRegistry::UPSTREAM
                    .context_for_rules(*rules)
                    .map(|ctx| ctx.branch()),
                rules.branch_id()
            );
        }

        for unknown in [0x0000_0000u32, 0x7E57_0001, 0xdead_beef] {
            let unknown = ConsensusBranchId::from(unknown);
            assert!(!DomainRegistry::UPSTREAM.admits(unknown));
            assert_eq!(DomainRegistry::UPSTREAM.context_for_branch(unknown), None);
        }

        // Upgrades with no branch ID have no context.
        assert_eq!(
            DomainRegistry::UPSTREAM.context_for_rules(NetworkUpgrade::Genesis),
            None
        );
        assert_eq!(
            DomainRegistry::UPSTREAM.context_for_rules(NetworkUpgrade::BeforeOverwinter),
            None
        );
    }

    /// The SWARM production domain is the value the identity proposal froze, and is the same
    /// value the vendored `zcash_protocol` admits as `BranchId::SwarmMain`.
    #[test]
    fn swarm_production_domain_matches_the_vendored_protocol_crate() {
        assert_eq!(u32::from(SWARM_PRODUCTION_DOMAIN), 0x5357_4d31);
        assert_eq!(
            u32::from(SWARM_PRODUCTION_DOMAIN).to_be_bytes(),
            *b"SWM1",
            "the domain is the ASCII bytes SWM1"
        );

        let branch =
            zcash_protocol::consensus::BranchId::try_from(u32::from(SWARM_PRODUCTION_DOMAIN))
                .expect("the vendored protocol crate admits the SWARM production domain");
        assert_eq!(branch, zcash_protocol::consensus::BranchId::SwarmMain);
        assert_eq!(u32::from(branch), u32::from(SWARM_PRODUCTION_DOMAIN));

        // The SWARM domain selects the NU6.3 rules, and answers every rule question exactly as
        // NU6.3 does.
        let nu6_3 = zcash_protocol::consensus::BranchId::Nu6_3;
        assert_eq!(
            branch.network_upgrade(),
            Some(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
        );
        assert_eq!(branch.network_upgrade(), nu6_3.network_upgrade());
        assert_eq!(branch.has_sprout(), nu6_3.has_sprout());
        assert_eq!(branch.has_sapling(), nu6_3.has_sapling());
        assert_eq!(branch.has_orchard(), nu6_3.has_orchard());
        assert_eq!(
            branch.sprout_uses_groth_proofs(),
            nu6_3.sprout_uses_groth_proofs()
        );
        assert_eq!(
            branch.orchard_protocol_revision(),
            nu6_3.orchard_protocol_revision()
        );
        assert_eq!(
            branch.height_bounds(&zcash_protocol::consensus::MAIN_NETWORK),
            nu6_3.height_bounds(&zcash_protocol::consensus::MAIN_NETWORK)
        );
        assert_eq!(
            branch.height_bounds(&zcash_protocol::consensus::TEST_NETWORK),
            nu6_3.height_bounds(&zcash_protocol::consensus::TEST_NETWORK)
        );
    }

    /// `BranchId::for_height` never returns the SWARM domain for an upstream network.
    ///
    /// The SWARM domain is named by no [`NetworkUpgrade`], and `for_height` can only return a
    /// domain that some upgrade names, so this holds structurally; it is asserted here over the
    /// upstream `Main` and `Test` parameters and over Zebra's own `Mainnet`, default testnet and
    /// Regtest networks, which all implement the same `Parameters` trait.
    #[test]
    fn upstream_networks_never_select_the_swarm_domain_by_height() {
        use zcash_protocol::consensus::{BlockHeight, BranchId, MAIN_NETWORK, TEST_NETWORK};

        let heights = [
            0u32,
            1,
            2,
            419_200,
            1_046_400,
            2_726_400,
            5_000_000,
            u32::MAX,
        ];

        for height in heights {
            let height = BlockHeight::from_u32(height);
            assert_ne!(
                BranchId::for_height(&MAIN_NETWORK, height),
                BranchId::SwarmMain
            );
            assert_ne!(
                BranchId::for_height(&TEST_NETWORK, height),
                BranchId::SwarmMain
            );
        }

        for network in [
            Network::Mainnet,
            Network::new_default_testnet(),
            Network::new_regtest(Default::default()),
        ] {
            for height in heights {
                let height = BlockHeight::from_u32(height);
                assert_ne!(
                    BranchId::for_height(&network, height),
                    BranchId::SwarmMain,
                    "{network} height {height:?} must not select the SWARM production domain"
                );
            }
        }
    }

    /// A block built for SwarmMain picks the SWARM production domain, and the V6 transaction
    /// version that goes with it.
    ///
    /// This is what the coinbase builder and the block template do: `Builder::new` resolves
    /// `BranchId::for_height` from the network, and takes the transaction version from that
    /// branch. Before the SWARM network type was taught to `for_height`, a SwarmMain coinbase
    /// would have been built under the *upstream* NU6.3 domain and rejected by SwarmMain's own
    /// validation.
    #[test]
    fn swarm_main_selects_its_own_domain_and_the_v6_version_when_building() {
        use zcash_primitives::transaction::TxVersion;
        use zcash_protocol::consensus::{BlockHeight, BranchId};

        let _init_guard = zebra_test::init();

        let swarm = crate::parameters::swarm_main::fixture::network();

        // Height 0 is Genesis: no domain applies, exactly as on every other network.
        assert_eq!(
            BranchId::for_height(&swarm, BlockHeight::from_u32(0)),
            BranchId::Sprout
        );

        for height in [1u32, 2, 100, 1_000_000, u32::MAX] {
            let height = BlockHeight::from_u32(height);
            let branch = BranchId::for_height(&swarm, height);

            assert_eq!(
                branch,
                BranchId::SwarmMain,
                "a transaction built for SwarmMain at {height:?} must carry the SWARM domain"
            );
            assert_eq!(u32::from(branch), u32::from(SWARM_PRODUCTION_DOMAIN));

            // V5/V6 only from height 1: the builder must not reach for a legacy version.
            assert_eq!(
                TxVersion::suggested_for_branch(branch),
                TxVersion::V6,
                "a SwarmMain coinbase at {height:?} must be a V6"
            );
        }

        // And the domain the network's own registry resolves at those heights is the same one, so
        // a coinbase built this way passes the validation this patch adds.
        for height in [block::Height(1), block::Height(2), block::Height(1_000_000)] {
            assert_eq!(
                swarm
                    .domain_registry()
                    .context_at(&swarm, height)
                    .map(|ctx| ctx.branch()),
                Some(SWARM_PRODUCTION_DOMAIN)
            );
        }
    }

    /// The SWARM production registry admits exactly one domain, and is disjoint from the upstream
    /// registry in both directions.
    #[test]
    fn swarm_production_registry_is_disjoint_from_upstream() {
        let _init_guard = zebra_test::init();

        let swarm = DomainRegistry::SWARM_PRODUCTION
            .context_for_branch(SWARM_PRODUCTION_DOMAIN)
            .expect("the SWARM registry admits the SWARM domain");
        assert_eq!(swarm.rules(), NetworkUpgrade::Nu6_3);
        assert_eq!(swarm.branch(), SWARM_PRODUCTION_DOMAIN);
        assert_eq!(
            DomainRegistry::SWARM_PRODUCTION.context_for_rules(NetworkUpgrade::Nu6_3),
            Some(swarm)
        );

        // Outbound: no upstream domain is admitted here, including upstream NU6.3, which selects
        // the very same rules.
        for (_rules, branch) in CONSENSUS_BRANCH_IDS {
            assert!(
                !DomainRegistry::SWARM_PRODUCTION.admits(*branch),
                "the SWARM registry must not admit the upstream domain {branch}"
            );
        }

        // Inbound: the upstream registry does not admit the SWARM domain.
        assert!(!DomainRegistry::UPSTREAM.admits(SWARM_PRODUCTION_DOMAIN));
        assert_eq!(
            DomainRegistry::UPSTREAM.context_for_branch(SWARM_PRODUCTION_DOMAIN),
            None
        );
        assert!(NetworkUpgrade::try_from(u32::from(SWARM_PRODUCTION_DOMAIN)).is_err());

        // The fixture registry is likewise unrelated to the production domain.
        assert!(!DomainRegistry::FIXTURE.admits(SWARM_PRODUCTION_DOMAIN));
        assert!(!DomainRegistry::SWARM_PRODUCTION.admits(FIXTURE_NU6_3_DOMAIN));

        // Rules with no consensus branch ID have no context here either, so a height-1 schedule
        // resolves height 0 (Genesis) to no domain, exactly as upstream does.
        assert_eq!(
            DomainRegistry::SWARM_PRODUCTION.context_for_rules(NetworkUpgrade::Genesis),
            None
        );
        assert_eq!(
            DomainRegistry::SWARM_PRODUCTION.context_for_rules(NetworkUpgrade::BeforeOverwinter),
            None
        );
    }

    /// `context_at` under the SWARM registry yields the SWARM context exactly at the heights
    /// whose rules are NU6.3, which for a schedule with every activation at height 1 is every
    /// height from 1 on.
    #[test]
    fn swarm_production_registry_resolves_heights_by_rules() {
        let _init_guard = zebra_test::init();

        for network in [Network::Mainnet, Network::new_default_testnet()] {
            let mut heights: Vec<block::Height> = vec![block::Height(0), block::Height(1)];
            for (height, _) in network.full_activation_list() {
                heights.push(height);
                if let Ok(after) = height.next() {
                    heights.push(after);
                }
            }

            for height in heights {
                let rules = NetworkUpgrade::current(&network, height);
                let expected = (rules == NetworkUpgrade::Nu6_3).then(|| {
                    DomainRegistry::SWARM_PRODUCTION
                        .context_for_rules(NetworkUpgrade::Nu6_3)
                        .expect("NU6.3 has a SWARM domain")
                });

                assert_eq!(
                    DomainRegistry::SWARM_PRODUCTION.context_at(&network, height),
                    expected,
                    "{network} height {height:?}: the SWARM registry admits only the NU6.3 rules"
                );
            }
        }
    }

    /// The test fixture adds a second domain for the NU6.3 rules without changing any height's
    /// context, and without being admitted by the production registry.
    #[test]
    fn fixture_registry_adds_a_second_domain_only() {
        let _init_guard = zebra_test::init();

        assert!(!DomainRegistry::UPSTREAM.admits(FIXTURE_NU6_3_DOMAIN));
        assert!(DomainRegistry::FIXTURE.admits(FIXTURE_NU6_3_DOMAIN));

        let fixture = DomainRegistry::FIXTURE
            .context_for_branch(FIXTURE_NU6_3_DOMAIN)
            .expect("the fixture domain is admitted by the fixture registry");
        assert_eq!(fixture.rules(), NetworkUpgrade::Nu6_3);
        assert_eq!(fixture.branch(), FIXTURE_NU6_3_DOMAIN);

        for network in [Network::Mainnet, Network::new_default_testnet()] {
            for (height, _) in network.full_activation_list() {
                assert_eq!(
                    DomainRegistry::FIXTURE.context_at(&network, height),
                    DomainRegistry::UPSTREAM.context_at(&network, height),
                    "the fixture registry must not change any height's context"
                );
            }
        }
    }
}
