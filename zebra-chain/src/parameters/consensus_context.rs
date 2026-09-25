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
//! module deliberately provides no way to add one at runtime. A production domain requires a
//! reviewed numeric value, a reviewed rule revision to bind it to, and a network variant to carry
//! it; none of those exist yet. The only non-upstream domain defined here is
//! [`FIXTURE_NU6_3_DOMAIN`], which is `#[cfg(test)]` test data.

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
    /// The closed upstream `(rules, domain)` table.
    base: &'static [(NetworkUpgrade, ConsensusBranchId)],
    /// Extra admitted domains. Empty outside tests.
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
