//! Funding Streams calculations [§7.10]
//!
//! [§7.10]: https://zips.z.cash/protocol/protocol.pdf#fundingstreams

use zebra_chain::{
    block::Height,
    parameters::{subsidy::*, Network},
    transparent::{self},
};

#[cfg(test)]
mod tests;

/// Returns the position in the address slice for each funding stream
/// as described in [protocol specification §7.10][7.10]
///
/// [7.10]: https://zips.z.cash/protocol/protocol.pdf#fundingstreams
fn funding_stream_address_index(
    height: Height,
    network: &Network,
    receiver: FundingStreamReceiver,
) -> Option<usize> {
    if receiver == FundingStreamReceiver::Deferred {
        return None;
    }

    let funding_streams = network.funding_streams(height)?;
    let num_addresses = funding_streams.recipient(receiver)?.addresses().len();

    // # Correctness
    //
    // SWARM production configures exactly one destination per recipient, fixed for the whole
    // funding stream range (`SwarmMainParametersBuilder::finish` rejects anything else), so there
    // is no address rotation to compute. The upstream formula below assumes the 48 rotating
    // addresses ZIP-214 gives each Zcash recipient, and its `assert!` would abort the node at the
    // first SWARM address period boundary — `post_blossom_halving_interval / 48` = height 35_001 —
    // where it would compute index 1 into a one-element slice. Upstream networks are unaffected.
    if network.is_swarm_main() {
        return Some(0);
    }

    let index = 1u32
        .checked_add(funding_stream_address_period(height, network))?
        .checked_sub(funding_stream_address_period(
            funding_streams.height_range().start,
            network,
        ))? as usize;

    assert!(index > 0 && index <= num_addresses);
    // spec formula will output an index starting at 1 but
    // Zebra indices for addresses start at zero, return converted.
    Some(index - 1)
}

/// Return the address corresponding to given height, network and funding stream receiver.
///
/// This function only returns transparent addresses, because the current Zcash funding streams
/// only use transparent addresses,
pub fn funding_stream_address(
    height: Height,
    network: &Network,
    receiver: FundingStreamReceiver,
) -> Option<&transparent::Address> {
    let index = funding_stream_address_index(height, network, receiver)?;
    let funding_streams = network.funding_streams(height)?;
    funding_streams.recipient(receiver)?.addresses().get(index)
}
