//! Internal mining in Zebra.
//!
//! # TODO
//! - pause mining if we have no peers, like `zcashd` does,
//!   and add a developer config that mines regardless of how many peers we have.
//!   <https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/miner.cpp#L865-L880>
//! - move common code into zebra-chain or zebra-node-services and remove the RPC dependency.

use std::{
    cmp::min,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::available_parallelism,
    time::{Duration, Instant},
};

use color_eyre::Report;
use futures::{stream::FuturesUnordered, StreamExt};
use thread_priority::{ThreadBuilder, ThreadPriority};
use tokio::{select, sync::watch, task::JoinHandle, time::sleep};
use tower::Service;
use tracing::{Instrument, Span};

use zebra_chain::{
    block::{self, Block},
    chain_sync_status::ChainSyncStatus,
    chain_tip::ChainTip,
    diagnostic::task::WaitForPanics,
    serialization::{AtLeastOne, ZcashSerialize},
    shutdown::is_shutting_down,
    work::equihash::{Solution, SolverCancelled},
};
use zebra_network::AddressBookPeers;
use zebra_node_services::mempool;
use zebra_rpc::{
    client::{
        BlockTemplateTimeSource,
        GetBlockTemplateCapability::{CoinbaseTxn, LongPoll},
        GetBlockTemplateParameters,
        GetBlockTemplateRequestMode::Template,
        HexData,
    },
    config::mining::Config,
    methods::{RpcImpl, RpcServer},
    proposal_block_from_template,
};
use zebra_state::WatchReceiver;

/// The amount of time we wait between block template retries.
pub const BLOCK_TEMPLATE_WAIT_TIME: Duration = Duration::from_secs(20);

/// A rate-limit for block template refreshes.
pub const BLOCK_TEMPLATE_REFRESH_LIMIT: Duration = Duration::from_secs(2);

/// How long we wait after mining a block, before expecting a new template.
///
/// This should be slightly longer than `BLOCK_TEMPLATE_REFRESH_LIMIT` to allow for template
/// generation.
pub const BLOCK_MINING_WAIT_TIME: Duration = Duration::from_secs(3);

/// How often the internal miner reports the solver rate it measured.
///
/// The count is taken where the solver asks for its next nonce, so one unit is
/// one real Equihash attempt and the difference over time is this process's own
/// solution rate. It is logged in the same `N sol/s` shape the standalone
/// miner uses, so an operator's tooling can read either miner with one parser.
pub const SOLVER_RATE_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Keeps several solvers racing on one block template down to one submitted block.
///
/// Every solver searches the same template over its own nonce range, so more than
/// one of them can find a valid solution before the node notices the tip has moved.
/// Those blocks are all valid, but only the first is wanted: the rest are the same
/// height on the same parent, and submitting them would be the node racing itself.
///
/// The claim is keyed on the parent block, which is what "the work we are doing
/// now" actually means. A new parent — the tip moved, whoever mined it — is new
/// work and can be claimed again.
#[derive(Clone, Debug, Default)]
pub struct SubmissionGuard {
    claimed_parent: Arc<Mutex<Option<block::Hash>>>,
}

impl SubmissionGuard {
    /// Creates a guard that has not claimed any work yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks for the right to submit a block that builds on `parent`.
    ///
    /// Returns `true` for the first caller for that parent, and `false` for every
    /// caller after it, until the parent changes.
    pub fn claim(&self, parent: block::Hash) -> bool {
        let mut claimed = self
            .claimed_parent
            .lock()
            .expect("submission guard mutex is never held across a panic");

        if *claimed == Some(parent) {
            return false;
        }

        *claimed = Some(parent);
        true
    }
}

/// Reports the rate the internal miner's solvers are actually achieving, as one
/// number for the whole node.
///
/// `attempts` is incremented where a solver asks for its next nonce, so one unit is
/// one real Equihash attempt and the difference over time is this process's own
/// solution rate, across every solver thread. Nothing here estimates a rate from
/// blocks found or from the difficulty: an unmeasured rate is reported as nothing
/// at all.
async fn report_solver_rate(attempts: Arc<AtomicU64>, solver_count: usize) {
    let mut last_total = attempts.load(Ordering::Relaxed);
    let mut last_at = Instant::now();

    while !is_shutting_down() {
        sleep(SOLVER_RATE_REPORT_INTERVAL).await;

        let now = Instant::now();
        let total = attempts.load(Ordering::Relaxed);
        let elapsed = now.duration_since(last_at).as_secs_f64();
        let attempts_this_window = total.saturating_sub(last_total);

        // A window with no attempts is a miner that is not solving (a new template,
        // a shutdown, a pause). Reporting zero would look like a measurement, so it
        // is skipped.
        if elapsed > 0.0 && attempts_this_window > 0 {
            let solps = attempts_this_window as f64 / elapsed;
            info!(
                solps,
                attempts = total,
                solver_count,
                "internal miner rate: {solps:.0} sol/s (attempts {attempts_this_window} in {elapsed:.1}s across {solver_count} threads)"
            );
        }

        last_total = total;
        last_at = now;
    }
}

/// Initialize the miner based on its config, and spawn a task for it.
///
/// This method is CPU and memory-intensive. It uses 144 MB of RAM and one CPU core per configured
/// mining thread.
///
/// See [`run_mining_solver()`] for more details.
pub fn spawn_init<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>(
    config: &Config,
    rpc: RpcImpl<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>,
) -> JoinHandle<Result<(), Report>>
// TODO: simplify or avoid repeating these generics (how?)
where
    Mempool: Service<
            mempool::Request,
            Response = mempool::Response,
            Error = zebra_node_services::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    Mempool::Future: Send,
    State: Service<
            zebra_state::Request,
            Response = zebra_state::Response,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <State as Service<zebra_state::Request>>::Future: Send,
    ReadState: Service<
            zebra_state::ReadRequest,
            Response = zebra_state::ReadResponse,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <ReadState as Service<zebra_state::ReadRequest>>::Future: Send,
    Tip: ChainTip + Clone + Send + Sync + 'static,
    BlockVerifierRouter: Service<zebra_consensus::Request, Response = block::Hash, Error = zebra_consensus::BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    <BlockVerifierRouter as Service<zebra_consensus::Request>>::Future: Send,
    SyncStatus: ChainSyncStatus + Clone + Send + Sync + 'static,
    AddressBook: AddressBookPeers + Clone + Send + Sync + 'static,
{
    // TODO: spawn an entirely new executor here, so mining is isolated from higher priority tasks.
    tokio::spawn(init(config.clone(), rpc).in_current_span())
}

/// Initialize the miner based on its config.
///
/// This method is CPU and memory-intensive. It uses 144 MB of RAM and one CPU core per configured
/// mining thread.
///
/// See [`run_mining_solver()`] for more details.
pub async fn init<Mempool, State, ReadState, Tip, BlockVerifierRouter, SyncStatus, AddressBook>(
    config: Config,
    rpc: RpcImpl<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>,
) -> Result<(), Report>
where
    Mempool: Service<
            mempool::Request,
            Response = mempool::Response,
            Error = zebra_node_services::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    Mempool::Future: Send,
    State: Service<
            zebra_state::Request,
            Response = zebra_state::Response,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <State as Service<zebra_state::Request>>::Future: Send,
    ReadState: Service<
            zebra_state::ReadRequest,
            Response = zebra_state::ReadResponse,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <ReadState as Service<zebra_state::ReadRequest>>::Future: Send,
    Tip: ChainTip + Clone + Send + Sync + 'static,
    BlockVerifierRouter: Service<zebra_consensus::Request, Response = block::Hash, Error = zebra_consensus::BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    <BlockVerifierRouter as Service<zebra_consensus::Request>>::Future: Send,
    SyncStatus: ChainSyncStatus + Clone + Send + Sync + 'static,
    AddressBook: AddressBookPeers + Clone + Send + Sync + 'static,
{
    // Every solver searches the same template over its own nonce range, so this is
    // how much of this machine the node spends on solving. Unset means one thread,
    // which is what Zebra has always done.
    //
    // Upstream held this at one thread (#8797) because solvers were not cancelled
    // when the best tip changed. They are here: `generate_block_templates` long-polls
    // the tip and publishes a new template, `cancel_fn` drops the solver as soon as
    // the header it is working on is no longer current, and `SubmissionGuard` keeps
    // a race between two finished solvers down to one submitted block.
    let configured_threads = config.internal_miner_threads.unwrap_or(1).max(1);
    // If we can't detect the number of cores, use the configured number.
    let available_threads = available_parallelism()
        .map(usize::from)
        .unwrap_or(configured_threads);

    // Use the minimum of the configured and available threads.
    let solver_count = min(configured_threads, available_threads);

    info!(
        ?solver_count,
        ?configured_threads,
        ?available_threads,
        "launching mining tasks with parallel solvers"
    );

    let (template_sender, template_receiver) = watch::channel(None);
    let template_receiver = WatchReceiver::new(template_receiver);

    // Spawn these tasks, to avoid blocked cooperative futures, and improve shutdown responsiveness.
    // This is particularly important when there are a large number of solver threads.
    let mut abort_handles = Vec::new();

    let template_generator = tokio::task::spawn(
        generate_block_templates(rpc.clone(), template_sender).in_current_span(),
    );
    abort_handles.push(template_generator.abort_handle());
    let template_generator = template_generator.wait_for_panics();

    // One counter and one reporter for the whole node: an operator wants the rate
    // this machine is achieving, not one line per thread that they have to add up.
    let attempts = Arc::new(AtomicU64::new(0));
    let rate_reporter = tokio::task::spawn(
        report_solver_rate(attempts.clone(), solver_count).in_current_span(),
    );
    abort_handles.push(rate_reporter.abort_handle());

    // Shared by every solver, so the first one to solve the current parent is the
    // only one that submits.
    let submission_guard = SubmissionGuard::new();

    let mut mining_solvers = FuturesUnordered::new();
    for solver_id in 0..solver_count {
        // Assume there are less than 256 cores. If there are more, only run 256 tasks.
        let solver_id = min(solver_id, usize::from(u8::MAX))
            .try_into()
            .expect("just limited to u8::MAX");

        let solver = tokio::task::spawn(
            run_mining_solver(
                solver_id,
                template_receiver.clone(),
                rpc.clone(),
                attempts.clone(),
                submission_guard.clone(),
            )
            .in_current_span(),
        );
        abort_handles.push(solver.abort_handle());

        mining_solvers.push(solver.wait_for_panics());
    }

    // These tasks run forever unless there is a fatal error or shutdown.
    // When that happens, the first task to error returns, and the other JoinHandle futures are
    // cancelled.
    let first_result;
    select! {
        result = template_generator => { first_result = result; }
        result = mining_solvers.next() => {
            first_result = result
                .expect("stream never terminates because there is at least one solver task");
        }
    }

    // But the spawned async tasks keep running, so we need to abort them here.
    for abort_handle in abort_handles {
        abort_handle.abort();
    }

    // Any spawned blocking threads will keep running. When this task returns and drops the
    // `template_sender`, it cancels all the spawned miner threads. This works because we've
    // aborted the `template_generator` task, which owns the `template_sender`. (And it doesn't
    // spawn any blocking threads.)
    first_result
}

/// Generates block templates using `rpc`, and sends them to mining threads using `template_sender`.
#[instrument(skip(rpc, template_sender))]
pub async fn generate_block_templates<
    Mempool,
    State,
    ReadState,
    Tip,
    BlockVerifierRouter,
    SyncStatus,
    AddressBook,
>(
    rpc: RpcImpl<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>,
    template_sender: watch::Sender<Option<Arc<Block>>>,
) -> Result<(), Report>
where
    Mempool: Service<
            mempool::Request,
            Response = mempool::Response,
            Error = zebra_node_services::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    Mempool::Future: Send,
    State: Service<
            zebra_state::Request,
            Response = zebra_state::Response,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <State as Service<zebra_state::Request>>::Future: Send,
    ReadState: Service<
            zebra_state::ReadRequest,
            Response = zebra_state::ReadResponse,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <ReadState as Service<zebra_state::ReadRequest>>::Future: Send,
    Tip: ChainTip + Clone + Send + Sync + 'static,
    BlockVerifierRouter: Service<zebra_consensus::Request, Response = block::Hash, Error = zebra_consensus::BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    <BlockVerifierRouter as Service<zebra_consensus::Request>>::Future: Send,
    SyncStatus: ChainSyncStatus + Clone + Send + Sync + 'static,
    AddressBook: AddressBookPeers + Clone + Send + Sync + 'static,
{
    // Pass the correct arguments, even if Zebra currently ignores them.
    let mut parameters =
        GetBlockTemplateParameters::new(Template, None, vec![LongPoll, CoinbaseTxn], None, None);

    // Shut down the task when all the template receivers are dropped, or Zebra shuts down.
    while !template_sender.is_closed() && !is_shutting_down() {
        let template: Result<_, _> = rpc.get_block_template(Some(parameters.clone())).await;

        // Wait for the chain to sync so we get a valid template.
        let Ok(template) = template else {
            warn!(
                ?BLOCK_TEMPLATE_WAIT_TIME,
                ?template,
                "waiting for a valid block template",
            );

            // Skip the wait if we got an error because we are shutting down.
            if !is_shutting_down() {
                sleep(BLOCK_TEMPLATE_WAIT_TIME).await;
            }

            continue;
        };

        // Convert from RPC GetBlockTemplate to Block
        let template = template
            .try_into_template()
            .expect("invalid RPC response: proposal in response to a template request");

        info!(
            height = ?template.height(),
            transactions = ?template.transactions().len(),
            "mining with an updated block template",
        );

        // Tell the next get_block_template() call to wait until the template has changed.
        parameters = GetBlockTemplateParameters::new(
            Template,
            None,
            vec![LongPoll, CoinbaseTxn],
            Some(template.long_poll_id()),
            None,
        );

        let block = proposal_block_from_template(
            &template,
            BlockTemplateTimeSource::CurTime,
            rpc.network(),
        )?;

        // If the template has actually changed, send an updated template.
        template_sender.send_if_modified(|old_block| {
            if old_block.as_ref().map(|b| *b.header) == Some(*block.header) {
                return false;
            }
            *old_block = Some(Arc::new(block));
            true
        });

        // If the blockchain is changing rapidly, limit how often we'll update the template.
        // But if we're shutting down, do that immediately.
        if !template_sender.is_closed() && !is_shutting_down() {
            sleep(BLOCK_TEMPLATE_REFRESH_LIMIT).await;
        }
    }

    Ok(())
}

/// Runs a single mining thread that gets blocks from the `template_receiver`, calculates equihash
/// solutions with nonces based on `solver_id`, and submits valid blocks to Zebra's block validator.
///
/// This method is CPU and memory-intensive. It uses 144 MB of RAM and one CPU core while running.
/// It can run for minutes or hours if the network difficulty is high. Mining uses a thread with
/// low CPU priority.
#[instrument(skip(template_receiver, rpc))]
pub async fn run_mining_solver<
    Mempool,
    State,
    ReadState,
    Tip,
    BlockVerifierRouter,
    SyncStatus,
    AddressBook,
>(
    solver_id: u8,
    mut template_receiver: WatchReceiver<Option<Arc<Block>>>,
    rpc: RpcImpl<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>,
    attempts: Arc<AtomicU64>,
    submission_guard: SubmissionGuard,
) -> Result<(), Report>
where
    Mempool: Service<
            mempool::Request,
            Response = mempool::Response,
            Error = zebra_node_services::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    Mempool::Future: Send,
    State: Service<
            zebra_state::Request,
            Response = zebra_state::Response,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <State as Service<zebra_state::Request>>::Future: Send,
    ReadState: Service<
            zebra_state::ReadRequest,
            Response = zebra_state::ReadResponse,
            Error = zebra_state::BoxError,
        > + Clone
        + Send
        + Sync
        + 'static,
    <ReadState as Service<zebra_state::ReadRequest>>::Future: Send,
    Tip: ChainTip + Clone + Send + Sync + 'static,
    BlockVerifierRouter: Service<zebra_consensus::Request, Response = block::Hash, Error = zebra_consensus::BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    <BlockVerifierRouter as Service<zebra_consensus::Request>>::Future: Send,
    SyncStatus: ChainSyncStatus + Clone + Send + Sync + 'static,
    AddressBook: AddressBookPeers + Clone + Send + Sync + 'static,
{
    // Shut down the task when the template sender is dropped, or Zebra shuts down.
    while template_receiver.has_changed().is_ok() && !is_shutting_down() {
        // Get the latest block template, and mark the current value as seen.
        // We mark the value first to avoid missed updates.
        template_receiver.mark_as_seen();
        let template = template_receiver.cloned_watch_data();

        let Some(template) = template else {
            if solver_id == 0 {
                info!(
                    ?solver_id,
                    ?BLOCK_TEMPLATE_WAIT_TIME,
                    "solver waiting for initial block template"
                );
            } else {
                debug!(
                    ?solver_id,
                    ?BLOCK_TEMPLATE_WAIT_TIME,
                    "solver waiting for initial block template"
                );
            }

            // Skip the wait if we didn't get a template because we are shutting down.
            if !is_shutting_down() {
                sleep(BLOCK_TEMPLATE_WAIT_TIME).await;
            }

            continue;
        };

        let height = template.coinbase_height().expect("template is valid");
        // The work this solver is doing is "a block on top of this parent". It is
        // what the solvers share, and what the submission guard claims.
        let parent_hash = template.header.previous_block_hash;

        // Set up the cancellation conditions for the miner.
        let mut cancel_receiver = template_receiver.clone();
        let old_header = *template.header;
        // The solver asks for its next nonce through this closure, so one call
        // here is one Equihash attempt by this solver. Every solver adds to the
        // same counter, because what an operator wants is this machine's rate, and
        // counting the attempts is the only honest way to know it: nothing else in
        // the node observes the solvers.
        let attempts_for_solver = attempts.clone();
        let cancel_fn = move || {
            attempts_for_solver.fetch_add(1, Ordering::Relaxed);

            match cancel_receiver.has_changed() {
                // Guard against get_block_template() providing an identical header. This could happen
                // if something irrelevant to the block data changes, the time was within 1 second, or
                // there is a spurious channel change.
                Ok(has_changed) => {
                    cancel_receiver.mark_as_seen();

                    // We only need to check header equality, because the block data is bound to the
                    // header.
                    if has_changed
                        && Some(old_header)
                            != cancel_receiver.cloned_watch_data().map(|b| *b.header)
                    {
                        Err(SolverCancelled)
                    } else {
                        Ok(())
                    }
                }
                // If the sender was dropped, we're likely shutting down, so cancel the solver.
                Err(_sender_dropped) => Err(SolverCancelled),
            }
        };

        // Mine at least one block using the equihash solver.
        let Ok(blocks) = mine_a_block(solver_id, template, cancel_fn).await else {
            // If the solver was cancelled, we're either shutting down, or we have a new template.
            if solver_id == 0 {
                info!(
                    ?height,
                    ?solver_id,
                    new_template = ?template_receiver.has_changed(),
                    shutting_down = ?is_shutting_down(),
                    "solver cancelled: getting a new block template or shutting down"
                );
            } else {
                debug!(
                    ?height,
                    ?solver_id,
                    new_template = ?template_receiver.has_changed(),
                    shutting_down = ?is_shutting_down(),
                    "solver cancelled: getting a new block template or shutting down"
                );
            }

            // If the blockchain is changing rapidly, limit how often we'll update the template.
            // But if we're shutting down, do that immediately.
            if template_receiver.has_changed().is_ok() && !is_shutting_down() {
                sleep(BLOCK_TEMPLATE_REFRESH_LIMIT).await;
            }

            continue;
        };

        // Submit the newly mined blocks to the verifiers.
        //
        // With several solvers on one template, more than one of them can finish
        // before the tip moves. Those blocks are all valid and all build on the same
        // parent, so only the first is submitted; the rest of the solvers go back for
        // a new template instead of racing the node against itself.
        //
        // TODO: if there is a new template (`cancel_fn().is_err()`), and
        //       GetBlockTemplate.submit_old is false, return immediately, and skip submitting the
        //       blocks.
        if !submission_guard.claim(parent_hash) {
            debug!(
                ?height,
                ?solver_id,
                ?parent_hash,
                "another solver already submitted a block for this parent: getting new work",
            );

            if template_receiver.has_changed().is_ok() && !is_shutting_down() {
                sleep(BLOCK_TEMPLATE_REFRESH_LIMIT).await;
            }

            continue;
        }

        let mut any_success = false;
        for block in blocks {
            let data = block
                .zcash_serialize_to_vec()
                .expect("serializing to Vec never fails");

            match rpc.submit_block(HexData(data), None).await {
                Ok(success) => {
                    info!(
                        ?height,
                        hash = ?block.hash(),
                        ?solver_id,
                        ?success,
                        "successfully mined a new block",
                    );
                    any_success = true;
                }
                Err(error) => info!(
                    ?height,
                    hash = ?block.hash(),
                    ?solver_id,
                    ?error,
                    "validating a newly mined block failed, trying again",
                ),
            }
        }

        // Start re-mining quickly after a failed solution.
        // If there's a new template, we'll use it, otherwise the existing one is ok.
        if !any_success {
            // If the blockchain is changing rapidly, limit how often we'll update the template.
            // But if we're shutting down, do that immediately.
            if template_receiver.has_changed().is_ok() && !is_shutting_down() {
                sleep(BLOCK_TEMPLATE_REFRESH_LIMIT).await;
            }
            continue;
        }

        // Wait for the new block to verify, and the RPC task to pick up a new template.
        // But don't wait too long, we could have mined on a fork.
        tokio::select! {
            shutdown_result = template_receiver.changed() => shutdown_result?,
            _ = sleep(BLOCK_MINING_WAIT_TIME) => {}

        }
    }

    Ok(())
}

/// Mines one or more blocks based on `template`. Calculates equihash solutions, checks difficulty,
/// and returns as soon as it has at least one block. Uses a different nonce range for each
/// `solver_id`.
///
/// If `cancel_fn()` returns an error, returns early with `Err(SolverCancelled)`.
///
/// See [`run_mining_solver()`] for more details.
pub async fn mine_a_block<F>(
    solver_id: u8,
    template: Arc<Block>,
    cancel_fn: F,
) -> Result<AtLeastOne<Block>, SolverCancelled>
where
    F: FnMut() -> Result<(), SolverCancelled> + Send + Sync + 'static,
{
    // TODO: Replace with Arc::unwrap_or_clone() when it stabilises:
    // https://github.com/rust-lang/rust/issues/93610
    let mut header = *template.header;

    // Use a different nonce for each solver thread.
    // Change both the first and last bytes, so we don't have to care if the nonces are incremented in
    // big-endian or little-endian order. And we can see the thread that mined a block from the nonce.
    *header.nonce.first_mut().unwrap() = solver_id;
    *header.nonce.last_mut().unwrap() = solver_id;

    // Mine one or more blocks using the solver, in a low-priority blocking thread.
    let span = Span::current();
    let solved_headers =
        tokio::task::spawn_blocking(move || span.in_scope(move || {
            let miner_thread_handle = ThreadBuilder::default().name("zebra-miner").priority(ThreadPriority::Min).spawn(move |priority_result| {
                if let Err(error) = priority_result {
                    info!(?error, "could not set miner to run at a low priority: running at default priority");
                }

                Solution::solve(header, cancel_fn)
            }).expect("unable to spawn miner thread");

            miner_thread_handle.wait_for_panics()
        }))
        .wait_for_panics()
        .await?;

    // Modify the template into solved blocks.

    // TODO: Replace with Arc::unwrap_or_clone() when it stabilises
    let block = (*template).clone();

    let solved_blocks: Vec<Block> = solved_headers
        .into_iter()
        .map(|header| {
            let mut block = block.clone();
            block.header = Arc::new(header);
            block
        })
        .collect();

    Ok(solved_blocks
        .try_into()
        .expect("a 1:1 mapping of AtLeastOne produces at least one block"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    use zebra_chain::block::Hash;

    /// A parent block hash that is distinct from the others in these tests.
    fn parent(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    #[test]
    fn config_without_threads_keeps_one_solver() {
        let config = Config::default();

        assert_eq!(config.internal_miner_solver_count(16), 1);
    }

    #[test]
    fn configured_threads_are_capped_by_the_machine() {
        let config = Config {
            internal_miner_threads: Some(15),
            ..Config::default()
        };

        assert_eq!(config.internal_miner_solver_count(15), 15);
        assert_eq!(config.internal_miner_solver_count(4), 4);
    }

    #[test]
    fn zero_threads_still_runs_one_solver() {
        let config = Config {
            internal_miner_threads: Some(0),
            ..Config::default()
        };

        assert_eq!(config.internal_miner_solver_count(8), 1);
        assert_eq!(config.internal_miner_solver_count(0), 1);
    }

    /// A `[mining] internal_miner_threads` in a config file reaches the miner, and a
    /// config file without it still parses and still means one thread.
    #[test]
    fn threads_round_trip_through_the_config_file() {
        let configured: Config =
            toml::from_str("internal_miner = true\ninternal_miner_threads = 6\n")
                .expect("a config with a thread count parses");
        assert_eq!(configured.internal_miner_threads, Some(6));
        assert_eq!(configured.internal_miner_solver_count(32), 6);

        let older: Config =
            toml::from_str("internal_miner = true\n").expect("a config without the field parses");
        assert_eq!(older.internal_miner_threads, None);
        assert_eq!(older.internal_miner_solver_count(32), 1);

        // A node that does not set it writes a config that does not mention it, so
        // the seed server's stored config is unchanged by this feature existing.
        let written = toml::to_string(&older).expect("the config serializes");
        assert!(
            !written.contains("internal_miner_threads"),
            "an unset thread count must not appear in a written config, got: {written}",
        );
    }

    /// Every solver races on the same template; the node submits one block.
    #[tokio::test]
    async fn only_one_of_many_solvers_submits_a_block_for_one_parent() {
        const SOLVERS: usize = 15;

        let config = Config {
            internal_miner_threads: Some(SOLVERS),
            ..Config::default()
        };
        let solver_count = config.internal_miner_solver_count(SOLVERS);
        assert_eq!(solver_count, SOLVERS, "every configured solver runs");

        let guard = SubmissionGuard::new();
        let submissions = Arc::new(AtomicUsize::new(0));
        let solved = parent(1);

        // Each task stands for one solver that finished its nonce range on the same
        // template at the same moment.
        let mut solvers = Vec::with_capacity(solver_count);
        for _ in 0..solver_count {
            let guard = guard.clone();
            let submissions = submissions.clone();
            solvers.push(tokio::spawn(async move {
                if guard.claim(solved) {
                    submissions.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for solver in solvers {
            solver.await.expect("solver task does not panic");
        }

        assert_eq!(
            submissions.load(Ordering::SeqCst),
            1,
            "{solver_count} solvers on one template must submit exactly one block",
        );
    }

    /// A new tip is new work, whoever mined it.
    #[test]
    fn a_new_parent_can_be_claimed_again() {
        let guard = SubmissionGuard::new();

        assert!(guard.claim(parent(1)), "the first claim wins");
        assert!(!guard.claim(parent(1)), "the same parent is already claimed");
        assert!(guard.claim(parent(2)), "a new parent is new work");
        assert!(!guard.claim(parent(2)));
        assert!(
            guard.claim(parent(1)),
            "a reorg back to an earlier parent is new work too"
        );
    }
}
