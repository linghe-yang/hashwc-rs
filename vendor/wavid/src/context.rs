use crate::{Event, ProtMsg, Request, State};
use anyhow::Result;
use config::Node;
use std::collections::HashMap;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use types::{InstanceId, WeightedMembership};
use util::weighted::Endpoint;

pub struct Context {
    pub(crate) network: Endpoint<ProtMsg>,
    pub(crate) membership: WeightedMembership,
    pub(crate) id: usize,
    pub(crate) states: HashMap<InstanceId, State>,
    input: Receiver<Request>,
    pub(crate) output: Sender<Event>,
    exit_rx: oneshot::Receiver<()>,
    startup: Vec<InstanceId>,
}
impl Context {
    /// Start this physical node's protocol service inside a Tokio runtime.
    ///
    /// # Parameter selection
    /// * `config`: set `id` to the local node ID and populate `net_map` and
    ///   `sk_map` with every participant's address and authentication key.
    ///   Use positive integer `weights`; actual corrupt weight must be strictly
    ///   below `weight_threshold = T`, with `3T <= W`. T bounds weight, not the
    ///   number of corrupt nodes. Participants share a fresh `session_id`,
    ///   membership, and threshold for each invocation. Concurrent services need
    ///   distinct listening addresses. One service multiplexes `InstanceId` values
    ///   on its listener; it does not allocate ports or apply offsets per instance.
    /// * `input`: a bounded request channel. Register before submitting input.
    ///   Prefer `spawn_with_manifest` across processes so peer messages cannot
    ///   arrive before local registration.
    /// * `output`: a bounded event channel that the caller must continuously drain.
    ///   A full channel pauses this service. Size it for event bursts across
    ///   concurrent instances; 64 is sufficient for a single-instance test.
    ///
    /// Sending () on the returned handle, or dropping it, stops the service.
    /// Retain it until the application confirms that no peer-service obligations
    /// remain; local output does not imply that other participants have finished.
    /// Configure each instance through `Request::Register.descriptor`:
    /// * `file_bytes`: the exact canonical bulk length, including application
    ///   encoding but excluding WAVID stripe padding. Use 0..=MAX_FILE_BYTES,
    ///   identically at every node.
    /// * `coding.block_bytes`: bytes per source block / coding coordinate; an
    ///   even value in 32..=4096, default 32. Common alternatives are 64/128/256.
    ///   Choose it for the application's short fields and proof sizes: larger
    ///   blocks reduce stripes and directory overhead, but coding-fault evidence
    ///   contains n blocks. When relying on the paper's bounds, keep
    ///   b=Theta(lambda+log n) rather than scaling it with the entire bulk.
    ///   The root binds this immutable instance parameter. It is independent of
    ///   the fixed 32 KiB network chunk size.
    /// * `root`: the application-authenticated directory root. It may initially
    ///   be None; External mode later binds it with Pin. Roots depend on this
    ///   service's public_id and cannot be reused from WRBC.
    /// * `retrievers`: physical IDs authorized to recover the file. An empty list
    ///   grants no initial authorization; Authorize only adds IDs. The application
    ///   must verify each node's eligibility before authorizing it.
    /// * `completion`: use Storage for standalone storage tests, or External when
    ///   the coin combines storage with private-input receipts. Submit Complete
    ///   only after authenticating the joint completion predicate. Stored confirms
    ///   verification of the local storage packet, not private inputs or circuit
    ///   semantics in the application.
    /// * `instance`: set dealer to the actual sender's ID. Use epoch/slot to
    ///   distinguish application calls; never reuse an InstanceId for a different
    ///   bulk within the same session.
    /// Recovery returns a ValidatedFile supporting open_source/open_range. Retain
    /// this shared handle to produce application evidence without further network
    /// responses; use as_ref() to read bytes without copying. Retrieve recovers
    /// stripes incrementally but emits File only after every stripe and padding
    /// check succeeds. A stripe containing public fault evidence can produce
    /// Invalid earlier; Stored still requires complete packet verification.
    pub fn spawn(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
    ) -> Result<oneshot::Sender<()>> {
        Self::spawn_with_manifest(config, input, output, Vec::new())
    }
    /// Install the instance manifest before listening, preventing early peer
    /// messages from being discarded during cross-process startup.
    ///
    /// See [Self::spawn] for `config`, `input`, `output`, and shutdown semantics.
    /// `registrations` may contain at most MAX_INSTANCES entries, with no duplicate
    /// InstanceId values. Only Register is accepted; submit other requests
    /// through input. Each instance's public parameters must agree across its
    /// participants; see [Self::spawn] for selection guidance.
    pub fn spawn_with_manifest(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
        registrations: Vec<Request>,
    ) -> Result<oneshot::Sender<()>> {
        config.validate_weighted()?;
        anyhow::ensure!(
            registrations.len() <= util::weighted::MAX_INSTANCES,
            "instance limit"
        );
        let membership = config.weighted_membership()?;
        let public_id = config.weighted_public_id("wavid");
        let mut states = HashMap::new();
        let mut startup = vec![];
        for request in registrations {
            let instance = request.instance();
            anyhow::ensure!(
                !states.contains_key(&instance),
                "duplicate manifest instance"
            );
            let state = match request {
                Request::Register {
                    instance,
                    descriptor,
                } => State::new(
                    membership.clone(),
                    config.id,
                    instance,
                    public_id,
                    descriptor,
                )?,
                _ => {
                    return Err(anyhow::anyhow!(
                        "manifest must contain Register requests only"
                    ))
                }
            };
            states.insert(instance, state);
            startup.push(instance);
        }
        let network = Endpoint::bind(&config, "wavid")?;
        let (exit_tx, exit_rx) = oneshot::channel();
        let mut context = Self {
            network,
            membership,
            id: config.id,
            states,
            input,
            output,
            exit_rx,
            startup,
        };
        tokio::spawn(async move {
            if let Err(e) = context.run().await {
                log::error!("wavid service: {}", e);
            }
        });
        Ok(exit_tx)
    }
    pub async fn run(&mut self) -> Result<()> {
        for instance in std::mem::take(&mut self.startup) {
            let _ = self.output.send(Event::Registered { instance }).await;
        }
        let mut input_open = true;
        loop {
            tokio::select! {
                _=&mut self.exit_rx=>break,
                msg=self.network.recv.recv()=>match msg{Some((sender,msg))=>self.process_msg(sender,msg).await?,None=>break},
                request=self.input.recv(), if input_open=>match request{Some(request)=>self.process_request(request).await?,None=>input_open=false},
            }
        }
        Ok(())
    }
    pub(crate) async fn flush(&mut self, instance: InstanceId) -> Result<()> {
        if let Some(state) = self.states.get_mut(&instance) {
            let actions = std::mem::take(&mut state.outgoing);
            if !actions.is_empty() {
                let sender = self.network.sender();
                util::weighted_compute::run(move || sender.send_batch(actions)).await??;
            }
            for event in std::mem::take(&mut state.events) {
                if self.output.send(event).await.is_err() {
                    log::debug!("wavid output receiver closed; retaining peer service");
                }
            }
        }
        Ok(())
    }
}
