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
    pub(crate) reuse_local_dealer: bool,
}
impl Context {
    /// Start this physical node's protocol service inside a Tokio runtime.
    ///
    /// # Parameter selection
    /// * `config`: set `id` to the local node ID and populate `net_map` and
    ///   `sk_map` with every participant's address and authentication key.
    ///   Use positive integer `weights`; actual corrupt weight must be strictly
    ///   below `weight_threshold = T`, with `3(T-1) < W`. T bounds weight, not the
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
    /// Register's `instance` must identify the dealer; Broadcast once per instance.
    /// `file_bytes` is the exact file length, allowing zero up to MAX_FILE_BYTES.
    /// `coding` follows WAVID: an even block size in 32..=4096 bytes, default 32,
    /// identical at all nodes. Larger blocks reduce stripe counts but enlarge
    /// evidence; see wavid::CodingParams. WRBC automatically enables retrieval for
    /// all participants and requires no separate WAVID network service. Deliver
    /// returns a shared ValidatedFile supporting on-demand source proofs; as_ref()
    /// reads its bytes without copying.
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
        Self::spawn_with_manifest_and_local_reuse(config, input, output, registrations, false)
    }
    /// Same manifest and asynchronous completion rule, with optional reuse of
    /// the local dealer's canonical encoding. Existing constructors keep the
    /// original all-party retrieval behavior. No wire message changes.
    pub fn spawn_with_manifest_and_local_reuse(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
        registrations: Vec<Request>,
        reuse_local_dealer: bool,
    ) -> Result<oneshot::Sender<()>> {
        config.validate_weighted()?;
        anyhow::ensure!(
            registrations.len() <= util::weighted::MAX_INSTANCES,
            "instance limit"
        );
        let membership = config.weighted_membership()?;
        let public_id = config.weighted_public_id("wrbc");
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
                    file_bytes,
                    coding,
                } => State::with_params_and_local_reuse(
                    membership.clone(),
                    config.id,
                    instance,
                    public_id,
                    file_bytes,
                    coding,
                    reuse_local_dealer,
                )?,
                _ => {
                    return Err(anyhow::anyhow!(
                        "manifest must contain Register requests only"
                    ));
                }
            };
            states.insert(instance, state);
            startup.push(instance);
        }
        let network = Endpoint::bind(&config, "wrbc")?;
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
            reuse_local_dealer,
        };
        tokio::spawn(async move {
            if let Err(e) = context.run().await {
                log::error!("wrbc service: {}", e);
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
                if util::observation::bulk_audit::enabled() && instance.slot == 0 {
                    if let Some(dealer) = instance.dealer {
                        for action in &actions {
                            if action.recipient == self.id { continue; }
                            if let wavid::Kind::Data { bytes, .. } = &action.message.kind {
                                util::observation::bulk_audit::add(dealer, "data_response_body_bytes", bytes.len());
                            }
                        }
                    }
                }
                let sender = self.network.sender();
                util::weighted_compute::run(move || sender.send_batch(actions)).await??;
            }
            for event in std::mem::take(&mut state.events) {
                if self.output.send(event).await.is_err() {
                    log::debug!("wrbc output receiver closed; retaining peer service");
                }
            }
        }
        Ok(())
    }
}
