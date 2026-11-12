//! Tokio protocol entry point: each primitive owns its TCP port and communicates through channels.
use crate::{
    Parameters,
    msg::{Action, Event, Request},
    state::State,
};
use anyhow::{Context as _, Result, anyhow};
use config::{Node, Ports, Service};
use network::PrivateEndpoint;
use std::collections::VecDeque;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

pub struct Handle {
    pub stop: Option<oneshot::Sender<()>>,
    pub task: Option<JoinHandle<Result<()>>>,
}
impl Handle {
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
pub struct Context {
    pub state: State,
    pub input: mpsc::Receiver<Request>,
    pub output: mpsc::Sender<Event>,
    pub exit: oneshot::Receiver<()>,
    pub avid_tx: mpsc::Sender<wavid::Request>,
    pub avid_rx: mpsc::Receiver<wavid::Event>,
    pub rbc_tx: mpsc::Sender<wrbc::Request>,
    pub rbc_rx: mpsc::Receiver<wrbc::Event>,
    pub root_tx: Option<mpsc::Sender<crate::root_rbc::Request>>,
    pub root_rx: mpsc::Receiver<crate::root_rbc::ServiceEvent>,
    pub ra_tx: mpsc::Sender<wra::Request>,
    pub ra_rx: mpsc::Receiver<wra::Event>,
    pub gather_tx: mpsc::Sender<wgather::Request>,
    pub gather_rx: mpsc::Receiver<wgather::Event>,
    pub binaa_tx: mpsc::Sender<wbinaa::Request>,
    pub binaa_rx: mpsc::Receiver<wbinaa::Event>,
    pub private: PrivateEndpoint,
    pub recovery: PrivateEndpoint,
    // Dropping these signals cancels all upstream service tasks, including on partial startup failure.
    pub _services: Vec<oneshot::Sender<()>>,
}
impl Context {
    pub fn spawn(
        node: Node,
        parameters: Parameters,
        input: mpsc::Receiver<Request>,
        output: mpsc::Sender<Event>,
    ) -> Result<Handle> {
        Self::spawn_with_behavior(node, parameters, crate::Behavior::Honest, input, output)
    }
    pub fn spawn_with_behavior(
        node: Node,
        parameters: Parameters,
        behavior: crate::Behavior,
        input: mpsc::Receiver<Request>,
        output: mpsc::Sender<Event>,
    ) -> Result<Handle> {
        // Validate ALL addresses before binding the first socket.
        sdc_util::execution::Settings::from_env()?;
        let ports = Ports::new(&node, parameters.port_stride)?;
        let mut state = State::new(&node, parameters.clone())?;
        state.behavior = behavior;
        let parameters = state.params.clone();
        let bound = parameters.bound_node(&node, state.setup());
        let mut services = vec![];
        let (rbc_tx, rbc_in) = mpsc::channel(1024);
        let (rbc_out, rbc_rx) = mpsc::channel(1024);
        let (root_tx, root_in) = mpsc::channel(1024);
        let (root_out, root_rx) = mpsc::channel(1024);
        let root_tx = if parameters.short_root_rbc || !state.list_chunk_lengths().is_empty() {
            services.push(
                crate::root_rbc::spawn(
                    ports.node(&bound, Service::Rbc)?,
                    parameters.epoch,
                    parameters.short_root_rbc,
                    state.rbc_manifest(),
                    state.list_chunk_lengths(),
                    root_in,
                    root_out,
                    rbc_in,
                    rbc_out,
                )
                .context("start short-root RBC")?,
            );
            Some(root_tx)
        } else {
            services.push(
                wrbc::Context::spawn_with_manifest(
                    ports.node(&bound, Service::Rbc)?,
                    rbc_in,
                    rbc_out,
                    state.rbc_manifest(),
                )
                .context("start WRBC")?,
            );
            None
        };
        let (avid_tx, avid_in) = mpsc::channel(1024);
        let (avid_out, avid_rx) = mpsc::channel(1024);
        services.push(
            wavid::Context::spawn_with_manifest(
                ports.node(&bound, Service::Avid)?,
                avid_in,
                avid_out,
                state.avid_manifest(),
            )
            .context("start WAVID")?,
        );
        let (ra_tx, ra_in) = mpsc::channel(1024);
        let (ra_out, ra_rx) = mpsc::channel(1024);
        services.push(
            wra::Context::spawn_with_manifest(
                ports.node(&bound, Service::Ra)?,
                ra_in,
                ra_out,
                state.ra_manifest(),
            )
            .context("start WRA")?,
        );
        let (gather_tx, gather_in) = mpsc::channel(1024);
        let (gather_out, gather_rx) = mpsc::channel(1024);
        services.push(
            wgather::Context::spawn_with_manifest(
                ports.node(&bound, Service::Gather)?,
                gather_in,
                gather_out,
                vec![wgather::Request::Register {
                    instance: state.global(),
                }],
            )
            .context("start WGather")?,
        );
        let (binaa_tx, binaa_in) = mpsc::channel(1024);
        let (binaa_out, binaa_rx) = mpsc::channel(1024);
        services.push(
            wbinaa::Context::spawn_with_manifest_and_compact(
                ports.node(&bound, Service::BinAa)?,
                binaa_in,
                binaa_out,
                vec![wbinaa::Request::Register {
                    instance: state.global(),
                    precision: parameters.precision(node.num_nodes),
                }],
                parameters.compact_binaa,
            )
            .context("start WBinAA")?,
        );
        let private =
            PrivateEndpoint::bind(&ports.node(&bound, Service::Private)?, "whcc/private")?;
        let recovery =
            PrivateEndpoint::bind(&ports.node(&bound, Service::Recovery)?, "whcc/recovery")?;
        let (stop, exit) = oneshot::channel();
        let failure_out = output.clone();
        let context = Self {
            state,
            input,
            output,
            exit,
            avid_tx,
            avid_rx,
            rbc_tx,
            rbc_rx,
            root_tx,
            root_rx,
            ra_tx,
            ra_rx,
            gather_tx,
            gather_rx,
            binaa_tx,
            binaa_rx,
            private,
            recovery,
            _services: services,
        };
        let task = tokio::spawn(async move {
            let result = context.run().await;
            if let Err(e) = &result {
                log::error!("whcc failed: {e:#}");
                let _ = failure_out.try_send(Event::Failed {
                    reason: format!("{e:#}"),
                });
            }
            result
        });
        Ok(Handle {
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn run(self) -> Result<()> {
        let Self {
            state,
            mut input,
            output,
            mut exit,
            mut avid_rx,
            avid_tx,
            mut rbc_rx,
            rbc_tx,
            mut ra_rx,
            ra_tx,
            mut gather_rx,
            gather_tx,
            mut binaa_rx,
            binaa_tx,
            root_tx,
            mut root_rx,
            mut private,
            mut recovery,
            _services,
        } = self;
        let settings = sdc_util::execution::Settings::from_env()?;
        let private_tx = private.sender();
        let recovery_tx = recovery.sender();
        let has_root = root_tx.is_some();
        let mut state = state;
        state.enable_cooperative_recovery();
        let (inbox, mut effects, mut worker) = sdc_util::weighted_actor::spawn_resumable(
            state,
            settings.actor_inbox,
            apply,
            State::recovery_pending,
            |state| {
                state.resume_recovery()?;
                Ok(take_effects(state, None))
            },
        );
        let meter = worker.meter.clone();
        let mut tasks = tokio::task::JoinSet::<Result<()>>::new();
        // This task keeps consuming messages while the serial CPU worker runs.
        tasks.spawn(async move {
            let mut input_open = true;
            loop {
                let event = tokio::select! {
                    request=input.recv(),if input_open=>match request {
                        Some(request)=>Input::Request(request),
                        None=>{input_open=false;continue;},
                    },
                    event=avid_rx.recv()=>Input::Avid(event.ok_or_else(||anyhow!("WAVID stopped"))?),
                    event=rbc_rx.recv()=>Input::Rbc(event.ok_or_else(||anyhow!("WRBC stopped"))?),
                    event=ra_rx.recv()=>Input::Ra(event.ok_or_else(||anyhow!("WRA stopped"))?),
                    event=gather_rx.recv()=>Input::Gather(event.ok_or_else(||anyhow!("WGather stopped"))?),
                    event=binaa_rx.recv()=>Input::BinAa(event.ok_or_else(||anyhow!("WBinAA stopped"))?),
                    event=root_rx.recv(),if has_root=>Input::Root(event.ok_or_else(||anyhow!("short RBC stopped"))?),
                    packet=private.recv()=>{let (sender,packet)=packet.ok_or_else(||anyhow!("private service stopped"))?;Input::Private(sender,packet)},
                    packet=recovery.recv()=>{let (sender,packet)=packet.ok_or_else(||anyhow!("recovery service stopped"))?;Input::Recovery(sender,packet)},
                };
                inbox.send(event).await?;
            }
        });
        // Dispatch preserves each state's action/event order. A slow primitive
        // cannot stop the independent ingress relay or monopolize a CPU worker.
        tasks.spawn(async move {
            let mut pending = VecDeque::new();
            let mut output_open = true;
            loop {
                tokio::select! {
                    permit=output.reserve(),if output_open && !pending.is_empty()=>match permit {
                        Ok(permit)=>permit.send(pending.pop_front().unwrap()),
                        Err(_)=>{output_open=false;pending.clear();},
                    },
                    batch=effects.recv()=>{
                        let mut batch=batch.ok_or_else(||anyhow!("CPU state worker stopped"))??;
                        let mut ready_recovery = Vec::new();
                        for (index,action) in std::mem::take(&mut batch.value.actions).into_iter().enumerate() {
                            match action {
                            Action::Avid(request)=>avid_tx.send(request).await?,
                            Action::Rbc(request)=>rbc_tx.send(request).await?,
                            Action::Ra(request)=>ra_tx.send(request).await?,
                            Action::Gather(request)=>gather_tx.send(request).await?,
                            Action::BinAa(request)=>binaa_tx.send(request).await?,
                            Action::RootRbc(request)=>root_tx.as_ref().ok_or_else(||anyhow!("short-root service missing"))?.send(request).await?,
                                Action::Private {recipient,packet}=>private_tx.send(recipient,&packet)?,
                                Action::Recovery {recipient,packet}=>ready_recovery.push((recipient,packet)),
                            }
                            if index % 64 == 63 { tokio::task::yield_now().await; }
                        }
                        recovery_tx.send_ready(ready_recovery)?;
                        if output_open { pending.extend(std::mem::take(&mut batch.value.events)); }
                        let inspection=batch.value.inspection.take();
                        // Inspection is delivered only after preceding effects;
                        // its own ticket must not keep an idle worker "busy".
                        drop(batch);
                        if let Some((reply,progress))=inspection {let _=reply.send(meter.annotate(progress));}
                    },
                }
            }
        });
        let result = tokio::select! {
            biased;
            _=&mut exit=>Ok(()),
            result=tasks.join_next()=>match result {
                Some(Ok(result))=>result,
                Some(Err(error))=>Err(error.into()),
                None=>Err(anyhow!("execution tasks stopped")),
            },
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let stopped = worker.shutdown().await;
        drop(_services);
        result.and(stopped)
    }
}

enum Input {
    Request(Request),
    Avid(wavid::Event),
    Rbc(wrbc::Event),
    Ra(wra::Event),
    Gather(wgather::Event),
    BinAa(wbinaa::Event),
    Root(crate::root_rbc::ServiceEvent),
    Private(usize, network::Packet),
    Recovery(usize, network::Packet),
}
struct Effects {
    actions: Vec<Action>,
    events: Vec<Event>,
    inspection: Option<(
        mpsc::UnboundedSender<sdc_util::observation::ServiceProgress>,
        sdc_util::observation::ServiceProgress,
    )>,
}
fn apply(state: &mut State, input: Input) -> Result<Option<Effects>> {
    let mut inspection = None;
    match input {
        Input::Request(Request::Start) => state.start()?,
        Input::Request(Request::Inspect { reply }) => {
            inspection = Some((reply, state.service_progress()))
        }
        Input::Avid(event) => state.avid_event(event)?,
        Input::Rbc(event) => state.rbc_event(event)?,
        Input::Ra(event) => state.ra_event(event)?,
        Input::Gather(event) => state.gather_event(event)?,
        Input::BinAa(event) => state.binaa_event(event)?,
        Input::Root(event) => state.short_broadcast_event(event)?,
        Input::Private(sender, packet) => state.private_packet(sender, packet)?,
        Input::Recovery(sender, packet) => state.recovery_packet(sender, packet)?,
    }
    Ok(take_effects(state, inspection))
}
fn take_effects(
    state: &mut State,
    inspection: Option<(
        mpsc::UnboundedSender<sdc_util::observation::ServiceProgress>,
        sdc_util::observation::ServiceProgress,
    )>,
) -> Option<Effects> {
    let actions = state.drain_actions();
    let events = state.drain_events();
    if actions.is_empty() && events.is_empty() && inspection.is_none() {
        return None;
    }
    Some(Effects {
        actions,
        events,
        inspection,
    })
}
