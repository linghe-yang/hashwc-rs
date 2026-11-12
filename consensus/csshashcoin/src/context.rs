//! Physical weighted TCP services. WRBC delivers each complete compact CSS+AX record.
use crate::{
    Parameters, State,
    msg::{Action, Behavior, Event, Request},
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
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
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
    state: State,
    input: mpsc::Receiver<Request>,
    output: mpsc::Sender<Event>,
    exit: oneshot::Receiver<()>,
    rbc_tx: mpsc::Sender<wrbc::Request>,
    rbc_rx: mpsc::Receiver<wrbc::Event>,
    ra_tx: mpsc::Sender<wra::Request>,
    ra_rx: mpsc::Receiver<wra::Event>,
    gather_tx: mpsc::Sender<wgather::Request>,
    gather_rx: mpsc::Receiver<wgather::Event>,
    binaa_tx: mpsc::Sender<wbinaa::Request>,
    binaa_rx: mpsc::Receiver<wbinaa::Event>,
    private: PrivateEndpoint,
    recovery: PrivateEndpoint,
    _services: Vec<oneshot::Sender<()>>,
}
impl Context {
    pub fn spawn(
        node: Node,
        params: Parameters,
        input: mpsc::Receiver<Request>,
        output: mpsc::Sender<Event>,
    ) -> Result<Handle> {
        Self::spawn_with_behavior(node, params, Behavior::Honest, input, output)
    }
    pub fn spawn_with_behavior(
        node: Node,
        params: Parameters,
        behavior: Behavior,
        input: mpsc::Receiver<Request>,
        output: mpsc::Sender<Event>,
    ) -> Result<Handle> {
        sdc_util::execution::Settings::from_env()?;
        let ports = Ports::new(&node, params.port_stride)?;
        let state = State::new(&node, params.clone(), behavior)?;
        let params = state.parameters().clone();
        let bound = params.bound_node(&node);
        let (rbc_tx, rbc_in) = mpsc::channel(1024);
        let (rbc_out, rbc_rx) = mpsc::channel(1024);
        let mut services = vec![
            wrbc::Context::spawn_with_manifest_and_local_reuse(
                ports.node(&bound, Service::Rbc)?,
                rbc_in,
                rbc_out,
                state.rbc_manifest(),
                params.reuse_local_dealer,
            )
            .context("WRBC")?,
        ];
        let (ra_tx, ra_in) = mpsc::channel(1024);
        let (ra_out, ra_rx) = mpsc::channel(1024);
        services.push(
            wra::Context::spawn_with_manifest(
                ports.node(&bound, Service::Ra)?,
                ra_in,
                ra_out,
                state.ra_manifest(),
            )
            .context("WRA")?,
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
            .context("WGather")?,
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
                    precision: params.precision(node.num_nodes),
                }],
                params.compact_binaa,
            )
            .context("WBinAA")?,
        );
        let private = PrivateEndpoint::bind(
            &ports.node(&bound, Service::Private)?,
            "csshashcoin/private",
        )?;
        let recovery = PrivateEndpoint::bind(
            &ports.node(&bound, Service::Recovery)?,
            "csshashcoin/recovery",
        )?;
        let (stop, exit) = oneshot::channel();
        let context = Self {
            state,
            input,
            output: output.clone(),
            exit,
            rbc_tx,
            rbc_rx,
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
                let _ = output.try_send(Event::Failed {
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
            mut rbc_rx,
            rbc_tx,
            mut ra_rx,
            ra_tx,
            mut gather_rx,
            gather_tx,
            mut binaa_rx,
            binaa_tx,
            mut private,
            mut recovery,
            _services,
        } = self;
        let settings = sdc_util::execution::Settings::from_env()?;
        let private_tx = private.sender();
        let recovery_tx = recovery.sender();
        let mut state = state;
        state.enable_cooperative_recovery();
        let (inbox, mut effects, mut worker) = sdc_util::weighted_actor::spawn_resumable(
            state,
            settings.actor_inbox,
            apply,
            State::recovery_pending,
            |state| {
                state.resume_recovery()?;
                take_effects(state, None)
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
                    event=rbc_rx.recv()=>Input::Rbc(event.ok_or_else(||anyhow!("WRBC stopped"))?),
                    event=ra_rx.recv()=>Input::Ra(event.ok_or_else(||anyhow!("WRA stopped"))?),
                    event=gather_rx.recv()=>Input::Gather(event.ok_or_else(||anyhow!("WGather stopped"))?),
                    event=binaa_rx.recv()=>Input::BinAa(event.ok_or_else(||anyhow!("WBinAA stopped"))?),
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
                            Action::Rbc(request)=>rbc_tx.send(request).await?,
                            Action::Ra(request)=>ra_tx.send(request).await?,
                            Action::Gather(request)=>gather_tx.send(request).await?,
                            Action::BinAa(request)=>binaa_tx.send(request).await?,
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
    Rbc(wrbc::Event),
    Ra(wra::Event),
    Gather(wgather::Event),
    BinAa(wbinaa::Event),
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
        Input::Rbc(event) => state.rbc_event(event)?,
        Input::Ra(event) => state.ra_event(event)?,
        Input::Gather(event) => state.gather_event(event)?,
        Input::BinAa(event) => state.binaa_event(event)?,
        Input::Private(sender, packet) => {
            if packet.kind == crate::msg::PRIVATE {
                state.packet(sender, packet)?;
            }
        }
        Input::Recovery(sender, packet) => {
            if packet.kind == crate::msg::RECONSTRUCT {
                state.packet(sender, packet)?;
            }
        }
    }
    take_effects(state, inspection)
}
fn take_effects(
    state: &mut State,
    inspection: Option<(
        mpsc::UnboundedSender<sdc_util::observation::ServiceProgress>,
        sdc_util::observation::ServiceProgress,
    )>,
) -> Result<Option<Effects>> {
    // Local actions still execute serially, with exactly the old self-message semantics.
    let mut actions = Vec::new();
    loop {
        let generated = std::mem::take(&mut state.actions);
        if generated.is_empty() {
            break;
        }
        for action in generated {
            match action {
                Action::Private { recipient, packet } | Action::Recovery { recipient, packet }
                    if recipient == state.id =>
                {
                    state.packet(recipient, packet)?
                }
                remote => actions.push(remote),
            }
        }
    }
    let events = std::mem::take(&mut state.events);
    if actions.is_empty() && events.is_empty() && inspection.is_none() {
        return Ok(None);
    }
    Ok(Some(Effects {
        actions,
        events,
        inspection,
    }))
}
