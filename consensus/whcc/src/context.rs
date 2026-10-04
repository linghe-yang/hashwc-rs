//! Tokio protocol entry point: each primitive owns its TCP port and communicates through channels.
use crate::{
    Parameters,
    msg::{Event, Request},
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
    pub pending_events: VecDeque<Event>,
    pub input: mpsc::Receiver<Request>,
    pub output: mpsc::Sender<Event>,
    pub exit: oneshot::Receiver<()>,
    pub rbc_tx: mpsc::Sender<wrbc::Request>,
    pub rbc_rx: mpsc::Receiver<wrbc::Event>,
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
        let ports = Ports::new(&node, parameters.port_stride)?;
        let mut state = State::new(&node, parameters.clone())?;
        state.behavior = behavior;
        let bound = parameters.bound_node(&node, state.setup());
        let mut services = vec![];
        let (rbc_tx, rbc_in) = mpsc::channel(1024);
        let (rbc_out, rbc_rx) = mpsc::channel(1024);
        services.push(
            wrbc::Context::spawn_with_manifest(
                ports.node(&bound, Service::Rbc)?,
                rbc_in,
                rbc_out,
                state.rbc_manifest(),
            )
            .context("start WRBC")?,
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
            wbinaa::Context::spawn_with_manifest(
                ports.node(&bound, Service::BinAa)?,
                binaa_in,
                binaa_out,
                vec![wbinaa::Request::Register {
                    instance: state.global(),
                    precision: parameters.precision(node.num_nodes),
                }],
            )
            .context("start WBinAA")?,
        );
        let private =
            PrivateEndpoint::bind(&ports.node(&bound, Service::Private)?, "whcc/private")?;
        let recovery =
            PrivateEndpoint::bind(&ports.node(&bound, Service::Recovery)?, "whcc/recovery")?;
        let (stop, exit) = oneshot::channel();
        let failure_out = output.clone();
        let mut context = Self {
            state,
            pending_events: VecDeque::new(),
            input,
            output,
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
    pub async fn run(&mut self) -> Result<()> {
        let mut input_open = true;
        let mut output_open = true;
        loop {
            tokio::select! {
                permit=self.output.reserve(), if output_open && !self.pending_events.is_empty()=>match permit {
                    Ok(permit)=>permit.send(self.pending_events.pop_front().unwrap()),
                    Err(_)=>{output_open=false;self.pending_events.clear();},
                },
                _=&mut self.exit=>return Ok(()),
                request=self.input.recv(),if input_open=>match request {
                    Some(Request::Start)=>self.state.start()?,None=>input_open=false,
                },
                event=self.rbc_rx.recv()=>self.state.rbc_event(event.ok_or_else(||anyhow!("WRBC stopped"))?)?,
                event=self.ra_rx.recv()=>self.state.ra_event(event.ok_or_else(||anyhow!("WRA stopped"))?)?,
                event=self.gather_rx.recv()=>self.state.gather_event(event.ok_or_else(||anyhow!("WGather stopped"))?)?,
                event=self.binaa_rx.recv()=>self.state.binaa_event(event.ok_or_else(||anyhow!("WBinAA stopped"))?)?,
                packet=self.private.recv()=>{let (sender,packet)=packet.ok_or_else(||anyhow!("private service stopped"))?;self.state.private_packet(sender,packet)?;},
                packet=self.recovery.recv()=>{let (sender,packet)=packet.ok_or_else(||anyhow!("recovery service stopped"))?;self.state.recovery_packet(sender,packet)?;},
            }
            self.flush().await?;
        }
    }
}
