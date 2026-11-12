use super::{Kind, Message, Request, ServiceEvent, State};
use anyhow::{Result, anyhow, ensure};
use sdc_types::{InstanceId, SendAction};
use sdc_util::weighted::Endpoint;
use std::collections::{BTreeMap, VecDeque};
use tokio::sync::{mpsc, oneshot};

/// One RBC port; explicit manifests choose fixed roots, fixed list chunks or
/// legacy coded ablations. No decision depends on observed payload length.
pub(crate) fn spawn(
    node: config::Node,
    epoch: u64,
    short_roots: bool,
    manifest: Vec<wrbc::Request>,
    chunk_lengths: Vec<usize>,
    mut roots_in: mpsc::Receiver<Request>,
    roots_out: mpsc::Sender<ServiceEvent>,
    mut coded_in: mpsc::Receiver<wrbc::Request>,
    coded_out: mpsc::Sender<wrbc::Event>,
) -> Result<oneshot::Sender<()>> {
    node.validate_weighted()?;
    let membership = node.weighted_membership()?;
    ensure!(
        usize::from(short_roots) * node.num_nodes
            + manifest.len()
            + chunk_lengths
                .iter()
                .map(|l| l / recovery::ranked::BLOCK_BYTES)
                .sum::<usize>()
            <= sdc_util::weighted::MAX_INSTANCES,
        "RBC instance limit"
    );
    let mut roots = (0..if short_roots { node.num_nodes } else { 0 })
        .map(|d| {
            let instance = InstanceId::new(epoch, Some(d), 0);
            Ok((
                instance,
                State::<super::Root>::new(membership.clone(), node.id, instance)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut coded = BTreeMap::new();
    let mut chunks = super::chunks::Lists::new(membership.clone(), node.id, epoch, &chunk_lengths)?;
    for registration in manifest {
        let wrbc::Request::Register {
            instance,
            file_bytes,
            coding,
        } = registration
        else {
            return Err(anyhow!("coded manifest must contain registrations"));
        };
        ensure!(
            instance.epoch == epoch
                && ((instance.slot == 0 && !short_roots)
                    || (instance.slot == 1 && chunk_lengths.is_empty()))
                && instance.dealer.is_some_and(|d| d < node.num_nodes)
                && !coded.contains_key(&instance),
            "invalid/duplicate list instance"
        );
        coded.insert(
            instance,
            wrbc::State::with_params(
                membership.clone(),
                node.id,
                instance,
                node.weighted_public_id("wrbc"),
                file_bytes,
                coding,
            )?,
        );
    }
    let mut network = Endpoint::<Message>::bind(&node, "wrbc")?;
    let (stop, mut exit) = oneshot::channel();
    tokio::spawn(async move {
        let result:Result<()> = async {
            let mut root_events=VecDeque::new();
            let mut coded_events=VecDeque::new();
            let (mut root_input_open,mut coded_input_open)=(true,true);
            let (mut root_output_open,mut coded_output_open)=(true,true);
            loop {
                // Reserve output without blocking incoming peer service or shutdown.
                let changed=tokio::select! {
                    _=&mut exit=>break,
                    permit=roots_out.reserve(),if root_output_open && !root_events.is_empty()=> {
                        match permit {Ok(p)=>p.send(root_events.pop_front().unwrap()),
                            Err(_)=>{root_output_open=false;root_events.clear();}}
                        None
                    },
                    permit=coded_out.reserve(),if coded_output_open && !coded_events.is_empty()=> {
                        match permit {Ok(p)=>p.send(coded_events.pop_front().unwrap()),
                            Err(_)=>{coded_output_open=false;coded_events.clear();}}
                        None
                    },
                    request=roots_in.recv(),if root_input_open=> {
                        if let Some(Request {instance,root})=request {
                            roots.get_mut(&instance).ok_or_else(||anyhow!("unregistered root"))?.broadcast(root)?;
                            Some(instance)
                        } else {root_input_open=false;None}
                    },
                    request=coded_in.recv(),if coded_input_open=> {
                        if let Some(request)=request {
                            let wrbc::Request::Broadcast {instance,data}=request else {
                                return Err(anyhow!("manifest is immutable"));
                            };
                            if instance.slot==1 && !chunk_lengths.is_empty() {
                                chunks.broadcast(instance,&data)?;
                            } else {
                                coded.get_mut(&instance).ok_or_else(||anyhow!("unregistered coded instance"))?.broadcast(&data)?;
                            }
                            Some(instance)
                        } else {coded_input_open=false;None}
                    },
                    incoming=network.recv.recv()=> {
                        let Some((sender,msg))=incoming else {break;};
                        let instance=msg.instance;
                        if let Kind::Coded(kind)=msg.kind {
                            if let Some(state)=coded.get_mut(&instance) {
                                state.receive(sender,wavid::ProtMsg {instance,kind:*kind});
                                Some(instance)
                            } else {None}
                        } else if let Some(state)=roots.get_mut(&instance) {
                            state.receive(sender,msg);
                            Some(instance)
                        } else {
                            chunks.receive(sender,msg);
                            Some(instance)
                        }
                    }
                };
                network.sender().send_batch(std::mem::take(&mut chunks.outgoing))?;
                if root_output_open {root_events.extend(std::mem::take(&mut chunks.events).into_iter().map(ServiceEvent::List));}
                else {chunks.events.clear();}
                if let Some(instance)=changed {
                    if let Some(state)=roots.get_mut(&instance) {
                        network.sender().send_batch(std::mem::take(&mut state.outgoing))?;
                        if root_output_open {root_events.extend(std::mem::take(&mut state.events).into_iter().map(ServiceEvent::Root));}
                        else {state.events.clear();}
                    } else if let Some(state)=coded.get_mut(&instance) {
                        let actions=std::mem::take(&mut state.outgoing).into_iter().map(|a|SendAction {
                            recipient:a.recipient,
                            message:Message {instance:a.message.instance,kind:Kind::Coded(Box::new(a.message.kind))}
                        }).collect();
                        network.sender().send_batch(actions)?;
                        if coded_output_open {coded_events.extend(std::mem::take(&mut state.events));}
                        else {state.events.clear();}
                    }
                }
            }
            Ok(())
        }.await;
        if let Err(e) = result {
            log::error!("WHCC short-root RBC service: {e:#}");
        }
    });
    Ok(stop)
}
