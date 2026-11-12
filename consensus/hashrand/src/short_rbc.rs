//! Adapter for the existing weighted Bracha state machine; exactly 32 B per root.
use anyhow::{Result, anyhow, ensure};
use std::collections::{BTreeMap, VecDeque};
use tokio::sync::{mpsc, oneshot};
use whcc::root_rbc::{Event, Message, State};

pub(crate) fn spawn(
    node: config::Node,
    manifest: Vec<wrbc::Request>,
    mut input: mpsc::Receiver<wrbc::Request>,
    output: mpsc::Sender<Event>,
) -> Result<oneshot::Sender<()>> {
    let membership = node.weighted_membership()?;
    ensure!(
        manifest.len() <= sdc_util::weighted::MAX_INSTANCES,
        "root instance limit"
    );
    let mut states = BTreeMap::new();
    for request in manifest {
        let wrbc::Request::Register {
            instance,
            file_bytes,
            ..
        } = request
        else {
            return Err(anyhow!("immutable root manifest"));
        };
        ensure!(
            file_bytes == 32 && !states.contains_key(&instance),
            "root manifest must contain unique 32 B values"
        );
        states.insert(instance, State::<[u8;32]>::new(membership.clone(), node.id, instance)?);
    }
    let mut network = sdc_util::weighted::Endpoint::<Message>::bind(&node, "wrbc")?;
    let (stop, mut exit) = oneshot::channel();
    tokio::spawn(async move {
        let result:Result<()>=async {
            let mut pending=VecDeque::new();let mut input_open=true;let mut output_open=true;
            loop {
                let changed=tokio::select! {
                    _=&mut exit=>break,
                    permit=output.reserve(),if output_open && !pending.is_empty()=>{
                        match permit {Ok(p)=>p.send(pending.pop_front().unwrap()),Err(_)=>{output_open=false;pending.clear();}} None
                    },
                    req=input.recv(),if input_open=>{
                        if let Some(wrbc::Request::Broadcast {instance,data})=req {
                            let root=data.as_slice().try_into().map_err(|_|anyhow!("root length"))?;
                            states.get_mut(&instance).ok_or_else(||anyhow!("unregistered root"))?.broadcast(root)?;Some(instance)
                        } else {input_open=false;None}
                    },
                    msg=network.recv.recv()=>{
                        let Some((sender,msg))=msg else {break;};let instance=msg.instance;
                        if let Some(state)=states.get_mut(&instance) {state.receive(sender,msg);Some(instance)} else {None}
                    }
                };
                if let Some(id)=changed {
                    let state=states.get_mut(&id).unwrap();
                    network.sender().send_batch(std::mem::take(&mut state.outgoing))?;
                    if output_open {pending.extend(std::mem::take(&mut state.events));} else {state.events.clear();}
                }
            }
            Ok(())
        }.await;
        if let Err(e) = result {
            log::error!("HashRand short root RBC: {e:#}");
        }
    });
    Ok(stop)
}
