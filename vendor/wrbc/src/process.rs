use crate::{Context, Event, ProtMsg, Request, State};
use anyhow::{Result, ensure};
use util::weighted::MAX_INSTANCES;
impl Context {
    pub(crate) async fn process_msg(&mut self, sender: usize, msg: ProtMsg) -> Result<()> {
        log::debug!(
            "Node {}: received message from node {} for instance {:?}",
            self.id,
            sender,
            msg.instance
        );
        let instance = msg.instance;
        if let Some(mut state) = self.states.remove(&instance) {
            state = util::weighted_compute::run(move || {
                state.receive(sender, msg);
                state
            })
            .await?;
            self.states.insert(instance, state);
        }
        self.flush(instance).await
    }
    pub(crate) async fn process_request(&mut self, request: Request) -> Result<()> {
        let instance = request.instance();
        let registering = matches!(&request, Request::Register { .. });
        let result: Result<()> = async {
            match request {
                Request::Register {
                    file_bytes, coding, ..
                } => {
                    ensure!(
                        !self.states.contains_key(&instance) && self.states.len() < MAX_INSTANCES,
                        "duplicate registration or instance limit"
                    );
                    self.states.insert(
                        instance,
                        State::with_params_and_local_reuse(
                            self.membership.clone(),
                            self.id,
                            instance,
                            self.network.public_id,
                            file_bytes,
                            coding,
                            self.reuse_local_dealer,
                        )?,
                    );
                }
                Request::Broadcast { data, .. } => {
                    let mut state = self
                        .states
                        .remove(&instance)
                        .ok_or_else(|| anyhow::anyhow!("unregistered instance"))?;
                    let (state, result) = util::weighted_compute::run(move || {
                        let result = state.broadcast(&data);
                        (state, result)
                    })
                    .await?;
                    self.states.insert(instance, state);
                    result?;
                }
            }
            Ok(())
        }
        .await;
        if result.is_ok() && registering {
            let _ = self.output.send(Event::Registered { instance }).await;
        }
        if let Err(e) = result {
            let _ = self
                .output
                .send(Event::Rejected {
                    instance,
                    reason: e.to_string(),
                })
                .await;
        }
        self.flush(instance).await
    }
}
