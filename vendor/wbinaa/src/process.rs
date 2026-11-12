use crate::{Context, Event, ProtMsg, Request, State};
use anyhow::{ensure, Result};
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
        if let Some(state) = self.states.get_mut(&instance) {
            state.receive(sender, msg);
        }
        self.flush(instance).await
    }
    pub(crate) async fn process_request(&mut self, request: Request) -> Result<()> {
        let instance = request.instance();
        let registering = matches!(&request, Request::Register { .. });
        let result = (|| -> Result<()> {
            match request {
                Request::Register { precision, .. } => {
                    ensure!(
                        !self.states.contains_key(&instance) && self.states.len() < MAX_INSTANCES,
                        "duplicate registration or instance limit"
                    );
                    let mut state =
                        State::new(self.membership.clone(), self.id, instance, precision)?;
                    if self.compact {
                        state.batch_entries = 3 * self.membership.n();
                    }
                    self.states.insert(instance, state);
                }
                Request::StartSelected {
                    inputs,
                    coordinates,
                    ..
                } => self
                    .states
                    .get_mut(&instance)
                    .ok_or_else(|| anyhow::anyhow!("unregistered instance"))?
                    .start_selected(inputs, coordinates)?,
                Request::Start { inputs, .. } => self
                    .states
                    .get_mut(&instance)
                    .ok_or_else(|| anyhow::anyhow!("unregistered instance"))?
                    .start(inputs)?,
            }
            Ok(())
        })();
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
