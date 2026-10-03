//! Transport-independent per-party protocol. Sender IDs MUST come from authenticated
//! private channels. WRBC/WRA are upstream state machines, not local reimplementations.
use crate::{Context, Opening, PrivateShare, Public, Recovery, Setup, ax};
use anyhow::{Result, ensure};
use hashwc_crypto::Block;
use hashwc_types::Error;
use sdc_types::{InstanceId, WeightedMembership};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug)]
pub enum Message {
    Public(wrbc::ProtMsg),
    Completion(wra::ProtMsg),
    Private(PrivateShare),
    Open(PrivateShare),
}
#[derive(Clone, Debug)]
pub struct Action {
    pub recipient: usize,
    pub message: Message,
}
#[derive(Debug)]
pub enum Event {
    Shared,
    Reconstructed(Recovery),
    Bottom,
    InvalidPublic,
}

pub struct State {
    setup: Arc<Setup>,
    context: Context,
    id: usize,
    instance: InstanceId,
    membership: WeightedMembership,
    broadcast: wrbc::State,
    completion: Option<wra::State>,
    public: Option<Public>,
    private: Option<PrivateShare>,
    pending_private: Option<PrivateShare>,
    pending_completion: BTreeMap<(usize, u8), wra::ProtMsg>,
    pending_open: BTreeMap<usize, PrivateShare>,
    opened: BTreeMap<usize, PrivateShare>,
    complete: bool,
    opening_requested: bool,
    released: bool,
    terminated: bool,
    started: bool,
    invalid: bool,
    outgoing: Vec<Action>,
    events: Vec<Event>,
}
impl State {
    pub fn new(setup: Arc<Setup>, context: Context, id: usize) -> Result<Self> {
        context.validate(&setup)?;
        let policy = setup.circuit().policy();
        policy.validate_async()?;
        ensure!(id < policy.n(), "party out of range");
        // Convert the current BigUint API at the upstream crate boundary only.
        let weights = policy
            .weights()
            .iter()
            .map(|w| w.to_string().parse().map_err(anyhow::Error::msg))
            .collect::<Result<Vec<_>>>()?;
        let membership = WeightedMembership::new(
            weights,
            policy
                .threshold()
                .to_string()
                .parse()
                .map_err(anyhow::Error::msg)?,
        )
        .map_err(anyhow::Error::msg)?;
        let instance =
            InstanceId::new(context.instance().epoch, Some(context.instance().dealer), 0);
        let broadcast = wrbc::State::new(
            membership.clone(),
            id,
            instance,
            context.id(),
            Public::encoded_len(&setup),
        )?;
        Ok(Self {
            setup,
            context,
            id,
            instance,
            membership,
            broadcast,
            completion: None,
            public: None,
            private: None,
            pending_private: None,
            pending_completion: BTreeMap::new(),
            pending_open: BTreeMap::new(),
            opened: BTreeMap::new(),
            complete: false,
            opening_requested: false,
            released: false,
            terminated: false,
            started: false,
            invalid: false,
            outgoing: vec![],
            events: vec![],
        })
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }
    pub fn public(&self) -> Option<&Public> {
        self.public.as_ref()
    }
    pub fn drain_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.outgoing)
    }
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
    pub fn start(&mut self, message: Block) -> Result<()> {
        ensure!(
            self.id == self.context.instance().dealer && !self.started,
            "only dealer may share once"
        );
        let (public, shares) = ax::share(&self.setup, &self.context, message)?;
        self.start_generated(public, shares)
    }
    /// Deterministic dealer input for reproducibility; opening randomness must be fresh in production.
    pub fn start_with_opening(&mut self, opening: &Opening) -> Result<()> {
        ensure!(
            self.id == self.context.instance().dealer && !self.started,
            "only dealer may share once"
        );
        let (public, shares) = ax::generate(&self.setup, &self.context, opening)?;
        self.start_generated(public, shares)
    }
    fn start_generated(&mut self, public: Public, shares: Vec<PrivateShare>) -> Result<()> {
        self.broadcast.broadcast(&public.encode())?;
        self.started = true;
        for share in shares {
            self.outgoing.push(Action {
                recipient: share.party,
                message: Message::Private(share),
            });
        }
        self.collect_broadcast()?;
        Ok(())
    }
    /// Call only after the OUTER protocol authorizes release (e.g. freezes its whole BinAA vector).
    /// Can be requested before local completion; release waits for completion and a valid receipt.
    pub fn begin_reconstruction(&mut self) -> Result<()> {
        self.opening_requested = true;
        self.advance()
    }
    pub fn receive(&mut self, sender: usize, message: Message) -> Result<()> {
        if sender >= self.membership.n() {
            return Ok(());
        }
        match message {
            Message::Public(msg) => {
                self.broadcast.receive(sender, msg);
                self.collect_broadcast()?;
            }
            Message::Completion(msg) => {
                if msg.instance != self.instance {
                    return Ok(());
                }
                if let Some(ra) = self.completion.as_mut() {
                    ra.receive(sender, msg);
                } else if !self.invalid {
                    let kind = match msg.kind {
                        wra::Kind::Echo(_) => 0,
                        wra::Kind::Ready(_) => 1,
                    };
                    self.pending_completion.entry((sender, kind)).or_insert(msg);
                }
            }
            Message::Private(s) => {
                if sender != self.context.instance().dealer
                    || s.party != self.id
                    || !self.match_share(&s)
                {
                    return Ok(());
                }
                if self.private.is_none() {
                    self.pending_private = Some(s);
                }
            }
            Message::Open(s) => {
                if s.party != sender || !self.match_share(&s) {
                    return Ok(());
                }
                if let Some(public) = &self.public {
                    if ax::verify_share(&self.setup, &self.context, public, &s) {
                        self.opened.entry(sender).or_insert(s);
                    }
                } else if !self.invalid {
                    self.pending_open.insert(sender, s);
                }
            }
        }
        self.advance()
    }
    fn match_share(&self, s: &PrivateShare) -> bool {
        s.setup_id == self.setup.id() && s.context_id == self.context.id()
    }
    fn collect_broadcast(&mut self) -> Result<()> {
        self.outgoing.extend(
            std::mem::take(&mut self.broadcast.outgoing)
                .into_iter()
                .map(|a| Action {
                    recipient: a.recipient,
                    message: Message::Public(a.message),
                }),
        );
        for event in std::mem::take(&mut self.broadcast.events) {
            match event {
                wrbc::Event::Deliver { data, .. } if self.public.is_none() && !self.invalid => {
                    match Public::decode(&self.setup, &self.context, &data) {
                        Ok(public) => {
                            let mut ra = wra::State::new(
                                self.membership.clone(),
                                self.id,
                                self.instance,
                                public.digest(),
                            )?;
                            for ((sender, _), msg) in std::mem::take(&mut self.pending_completion) {
                                ra.receive(sender, msg);
                            }
                            for (sender, s) in std::mem::take(&mut self.pending_open) {
                                if ax::verify_share(&self.setup, &self.context, &public, &s) {
                                    self.opened.insert(sender, s);
                                }
                            }
                            self.completion = Some(ra);
                            self.public = Some(public);
                        }
                        Err(_) => self.reject_public(),
                    }
                }
                wrbc::Event::Invalid { .. } => self.reject_public(),
                _ => {}
            }
        }
        Ok(())
    }
    fn reject_public(&mut self) {
        if !self.invalid {
            self.invalid = true;
            self.pending_private = None;
            self.pending_completion.clear();
            self.pending_open.clear();
            self.events.push(Event::InvalidPublic);
        }
    }
    fn advance(&mut self) -> Result<()> {
        if let Some(public) = &self.public
            && let Some(s) = self.pending_private.take()
            && ax::verify_share(&self.setup, &self.context, public, &s)
            && self.private.is_none()
        {
            self.private = Some(s);
            // ECHO only after the full public transcript AND authentic private token are held.
            self.completion
                .as_mut()
                .expect("registered with public")
                .input(true)?;
        }
        if let Some(ra) = self.completion.as_mut() {
            self.outgoing.extend(
                std::mem::take(&mut ra.outgoing)
                    .into_iter()
                    .map(|a| Action {
                        recipient: a.recipient,
                        message: Message::Completion(a.message),
                    }),
            );
            for event in std::mem::take(&mut ra.events) {
                if matches!(event, wra::Event::Output { value: true, .. }) && !self.complete {
                    self.complete = true;
                    self.events.push(Event::Shared);
                    log::info!(
                        "wiAwVSS shared party={} dealer={} epoch={}",
                        self.id,
                        self.context.instance().dealer,
                        self.context.instance().epoch
                    );
                }
            }
        }
        if self.complete && self.opening_requested {
            if !self.released
                && let Some(s) = &self.private
            {
                for recipient in 0..self.membership.n() {
                    self.outgoing.push(Action {
                        recipient,
                        message: Message::Open(s.clone()),
                    });
                }
                self.released = true;
            }
            if !self.terminated {
                let shares: Vec<_> = self.opened.values().cloned().collect();
                match ax::reconstruct(
                    &self.setup,
                    &self.context,
                    self.public
                        .as_ref()
                        .expect("completed implies fixed public"),
                    &shares,
                ) {
                    Ok(recovery) => {
                        self.terminated = true;
                        self.events.push(Event::Reconstructed(recovery));
                        log::info!(
                            "wiAwVSS reconstructed party={} dealer={} epoch={}",
                            self.id,
                            self.context.instance().dealer,
                            self.context.instance().epoch
                        );
                    }
                    Err(Error::InsufficientShares) => {}
                    Err(Error::InvalidCommitment) => {
                        self.terminated = true;
                        self.events.push(Event::Bottom);
                        log::info!(
                            "wiAwVSS bottom party={} dealer={} epoch={}",
                            self.id,
                            self.context.instance().dealer,
                            self.context.instance().epoch
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        // Even after output, continue forwarding primitive messages and serve a late local token.
        Ok(())
    }
}

#[cfg(test)]
mod tests;
