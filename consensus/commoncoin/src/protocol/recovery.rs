use crate::{
    msg::{Action, Event, RECOVERY_TOKEN, TERMINAL},
    state::State,
};
use anyhow::Result;
use network::Packet;
use num_bigint::BigUint;
use wiawvss::{
    PrivateShare,
    terminal::{self, Terminal},
};
impl State {
    pub fn recovery_packet(&mut self, sender: usize, packet: Packet) -> Result<()> {
        let d = packet.dealer;
        if sender >= self.n || d >= self.n || packet.epoch != self.params.epoch {
            return Ok(());
        }
        match packet.kind {
            RECOVERY_TOKEN => {
                // Early honest packets may precede local declaration/header/freeze deliveries.
                if self.assignments.delivered(self.id) && !self.assignments.authorized(self.id, d) {
                    return Ok(());
                }
                let Ok(share) = PrivateShare::decode(&packet.payload) else {
                    return Ok(());
                };
                let dealer = &mut self.dealers[d];
                if share.party != sender
                    || share.context_id != dealer.context.id()
                    || share.setup_id != self.setup.id()
                {
                    return Ok(());
                }
                if let Some(public) = &dealer.public
                    && !crypto::equal(
                        &crypto::input_commitment(&dealer.context.id(), sender, &share.token),
                        &public.base.inputs[sender],
                    )
                {
                    return Ok(());
                }
                if dealer.tokens.get(&sender) != Some(&share) {
                    dealer.tokens.insert(sender, share);
                    dealer.recovery_dirty = true;
                }
            }
            TERMINAL => {
                let dealer = &mut self.dealers[d];
                if packet.payload.len() > Terminal::MAX_BYTES
                    || packet.payload.len() < 33
                    || dealer.terminal_seen[sender]
                {
                    return Ok(());
                }
                dealer.terminal_seen[sender] = true;
                dealer
                    .pending_terminals
                    .insert(sender, packet.payload.clone());
            }
            _ => return Ok(()),
        }
        self.advance()
    }
    pub(super) fn recovery(&mut self) -> Result<()> {
        // One barrier for the WHOLE vector. No token-dependent terminal is processed earlier.
        if self.coefficients.is_none() {
            return Ok(());
        }
        for d in 0..self.n {
            if !self.dealers[d].complete {
                continue;
            }
            let dealer = &mut self.dealers[d];
            if let Some(share) = &dealer.receipt {
                for recipient in 0..self.n {
                    if !dealer.served[recipient] && self.assignments.authorized(recipient, d) {
                        dealer.served[recipient] = true;
                        self.actions.push(Action::Recovery {
                            recipient,
                            packet: Packet {
                                epoch: self.params.epoch,
                                dealer: d,
                                kind: RECOVERY_TOKEN,
                                payload: share.encode().to_vec(),
                            },
                        });
                    }
                }
            }
            // Invalid senders never occupy another authenticated sender's terminal slot.
            let senders: Vec<_> = dealer.pending_terminals.keys().copied().collect();
            for sender in senders {
                if !self.assignments.delivered(sender) {
                    continue;
                }
                let raw = dealer.pending_terminals.remove(&sender).unwrap();
                if !self.assignments.authorized(sender, d) || dealer.value.is_some() {
                    continue;
                }
                let public = dealer.public.as_ref().expect("completion pins public");
                if let Ok(terminal) = Terminal::decode(public, &raw)
                    && terminal::verify(&self.setup, &dealer.context, public, &terminal)
                {
                    let value = match &terminal {
                        Terminal::Success(o) => BigUint::from_bytes_be(&o.message),
                        _ => BigUint::from(0u8),
                    };
                    let rejected =
                        !matches!(&terminal, Terminal::Success(_)) || value >= self.params.range();
                    dealer.value = Some(if rejected { BigUint::from(0u8) } else { value });
                    dealer.terminal = Some(raw);
                    self.events.push(Event::Terminal {
                        dealer: d,
                        rejected,
                    });
                }
            }
            if self.assignments.authorized(self.id, d)
                && dealer.value.is_none()
                && dealer.recovery_dirty
            {
                dealer.recovery_dirty = false;
                let public = dealer.public.as_ref().unwrap();
                let shares = dealer.tokens.values().cloned().collect::<Vec<_>>();
                match terminal::recover(&self.setup, &dealer.context, public, &shares) {
                    Ok(terminal) => {
                        // All local outcomes pass the very same public verification predicate.
                        anyhow::ensure!(
                            terminal::verify(&self.setup, &dealer.context, public, &terminal),
                            "local terminal verification failed"
                        );
                        let value = match &terminal {
                            Terminal::Success(o) => BigUint::from_bytes_be(&o.message),
                            _ => BigUint::from(0u8),
                        };
                        let rejected = !matches!(&terminal, Terminal::Success(_))
                            || value >= self.params.range();
                        dealer.value = Some(if rejected { BigUint::from(0u8) } else { value });
                        dealer.terminal = Some(terminal.encode(public));
                        self.events.push(Event::Terminal {
                            dealer: d,
                            rejected,
                        });
                    }
                    Err(types::Error::InsufficientShares) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // Late authorization creates a late service obligation, including after coin output.
            if self.assignments.authorized(self.id, d)
                && !dealer.terminal_sent
                && let Some(raw) = &dealer.terminal
            {
                dealer.terminal_sent = true;
                for recipient in 0..self.n {
                    self.actions.push(Action::Recovery {
                        recipient,
                        packet: Packet {
                            epoch: self.params.epoch,
                            dealer: d,
                            kind: TERMINAL,
                            payload: raw.clone(),
                        },
                    });
                }
            }
        }
        Ok(())
    }
}
