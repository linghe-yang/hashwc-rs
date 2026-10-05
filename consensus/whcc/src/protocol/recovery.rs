use crate::{
    msg::{Action, Event, RECOVERY_TOKEN, TERMINAL},
    state::State,
};
use anyhow::Result;
use network::Packet;
use num_bigint::BigUint;
use wiawvss::{
    PrivateShare,
    certified::{self, Certificate, Evidence},
};
impl State {
    pub fn recovery_packet(&mut self, sender: usize, mut packet: Packet) -> Result<()> {
        let d = packet.dealer;
        if sender >= self.n || d >= self.n || packet.epoch != self.params.epoch {
            return Ok(());
        }
        match packet.kind {
            RECOVERY_TOKEN => {
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
                if let std::collections::btree_map::Entry::Vacant(e) = dealer.tokens.entry(sender) {
                    e.insert(share);
                    dealer.recovery_dirty = true;
                }
            }
            TERMINAL => {
                let dealer = &mut self.dealers[d];
                if packet.payload.len() > certified::max_evidence_bytes(&dealer.codec)
                    || packet.payload.len() < 36
                    || dealer.terminal_seen[sender]
                {
                    return Ok(());
                }
                dealer.terminal_seen[sender] = true;
                dealer
                    .pending_terminals
                    .insert(sender, std::mem::take(&mut packet.payload));
            }
            _ => return Ok(()),
        }
        self.advance()
    }
    pub(super) fn recovery(&mut self) -> Result<()> {
        if self.behavior == crate::Behavior::RecoveryStress {
            self.adversarial_recovery();
            return Ok(());
        }
        if self.coefficients.is_none() {
            return Ok(());
        }
        let bits = self.contribution_bits();
        for d in 0..self.n {
            let dealer = &mut self.dealers[d];
            if !dealer.complete {
                continue;
            }
            let header = dealer.header.as_ref().expect("completion pins header");
            // Receipt may arrive after global completion or even after local coin output.
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
            for sender in dealer.pending_terminals.keys().copied().collect::<Vec<_>>() {
                if !self.assignments.delivered(sender) {
                    continue;
                }
                let raw = dealer.pending_terminals.remove(&sender).unwrap();
                if !self.assignments.authorized(sender, d) || dealer.value.is_some() {
                    continue;
                }
                let decoded = Certificate::decode(&dealer.codec, &raw);
                let valid = decoded.as_ref().is_ok_and(|cert| {
                    certified::verify(
                        &self.setup,
                        &dealer.context,
                        &dealer.codec,
                        header,
                        cert,
                        bits,
                    )
                });
                self.events.push(Event::TerminalChecked {
                    dealer: d,
                    sender,
                    decoded: decoded.is_ok(),
                    accepted: valid,
                });
                if valid {
                    let cert = decoded.unwrap();
                    let (value, rejected) = match cert.evidence {
                        Evidence::Success(o) => (BigUint::from_bytes_be(&o.message), false),
                        _ => (BigUint::from(0u8), true),
                    };
                    dealer.value = Some(value);
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
                let cert = if let Some(cert) = &dealer.storage_terminal {
                    anyhow::ensure!(
                        certified::verify(
                            &self.setup,
                            &dealer.context,
                            &dealer.codec,
                            header,
                            cert,
                            bits
                        ),
                        "invalid local storage terminal"
                    );
                    Some(cert.clone())
                } else if let (Some(public), Some(file)) = (&dealer.public, &dealer.file) {
                    certified::RecoverySource {
                        setup: &self.setup,
                        context: &dealer.context,
                        codec: &dealer.codec,
                        header,
                        public,
                        file,
                    }
                    .recover(dealer.tokens.values(), bits)?
                } else {
                    None
                };
                if let Some(cert) = cert {
                    let (value, rejected) = match &cert.evidence {
                        Evidence::Success(o) => (BigUint::from_bytes_be(&o.message), false),
                        _ => (BigUint::from(0u8), true),
                    };
                    dealer.value = Some(value);
                    dealer.terminal = Some(cert.encode());
                    self.events.push(Event::Terminal {
                        dealer: d,
                        rejected,
                    });
                }
            }
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
