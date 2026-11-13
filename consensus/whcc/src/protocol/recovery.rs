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
// Count the first accepted outcome per local dealer instance. Joining this with
// terminal_broadcasts records the actual outgoing kind, including relayed proofs.
fn audit_rejection(d: usize, cert: &Certificate, generated: bool) {
    use wiawvss::terminal::Terminal;
    let field = match (&cert.evidence, generated) {
        (Evidence::Semantic { fault: Terminal::RootFault { .. }, .. }, true) => "root_generated",
        (Evidence::Semantic { fault: Terminal::RootFault { .. }, .. }, false) => "root_received",
        (Evidence::Semantic { fault: Terminal::ModuleFault { .. }, .. }, true) => "module_generated",
        (Evidence::Semantic { fault: Terminal::ModuleFault { .. }, .. }, false) => "module_received",
        _ => return,
    };
    sdc_util::observation::bulk_audit::add(d, field, 1);
}

impl State {
    pub fn recovery_packet(&mut self, sender: usize, mut packet: Packet) -> Result<()> {
        let d = packet.dealer;
        if sender >= self.n || d >= self.n || packet.epoch != self.params.epoch {
            return Ok(());
        }
        if self.dealers[d].value.is_some() {
            // The immutable terminal is already known. Late private receipts
            // use their separate handler and must still be served.
            return Ok(());
        }
        match packet.kind {
            RECOVERY_TOKEN => {
                if self.assignments.delivered(self.id) && !self.remote_authorized(self.id, d) {
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
                    self.work.wake(d);
                }
            }
            TERMINAL => {
                let dealer = &mut self.dealers[d];
                if packet.payload.len()
                    > certified::max_evidence_bytes_for_setup(&self.setup, &dealer.codec)
                    || packet.payload.len() < 36
                    || dealer.terminal_seen[sender]
                {
                    return Ok(());
                }
                dealer.terminal_seen[sender] = true;
                dealer
                    .pending_terminals
                    .insert(sender, std::mem::take(&mut packet.payload));
                if self.assignments.delivered(sender) {
                    dealer.ready_terminals.insert(sender);
                    self.work.wake(d);
                } else {
                    self.terminal_waiters[sender].insert(d);
                }
            }
            _ => return Ok(()),
        }
        self.advance()
    }
    /// Release only already-authorized, complete, opened obligations. This cheap
    /// phase must be dispatched before any full candidate verification.
    pub(super) fn release_recovery_tokens(&mut self, d: usize) {
        if self.behavior == crate::Behavior::RecoveryStress || self.coefficients.is_none() {
            return;
        }
        let dealer = &mut self.dealers[d];
        if !dealer.complete {
            return;
        }
        // Receipt may arrive after global completion or even after local coin output.
        if let Some(share) = &dealer.receipt {
            let encoded = share.encode();
            for recipient in std::mem::take(&mut dealer.pending_recipients) {
                debug_assert!(
                    !dealer.served[recipient] && self.assignments.authorized(recipient, d)
                );
                dealer.served[recipient] = true;
                self.actions.push(Action::Recovery {
                    recipient,
                    packet: Packet {
                        epoch: self.params.epoch,
                        dealer: d,
                        kind: RECOVERY_TOKEN,
                        payload: encoded.to_vec(),
                    },
                });
            }
        }
    }

    pub(super) fn recovery(&mut self, d: usize) -> Result<()> {
        if self.behavior == crate::Behavior::RecoveryStress {
            self.adversarial_recovery(d);
            return Ok(());
        }
        if self.coefficients.is_none() {
            return Ok(());
        }
        let bits = self.contribution_bits();
        let reuse_self = self.reuses_local_dealer() && d == self.id;
        let remote = self.remote_authorized(self.id, d);
        let dealer = &mut self.dealers[d];
        if !dealer.complete {
            return Ok(());
        }
        let header = dealer.header.as_ref().expect("completion pins header");
        if reuse_self
            && self.assignments.authorized(self.id, d)
            && dealer.value.is_none()
            && let Some(material) = &self.local_material
            && let Some(cert) =
                material.certificate(&self.setup, &dealer.context, &dealer.codec, header)
        {
            let _profile = sdc_util::profile::span("recovery.local_dealer");
            let Evidence::Success(opening) = &cert.evidence else {
                unreachable!()
            };
            dealer.value = Some(BigUint::from_bytes_be(&opening.message));
            dealer.terminal = Some(cert.encode());
            sdc_util::observation::bulk_audit::add(d, "local_reuse_bytes", material.file().as_ref().len());
            dealer.file = Some(material.file().clone());
            self.events.push(Event::Terminal {
                dealer: d,
                rejected: false,
            });
        }
        let mut checked_terminal = false;
        while !(self.cooperative_recovery && checked_terminal) {
            let Some(sender) = dealer.ready_terminals.pop_first() else {
                break;
            };
            debug_assert!(self.assignments.delivered(sender));
            let raw = dealer.pending_terminals.remove(&sender).unwrap();
            if !self.assignments.authorized(sender, d) || dealer.value.is_some() {
                continue;
            }
            // Authorization and each sender's allowance are checked above.
            // Across senders, identical rejected bytes need only one full check.
            checked_terminal = true;
            let scope = crypto::hash(
                b"coin/recovery-verification/v1",
                &[&header.id(), &bits.to_le_bytes()],
            );
            let audit_start = sdc_util::observation::bulk_audit::enabled().then(std::time::Instant::now);
            let (decoded, accepted) = dealer.rejected_terminals.check(scope, &raw, self.n, || {
                let decoded = Certificate::decode_for_setup(&self.setup, &dealer.codec, &raw);
                let verified = decoded.as_ref().ok().and_then(|cert| {
                    let start = (matches!(&cert.evidence, Evidence::Semantic {
                        fault: wiawvss::terminal::Terminal::ModuleFault { .. }, ..
                    }) && sdc_util::observation::bulk_audit::enabled())
                        .then(std::time::Instant::now);
                    let verified = if let Some(material) = &dealer.material {
                        certified::verify_with_material(
                            &self.setup,
                            &dealer.context,
                            &dealer.codec,
                            header,
                            cert,
                            bits,
                            material,
                        )
                        .map(|v| match v {
                            certified::VerifiedEvidence::Success(file) => Some(file),
                            certified::VerifiedEvidence::Rejection => None,
                        })
                    } else {
                        certified::verify_with_file(
                            &self.setup,
                            &dealer.context,
                            &dealer.codec,
                            header,
                            cert,
                            bits,
                            dealer.file.as_ref(),
                        )
                        .then_some(None)
                    };
                    if let Some(start) = start && verified.is_some() {
                        sdc_util::observation::bulk_audit::add(
                            d, "module_verify_ns", start.elapsed().as_nanos() as usize,
                        );
                    }
                    verified
                });
                (decoded.is_ok(), decoded.ok().zip(verified))
            });
            self.events.push(Event::TerminalChecked {
                dealer: d,
                sender,
                decoded,
                accepted: accepted.is_some(),
            });
            if let Some((cert, file)) = accepted {
                if let Some(t) = audit_start && matches!(&cert.evidence, Evidence::Semantic { fault: wiawvss::terminal::Terminal::RootFault { .. }, .. }) {
                    let ns = t.elapsed().as_nanos() as usize;
                    sdc_util::observation::bulk_audit::add(d, "root_checks", 1);
                    sdc_util::observation::bulk_audit::add(d, "root_check_ns", ns);
                }
                audit_rejection(d, &cert, false);
                if let Some(file) = file {
                    dealer.file = Some(file);
                    self.actions
                        .push(Action::Avid(wavid::Request::PollMaterial {
                            instance: sdc_types::InstanceId::new(self.params.epoch, Some(d), 0),
                        }));
                }
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
        // A continuation performs at most one remote verification or one
        // local reconstruction. An invalid remote candidate cannot indefinitely
        // exclude local recovery: every sender has only one terminal allowance.
        if self.cooperative_recovery && checked_terminal && dealer.value.is_none() {
            if remote && dealer.recovery_dirty {
                self.recovery_work.wake(d);
            }
            return Ok(());
        }
        if remote && dealer.value.is_none() && dealer.recovery_dirty {
            dealer.recovery_dirty = false;
            let audit_start = sdc_util::observation::bulk_audit::enabled().then(std::time::Instant::now);
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
            } else if let Some(cache) = &mut dealer.recovery_cache {
                cache.recover(
                    &self.setup,
                    &dealer.context,
                    &dealer.codec,
                    header,
                    dealer.tokens.values(),
                    bits,
                )?
            } else {
                None
            };
            if let Some(cert) = cert {
                if let Some(t) = audit_start && matches!(&cert.evidence, Evidence::Semantic { fault: wiawvss::terminal::Terminal::RootFault { .. }, .. }) {
                    let ns = t.elapsed().as_nanos() as usize;
                    sdc_util::observation::bulk_audit::add(d, "local_root_certificates", 1);
                    sdc_util::observation::bulk_audit::add(d, "local_root_final_step_ns", ns);
                }
                audit_rejection(d, &cert, true);
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
            sdc_util::observation::bulk_audit::add(d, "terminal_broadcasts", 1);
            sdc_util::observation::bulk_audit::add(d, "certificate_bytes_before_fanout", raw.len());
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
        Ok(())
    }
}
