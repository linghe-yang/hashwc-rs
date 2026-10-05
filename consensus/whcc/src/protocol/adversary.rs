//! Bounded research adversary. This is a workload, not a globally worst scheduler.
use crate::{
    State,
    msg::{Action, TERMINAL},
};
use network::Packet;
use wiawvss::{
    Opening, Public,
    certified::{Certificate, Evidence},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Behavior {
    #[default]
    Honest,
    RecoveryStress,
}
impl Behavior {
    pub fn name(self) -> &'static str {
        match self {
            Self::Honest => "honest",
            Self::RecoveryStress => "recovery-stress",
        }
    }
    pub fn corrupt_public(self, public: &mut Public) {
        if self == Self::RecoveryStress {
            // Inputs/wires remain authentic: completion succeeds. The opening is
            // canonical, but full AX regeneration detects the altered commitment.
            public.commitment[0] ^= 1;
        }
    }
}
impl State {
    pub fn adversarial_recovery(&mut self) {
        // Queue fake openings as soon as public data and authorization arrive,
        // before honest freeze/recovery can make verification unnecessary.
        // No secret token is used. Each authorized dealer gets one broadcast.
        for d in 0..self.n {
            let dealer = &mut self.dealers[d];
            if dealer.header.is_none()
                || dealer.terminal_sent
                || !self.assignments.authorized(self.id, d)
            {
                continue;
            }
            let header = dealer.header.as_ref().expect("guarded header");
            let raw = Certificate {
                header_id: header.id(),
                evidence: Evidence::Success(Opening {
                    message: [0; 32],
                    randomness: [0; 32],
                }),
            }
            .encode();
            dealer.terminal_sent = true;
            let mut recipients = 0;
            for recipient in 0..self.n {
                if recipient == self.id {
                    continue;
                }
                self.actions.push(Action::Recovery {
                    recipient,
                    packet: Packet {
                        epoch: self.params.epoch,
                        dealer: d,
                        kind: TERMINAL,
                        payload: raw.clone(),
                    },
                });
                recipients += 1;
            }
            self.events.push(crate::Event::AdversarialTerminal {
                dealer: d,
                recipients,
            });
        }
    }
}
