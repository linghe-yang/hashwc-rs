use crate::{Event, Kind, State};
use anyhow::{ensure, Result};
impl State {
    pub fn authorize(&mut self, retrievers: Vec<usize>) -> Result<()> {
        self.membership
            .weight(retrievers.iter().copied())
            .map_err(anyhow::Error::msg)?;
        // This API adds edges. No authorized edge can be revoked.
        self.retrievers.extend(retrievers);
        self.advance();
        Ok(())
    }
    pub fn retrieve(&mut self) -> Result<()> {
        ensure!(
            self.retrievers.contains(&self.id),
            "local party not authorized to retrieve"
        );
        self.want = true;
        self.advance();
        Ok(())
    }
    pub(crate) fn accept_stream(&mut self, sender: usize, stream: &mut super::stream::DataStream) {
        if !stream.directory_checked {
            let Some(raw) = stream.take(self.codec.directory_bytes()) else {
                return;
            };
            let Some(roots) = self.codec.decode_directory(&raw) else {
                stream.close();
                return;
            };
            if let Some(recovery) = &self.recovery {
                if recovery.roots != roots {
                    stream.close();
                    return;
                }
            } else {
                let Some(root) = self.completed_root else {
                    stream.close();
                    return;
                };
                match super::stream::Recovery::new(&self.codec, root, roots) {
                    Ok(recovery) => self.recovery = Some(recovery),
                    Err(_) => {
                        stream.close();
                        return;
                    }
                }
            }
            stream.directory_checked = true;
        }
        while stream.stripe < self.codec.q {
            let Some(raw) = stream.take(self.codec.stripe_bytes(sender)) else {
                break;
            };
            let z = stream.stripe;
            stream.stripe += 1;
            let recovery = self.recovery.as_mut().unwrap();
            // Already checked the full codeword at this root; late coordinates
            // cannot improve it, and do not recreate released proof state.
            if recovery.done[z] {
                continue;
            }
            let Some(fragments) =
                self.codec
                    .decode_stripe_packet(sender, z, &raw, recovery.roots[z])
            else {
                // An invalid/truncated transport package is not public fault evidence.
                // Earlier independently authenticated stripes remain usable.
                stream.close();
                break;
            };
            for fragment in fragments {
                if self.rows[z].len() == self.codec.k {
                    break;
                }
                self.rows[z].entry(fragment.index()).or_insert(fragment);
            }
            if self.rows[z].len() == self.codec.k {
                let fragments: Vec<_> = std::mem::take(&mut self.rows[z]).into_values().collect();
                match self.codec.recover_verified_stripe(
                    z,
                    recovery.roots[z],
                    &recovery.directory,
                    &fragments,
                ) {
                    Ok(Ok(bytes)) => recovery.store(&self.codec, z, &bytes),
                    Ok(Err(fault)) => {
                        self.finish_retrieval(crate::Retrieval::Invalid(fault));
                        return;
                    }
                    Err(e) => {
                        log::error!("WAVID stripe recovery: {}", e);
                        stream.close();
                        return;
                    }
                }
                if recovery.complete() {
                    let file = self.recovery.take().unwrap().finish(&self.codec);
                    self.finish_retrieval(crate::Retrieval::File(file));
                    return;
                }
            }
        }
    }
    fn finish_retrieval(&mut self, result: crate::Retrieval) {
        self.result = Some(result.clone());
        self.events.push(Event::Result {
            instance: self.instance,
            result,
        });
        self.data_slots.clear();
        self.rows.iter_mut().for_each(|r| r.clear());
        self.recovery = None;
    }
    pub(crate) fn advance_retrieval(&mut self) {
        if self.want && !self.asked {
            if let Some(root) = self.completed_root {
                self.asked = true;
                self.broadcast(Kind::Request(root));
            }
        }
        if let Some(root) = self.completed_root {
            if self.stored_root == Some(root) {
                let peers: Vec<_> = self
                    .requests
                    .iter()
                    .filter(|(peer, r)| {
                        **r == root && self.retrievers.contains(peer) && !self.served.contains(peer)
                    })
                    .map(|(p, _)| *p)
                    .collect();
                if !peers.is_empty() {
                    let raw = self.stored_packet.as_ref().unwrap().clone();
                    for peer in peers {
                        self.served.insert(peer);
                        self.packet(peer, true, &raw);
                    }
                }
            }
        }
        // Never clear stored_packet, authorized edges, or served slots at local output.
    }
}
