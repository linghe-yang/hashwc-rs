use super::msg::{Message, Payload, Wire};
use anyhow::{Result, anyhow, ensure};
use config::Node;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
};

pub const MAX_BYTES: usize = 4096;
pub fn seal(payload: Payload, key: &[u8], from_server: bool) -> Result<Wire> {
    ensure!(key.len() == 32, "invalid synchronizer key");
    let tag = crypto::hash(
        b"benchmark/control/v1",
        &[
            key,
            &[u8::from(from_server)],
            &serde_json::to_vec(&payload)?,
        ],
    );
    Ok(Wire { payload, tag })
}
pub fn verify(
    wire: Wire,
    node: &Node,
    epoch: u64,
    party: usize,
    key: &[u8],
    from_server: bool,
) -> Result<Payload> {
    ensure!(
        wire.payload.session == node.session_id
            && wire.payload.epoch == epoch
            && wire.payload.party == party,
        "control context mismatch"
    );
    let expected = seal(wire.payload.clone(), key, from_server)?;
    ensure!(
        crypto::equal(&expected.tag, &wire.tag),
        "invalid control authentication"
    );
    Ok(wire.payload)
}
pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Wire> {
    let len = reader.read_u32_le().await? as usize;
    ensure!(len > 0 && len <= MAX_BYTES, "invalid control frame size");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, wire: &Wire) -> Result<()> {
    let bytes = serde_json::to_vec(wire)?;
    ensure!(bytes.len() <= MAX_BYTES, "control frame too large");
    writer.write_u32_le(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}
pub struct Channel {
    pub input: mpsc::UnboundedReceiver<Result<Message>>,
    pub output: mpsc::UnboundedSender<Message>,
    pub tasks: Vec<JoinHandle<()>>,
}
impl Channel {
    pub fn new(
        stream: TcpStream,
        node: Node,
        epoch: u64,
        party: usize,
        key: Vec<u8>,
        server: bool,
    ) -> Self {
        let (mut reader, mut writer) = stream.into_split();
        let (in_tx, input) = mpsc::unbounded_channel();
        let (output, mut out_rx) = mpsc::unbounded_channel();
        let write_node = node.clone();
        let write_key = key.clone();
        let errors = in_tx.clone();
        let send_task = tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                let result = async {
                    let payload = Payload {
                        session: write_node.session_id,
                        epoch,
                        party,
                        message,
                    };
                    write(&mut writer, &seal(payload, &write_key, server)?).await
                }
                .await;
                if let Err(e) = result {
                    let _ = errors.send(Err(e));
                    break;
                }
            }
        });
        let receive_task = tokio::spawn(async move {
            loop {
                let result = async {
                    let wire = read(&mut reader).await?;
                    Ok(verify(wire, &node, epoch, party, &key, !server)?.message)
                }
                .await;
                let failed = result.is_err();
                if in_tx.send(result).is_err() || failed {
                    break;
                }
            }
        });
        Self {
            input,
            output,
            tasks: vec![send_task, receive_task],
        }
    }
    pub fn send(&self, message: Message) -> Result<()> {
        self.output
            .send(message)
            .map_err(|_| anyhow!("control channel closed"))
    }
    pub async fn recv(&mut self) -> Result<Message> {
        self.input
            .recv()
            .await
            .ok_or_else(|| anyhow!("synchronizer disconnected before STOP"))?
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
