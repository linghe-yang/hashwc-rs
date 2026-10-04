use crypto::Block;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Message {
    Hello { output_bits: u32 },
    Prepare,
    PrepareOk,
    Start,
    Finish { coin: whcc::Coin },
    Stop,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub session: Block,
    pub epoch: u64,
    pub party: usize,
    pub message: Message,
}
#[derive(Serialize, Deserialize)]
pub struct Wire {
    pub payload: Payload,
    pub tag: Block,
}
