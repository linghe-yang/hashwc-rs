pub mod codec;
pub mod io;

pub const CHANNEL_SIZE: usize = 100_000;
pub mod weighted;

pub mod execution;
pub mod observation;
pub mod profile;
pub mod weighted_actor;
pub mod weighted_compute;

pub mod weighted_work;
