//! AX sharing, wiAwVSS state, and publicly verifiable terminal evidence.
pub mod ax;
pub mod modules;
pub mod terminal;
pub use ax::{Context, Opening, PrivateShare, Public, Recovery};

pub mod blocksize;
pub mod certified;

pub mod view;
pub use view::PublicView;

pub mod incremental;
pub use incremental::IncrementalRecovery;

/// Full-record CSS+AX recovery for the CSS-HashCoin warm-up baseline.
pub mod compact;
