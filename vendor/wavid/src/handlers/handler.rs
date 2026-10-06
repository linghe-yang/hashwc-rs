/// Authentication, replay filtering and delivery to Context are shared across weighted protocols.
pub type Handler = util::weighted::Handler<crate::ProtMsg>;
