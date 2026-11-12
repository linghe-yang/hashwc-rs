//! Shared CPU budget; network reactors never perform large coding jobs directly.
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
pub async fn run<F, R>(work: F) -> anyhow::Result<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let settings = crate::execution::Settings::from_env()?;
    let budget = BUDGET
        .get_or_init(|| Arc::new(Semaphore::new(settings.compute_jobs)))
        .clone();
    let permit = budget.acquire_owned().await?;
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await?)
}
