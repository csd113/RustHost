//! Preparation and publication of a replacement site snapshot.

use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::{
    config::Config,
    runtime::state::{SharedState, StatusMessage},
    server, Result,
};

const RELOAD_STATUS_DURATION: Duration = Duration::from_secs(3);

/// Prepare and publish one site generation shared by all listeners.
///
/// # Errors
///
/// Preparation failures are reported through logs and status; the active site
/// is preserved. The result remains `Ok(())` so operators can retry without
/// terminating the service.
pub async fn reload_site(
    config: &Config,
    state: SharedState,
    data_dir: PathBuf,
    root_tx: &tokio::sync::watch::Sender<std::sync::Arc<crate::server::SiteSnapshot>>,
) -> Result<()> {
    let previous = Arc::clone(&root_tx.borrow());
    let config = config.clone();
    let prepared =
        tokio::task::spawn_blocking(move || server::SiteSnapshot::prepare(&config, &data_dir))
            .await
            .map_err(|e| e.to_string())
            .and_then(|result| result.map_err(|e| e.to_string()));
    let next = match prepared {
        Ok(next) => next,
        Err(message) => {
            log::warn!("Site reload failed: {message}");
            state.write().await.status_message = Some(StatusMessage::persistent(format!(
                "Reload failed: {message}"
            )));
            return Ok(());
        }
    };
    let mut state = state.write().await;
    // A concurrently completed reload must not be overwritten by older work.
    // Cancellation before this synchronous publication leaves the old site intact.
    let published = root_tx.send_if_modified(|current| {
        if !Arc::ptr_eq(current, &previous) {
            return false;
        }
        *current = Arc::clone(&next);
        true
    });
    if published {
        state.site_file_count = next.file_count;
        state.site_total_bytes = next.total_bytes;
        state.status_message = Some(StatusMessage::temporary(
            format!(
                "Reload complete: {} files, {}",
                next.file_count,
                crate::runtime::state::format_bytes(next.total_bytes)
            ),
            RELOAD_STATUS_DURATION,
        ));
    } else {
        state.status_message = Some(StatusMessage::persistent(
            "Reload superseded by another completed reload",
        ));
    }
    drop(state);
    Ok(())
}
