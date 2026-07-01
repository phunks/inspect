use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::filters::generator::GeneratedFilter;
use crate::filters::manager::FilterManager;
use crate::mitm::capture::CapturePaths;

#[derive(Clone, Debug)]
pub struct GeneratedFilterSaveResult {
    pub path: PathBuf,
}

pub fn save_generated_filter_and_reload(
    capture_paths: &CapturePaths,
    filter_manager: &FilterManager,
    filter: &GeneratedFilter,
) -> Result<GeneratedFilterSaveResult> {
    let source = filter.to_roto_source();

    save_generated_roto_source_and_reload(
        capture_paths,
        filter_manager,
        &filter.name,
        &source,
    )
}

pub fn save_generated_roto_source_and_reload(
    capture_paths: &CapturePaths,
    filter_manager: &FilterManager,
    name: &str,
    source: &str,
) -> Result<GeneratedFilterSaveResult> {
    let path = capture_paths
        .write_generated_filter(name, source)
        .with_context(|| format!("write generated roto filter {name:?}"))?;

    if let Err(err) = filter_manager.validate_filter_file(&path) {
        let quarantine_result = capture_paths.quarantine_generated_filter(&path);

        match quarantine_result {
            Ok(quarantined_path) => {
                warn!(
                    path = %path.display(),
                    quarantined_path = %quarantined_path.display(),
                    error = ?err,
                    "generated roto filter validation failed; moved to capture quarantine"
                );

                return Err(err).with_context(|| {
                    format!(
                        "generated roto filter validation failed; quarantined at {}",
                        quarantined_path.display()
                    )
                });
            }
            Err(quarantine_err) => {
                warn!(
                    path = %path.display(),
                    error = ?err,
                    quarantine_error = ?quarantine_err,
                    "generated roto filter validation failed; failed to move to capture quarantine"
                );

                return Err(err).with_context(|| {
                    format!(
                        "generated roto filter validation failed and quarantine failed: {}",
                        quarantine_err
                    )
                });
            }
        }
    }

    if let Err(err) = filter_manager.reload() {
        let quarantine_result = capture_paths.quarantine_generated_filter(&path);

        match quarantine_result {
            Ok(quarantined_path) => {
                warn!(
                    path = %path.display(),
                    quarantined_path = %quarantined_path.display(),
                    error = ?err,
                    "generated roto filter reload failed; moved to capture quarantine"
                );

                return Err(err).with_context(|| {
                    format!(
                        "generated roto filter reload failed; quarantined at {}",
                        quarantined_path.display()
                    )
                });
            }
            Err(quarantine_err) => {
                warn!(
                    path = %path.display(),
                    error = ?err,
                    quarantine_error = ?quarantine_err,
                    "generated roto filter reload failed; failed to move to capture quarantine"
                );

                return Err(err).with_context(|| {
                    format!(
                        "generated roto filter reload failed and quarantine failed: {}",
                        quarantine_err
                    )
                });
            }
        }
    }

    info!(
        path = %path.display(),
        name,
        "saved generated roto filter and reloaded filters"
    );

    Ok(GeneratedFilterSaveResult { path })
}

#[cfg(test)]
mod tests {
    use crate::filters::GeneratedFilterBuilder;

    #[test]
    fn generated_filter_source_can_be_built_before_save() {
        let filter = GeneratedFilterBuilder::response("generated test")
            .status_eq(404)
            .mark("generated-404")
            .set_response_status(200)
            .set_response_body_text("ok\n", "text/plain; charset=utf-8")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(source.contains("res.status() == 404"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".set_body_text(\"ok\\n\", \"text/plain; charset=utf-8\")"));
    }
}