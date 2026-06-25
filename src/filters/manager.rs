use crate::filters::runtime::{
    compile_roto_filter_file,
    CompiledFilter,
    CompiledFilterSet,
    RotoProgram,
};
use crate::filters::types::{FilterDefinition, FilterMetadata};
use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

const DEFAULT_PRIORITY: i32 = 1000;
const FRONT_MATTER_DELIMITER: &str = "+++";
const FILTER_RELOAD_DEBOUNCE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub struct FilterManager {
    filters_dir: PathBuf,
    current: Arc<RwLock<Arc<CompiledFilterSet>>>,
}


impl FilterManager {
    pub fn new(filters_dir: impl Into<PathBuf>) -> Self {
        let filters_dir = filters_dir.into();
        let filters_dir = if filters_dir.is_absolute() {
            filters_dir
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(filters_dir)
        };

        Self {
            filters_dir,
            current: Arc::new(RwLock::new(Arc::new(CompiledFilterSet::empty()))),
        }
    }

    pub fn filters_dir(&self) -> &Path {
        &self.filters_dir
    }

    pub fn current(&self) -> Arc<CompiledFilterSet> {
        self.current.read().clone()
    }

    pub fn reload(&self) -> Result<()> {
        let cwd = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("<unknown>"));

        let filters_dir_absolute = if self.filters_dir.is_absolute() {
            self.filters_dir.clone()
        } else {
            cwd.join(&self.filters_dir)
        };

        let next = self.load_filter_set().context("load filter set")?;
        let count = next.len();

        for filter in next.filters() {
            let (
                program,
                has_on_request,
                has_on_response,
                has_request_action,
                has_response_action,
                has_request_mark,
                has_response_mark,
                has_request_header,
                has_response_header,
                has_request_body,
                has_response_body,
            ) = match &filter.program {
                RotoProgram::MetadataOnly => (
                    "metadata-only",
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                ),
                RotoProgram::Compiled { filter, .. } => (
                    "compiled",
                    filter.has_on_request(),
                    filter.has_on_response(),
                    filter.has_request_action(),
                    filter.has_response_action(),
                    filter.has_request_mark(),
                    filter.has_response_mark(),
                    filter.has_request_header(),
                    filter.has_response_header(),
                    filter.has_request_body(),
                    filter.has_response_body(),
                ),
            };

            info!(
                filters_dir = %self.filters_dir.display(),
                filters_dir_absolute = %filters_dir_absolute.display(),
                cwd = %cwd.display(),
                filter = filter.name(),
                priority = filter.priority,
                path = %filter.definition.path.display(),
                enabled = filter.definition.metadata.enabled,
                program,
                has_on_request,
                has_on_response,
                has_request_action,
                has_response_action,
                has_request_mark,
                has_response_mark,
                has_request_header,
                has_response_header,
                has_request_body,
                has_response_body,
                trigger_host = ?filter.definition.metadata.trigger.host,
                trigger_path = ?filter.definition.metadata.trigger.path,
                trigger_method = ?filter.definition.metadata.trigger.method,
                trigger_phase = ?filter.definition.metadata.trigger.phase,
                "loaded roto filter"
            );
        }

        *self.current.write() = Arc::new(next);

        info!(
            filters_dir = %self.filters_dir.display(),
            filters_dir_absolute = %filters_dir_absolute.display(),
            cwd = %cwd.display(),
            count,
            "reloaded roto filters"
        );

        Ok(())
    }

    pub async fn reload_loop(self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        if let Err(err) = self.reload() {
            warn!(
                filters_dir = %self.filters_dir.display(),
                error = ?err,
                "initial roto filter reload failed"
            );
        }

        if !self.filters_dir.exists() {
            info!(
                filters_dir = %self.filters_dir.display(),
                "filters directory does not exist; watcher disabled"
            );

            let _ = shutdown_rx.changed().await;
            return;
        }

        let mut last_snapshot = match self.snapshot() {
            Ok(snapshot) => snapshot,
            Err(err) => {
                warn!(
                    filters_dir = %self.filters_dir.display(),
                    error = ?err,
                    "failed to snapshot roto filters"
                );
                FilterSnapshot::default()
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    break;
                }
                _ = tokio::time::sleep(FILTER_RELOAD_DEBOUNCE) => {
                    let next_snapshot = match self.snapshot() {
                        Ok(snapshot) => snapshot,
                        Err(err) => {
                            warn!(
                                filters_dir = %self.filters_dir.display(),
                                error = ?err,
                                "failed to snapshot roto filters"
                            );
                            continue;
                        }
                    };

                    if next_snapshot == last_snapshot {
                        continue;
                    }

                    last_snapshot = next_snapshot;

                    if let Err(err) = self.reload() {
                        warn!(
                            filters_dir = %self.filters_dir.display(),
                            error = ?err,
                            "roto filter reload failed; keeping previous filters"
                        );
                    }
                }
            }
        }
    }
    
    fn snapshot(&self) -> Result<FilterSnapshot> {
        FilterSnapshot::read(&self.filters_dir)
    }

    fn load_filter_set(&self) -> Result<CompiledFilterSet> {
        if !self.filters_dir.exists() {
            debug!(
                filters_dir = %self.filters_dir.display(),
                "filters directory does not exist; using empty filter set"
            );

            return Ok(CompiledFilterSet::empty());
        }

        let mut filters = Vec::new();

        for entry in std::fs::read_dir(&self.filters_dir)
            .with_context(|| format!("read filters dir {}", self.filters_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            if !is_roto_file(&path) {
                continue;
            }

            match self.load_filter(&path) {
                Ok(Some(filter)) => filters.push(filter),
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        path = %path.display(),
                        error = ?err,
                        "failed to load roto filter; skipping this file"
                    );
                }
            }
        }

        Ok(CompiledFilterSet::new(filters))
    }

    fn load_filter(&self, path: &Path) -> Result<Option<CompiledFilter>> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("read roto filter {}", path.display()))?;

        let (metadata, script) = parse_filter_source(&source)
            .with_context(|| format!("parse filter metadata {}", path.display()))?;

        if !metadata.enabled {
            debug!(
                path = %path.display(),
                "roto filter disabled"
            );

            return Ok(None);
        }

        let priority = metadata
            .priority
            .unwrap_or_else(|| priority_from_file_name(path).unwrap_or(DEFAULT_PRIORITY));

        let definition = FilterDefinition {
            path: path.to_path_buf(),
            source,
            metadata,
            script,
        };

        Ok(Some(compile_filter_definition(definition, priority)?))
    }
}

fn compile_filter_definition(
    definition: FilterDefinition,
    priority: i32,
) -> Result<CompiledFilter> {
    if !has_executable_roto_script(&definition.script) {
        debug!(
            path = %definition.path.display(),
            priority,
            "loaded metadata-only roto filter"
        );

        return Ok(CompiledFilter::metadata_only(definition, priority));
    }

    let compiled_roto = compile_roto_filter_file(&definition.path)
        .with_context(|| format!("compile roto filter {}", definition.path.display()))?;

    debug!(
        path = %definition.path.display(),
        priority,
        script_len = definition.script.len(),
        has_on_request = compiled_roto.has_on_request(),
        has_on_response = compiled_roto.has_on_response(),
        has_request_mark = compiled_roto.has_request_mark(),
        has_response_mark = compiled_roto.has_response_mark(),
        has_request_header = compiled_roto.has_request_header(),
        has_response_header = compiled_roto.has_response_header(),
        has_request_body = compiled_roto.has_request_body(),
        has_response_body = compiled_roto.has_response_body(),
        "compiled roto filter and ping() returned true"
    );

    Ok(CompiledFilter::compiled(
        definition,
        priority,
        compiled_roto,
    ))
}

fn has_executable_roto_script(script: &str) -> bool {
    script
        .lines()
        .map(str::trim)
        .any(|line| {
            !line.is_empty()
                && !line.starts_with("//")
                && !line.starts_with("/*")
                && !line.starts_with('*')
                && !line.starts_with("*/")
        })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FilterSnapshot {
    files: Vec<FilterSnapshotEntry>,
}

impl FilterSnapshot {
    fn read(filters_dir: &Path) -> Result<Self> {
        if !filters_dir.exists() {
            return Ok(Self::default());
        }

        let mut files = Vec::new();

        for entry in std::fs::read_dir(filters_dir)
            .with_context(|| format!("read filters dir {}", filters_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            if !is_roto_file(&path) {
                continue;
            }

            let metadata = entry
                .metadata()
                .with_context(|| format!("read filter metadata {}", path.display()))?;

            files.push(FilterSnapshotEntry {
                path,
                len: metadata.len(),
                modified: metadata.modified().ok(),
            });
        }

        files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self { files })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FilterSnapshotEntry {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

fn is_roto_file(path: &Path) -> bool {
    path.is_file()
        && path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("roto"))
}

fn priority_from_file_name(path: &Path) -> Option<i32> {
    let file_name = path.file_name()?.to_str()?;
    let prefix = file_name.split_once('-')?.0;

    if prefix.is_empty() || !prefix.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    prefix.parse().ok()
}

fn parse_filter_source(source: &str) -> Result<(FilterMetadata, String)> {
    let mut front_matter_start_byte = None;
    let mut first_non_empty_line = None;

    for (byte_idx, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        first_non_empty_line = Some(line);
        front_matter_start_byte = source
            .lines()
            .take(byte_idx)
            .map(|line| line.len() + 1)
            .sum::<usize>()
            .into();

        break;
    }

    let Some(first_line) = first_non_empty_line else {
        return Ok((FilterMetadata::default(), String::new()));
    };

    if normalized_comment_line(first_line).as_deref() != Some(FRONT_MATTER_DELIMITER) {
        return Ok((FilterMetadata::default(), source.to_string()));
    }

    let start_byte = front_matter_start_byte.unwrap_or(0);
    let source_from_front_matter = &source[start_byte..];
    let mut lines = source_from_front_matter.lines();

    let _ = lines.next();

    let mut toml_text = String::new();
    let mut script = String::new();
    let mut in_front_matter = true;
    let mut found_end = false;

    for line in lines {
        if in_front_matter {
            let normalized = normalized_comment_line(line).unwrap_or_else(|| line.to_string());

            if normalized.trim() == FRONT_MATTER_DELIMITER {
                in_front_matter = false;
                found_end = true;
                continue;
            }

            toml_text.push_str(&normalized);
            toml_text.push('\n');
        } else {
            script.push_str(line);
            script.push('\n');
        }
    }

    if !found_end {
        anyhow::bail!("unterminated filter metadata block");
    }

    let metadata = toml::from_str::<FilterMetadata>(&toml_text)
        .context("parse TOML front matter")?;

    Ok((metadata, script))
}

fn normalized_comment_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();

    trimmed
        .strip_prefix("//!")
        .or_else(|| trimmed.strip_prefix("//"))
        .map(|line| line.trim_start().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::types::{FilterPhase, FilterRequestView};

    #[test]
    fn priority_is_read_from_file_name_prefix() {
        assert_eq!(
            priority_from_file_name(Path::new("000-generic.roto")),
            Some(0),
        );
        assert_eq!(
            priority_from_file_name(Path::new("200-api-example.roto")),
            Some(200),
        );
        assert_eq!(
            priority_from_file_name(Path::new("generic.roto")),
            None,
        );
    }

    #[test]
    fn parse_source_without_front_matter_uses_defaults() {
        let source = "fn on_request() {}\n";
        let (metadata, script) = parse_filter_source(source).unwrap();

        assert!(metadata.enabled);
        assert_eq!(metadata.priority, None);
        assert_eq!(metadata.trigger.host, vec!["*"]);
        assert_eq!(metadata.trigger.path, vec!["*"]);
        assert_eq!(script, source);
    }

    #[test]
    fn parse_source_with_comment_toml_front_matter() {
        let source = r#"//! +++
//! name = "example"
//! enabled = true
//!
//! [trigger]
//! host = ["api.example.com"]
//! path = ["/v1/*"]
//! method = ["GET"]
//! phase = ["request"]
//! +++

fn on_request(req: Request) -> RequestAction {
    RequestAction::pass(req)
}
"#;

        let (metadata, script) = parse_filter_source(source).unwrap();

        assert_eq!(metadata.name.as_deref(), Some("example"));
        assert!(metadata.enabled);
        assert_eq!(metadata.trigger.host, vec!["api.example.com"]);
        assert_eq!(metadata.trigger.path, vec!["/v1/*"]);
        assert_eq!(metadata.trigger.method, vec!["GET"]);
        assert_eq!(metadata.trigger.phase, vec![FilterPhase::Request]);
        assert!(script.contains("fn on_request"));
    }

    #[test]
    fn parse_source_with_plain_comment_toml_front_matter() {
        let source = r#"// +++
// name = "generic"
// enabled = false
// +++

fn on_response() {}
"#;

        let (metadata, script) = parse_filter_source(source).unwrap();

        assert_eq!(metadata.name.as_deref(), Some("generic"));
        assert!(!metadata.enabled);
        assert!(script.contains("fn on_response"));
    }

    #[test]
    fn metadata_priority_overrides_file_name_priority() {
        let source = r#"// +++
// name = "override"
// priority = 42
// +++

fn on_request() {}
"#;

        let (metadata, _script) = parse_filter_source(source).unwrap();

        let priority = metadata
            .priority
            .unwrap_or_else(|| priority_from_file_name(Path::new("100-test.roto")).unwrap());

        assert_eq!(priority, 42);
    }

    #[test]
    fn compiled_filter_set_sorts_by_priority_then_path() {
        let first = CompiledFilter::metadata_only(
            FilterDefinition {
                path: PathBuf::from("b.roto"),
                source: String::new(),
                metadata: FilterMetadata::default(),
                script: String::new(),
            },
            100,
        );

        let second = CompiledFilter::metadata_only(
            FilterDefinition {
                path: PathBuf::from("a.roto"),
                source: String::new(),
                metadata: FilterMetadata::default(),
                script: String::new(),
            },
            0,
        );

        let set = CompiledFilterSet::new(vec![first, second]);

        assert_eq!(set.filters()[0].definition.path, PathBuf::from("a.roto"));
        assert_eq!(set.filters()[1].definition.path, PathBuf::from("b.roto"));
    }

    #[test]
    fn compiled_filter_set_returns_matching_request_filters() {
        let source = r#"// +++
// name = "api"
// [trigger]
// host = ["api.example.com"]
// path = ["/v1/*"]
// method = ["GET"]
// phase = ["request"]
// +++

fn on_request() {}
"#;

        let (metadata, script) = parse_filter_source(source).unwrap();

        let filter = CompiledFilter::compiled(
            FilterDefinition {
                path: PathBuf::from("000-api.roto"),
                source: source.to_string(),
                metadata,
                script,
            },
            0,
            Default::default(),
        );

        let set = CompiledFilterSet::new(vec![filter]);

        let req = FilterRequestView {
            host: "api.example.com",
            path: "/v1/users",
            method: "GET",
        };

        let matched = set.matching_request(&req).collect::<Vec<_>>();

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name(), "api");
    }

    #[test]
    fn executable_script_detection_ignores_comments() {
        assert!(!has_executable_roto_script(""));
        assert!(!has_executable_roto_script("// metadata-only\n// TODO\n"));
        assert!(!has_executable_roto_script("/* block */\n"));
        assert!(!has_executable_roto_script("    // indented comment\n"));

        assert!(has_executable_roto_script("fn ping() -> bool { true }\n"));
    }
}