use crate::filters::runtime::{
    compile_roto_filter_file,
    CompiledFilter,
    CompiledFilterSet,
    RotoProgram,
};
use crate::filters::types::{
    FilterDefinition,
    FilterMetadata,
    FilterSourceKind,
};
use crate::mitm::store_metadata::{
    FilterStatusMetadata,
    RequestResponseEvent,
};
use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};

const DEFAULT_PRIORITY: i32 = 1000;
const FRONT_MATTER_DELIMITER: &str = "+++";
const FILTER_RELOAD_DEBOUNCE: Duration = Duration::from_millis(250);
const GENERATED_FILTER_ID_PREFIX: &str = "inspect-generated:";


fn stable_hash_hex(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;

    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    format!("{hash:016x}")
}

fn script_hash(source: &str) -> String {
    stable_hash_hex(source)
}

fn is_reserved_generated_id(id: &str) -> bool {
    id.starts_with(GENERATED_FILTER_ID_PREFIX)
}

fn filter_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown.roto")
        .to_string()
}

fn build_filter_id(
    source_kind: FilterSourceKind,
    file_name: &str,
    explicit_id: Option<&str>,
    script_hash: &str,
) -> String {
    let _ = source_kind;
    let _ = script_hash;

    let raw = match explicit_id {
        Some(id) => format!("id\0{id}"),
        None => format!("file\0{file_name}"),
    };

    format!("filter-{}", stable_hash_hex(&raw))
}

#[derive(Clone, Debug)]
pub struct FilterManager {
    filters_dir: PathBuf,
    filter_dirs: Vec<PathBuf>,
    quarantine_dir: PathBuf,
    current: Arc<RwLock<Arc<CompiledFilterSet>>>,
    event_sender: Option<UnboundedSender<RequestResponseEvent>>,
}

#[derive(Clone, Debug)]
struct LoadedFilterSet {
    filters: CompiledFilterSet,
    file_names: Vec<String>,
}


impl FilterManager {
    pub fn new(filters_dir: impl Into<PathBuf>) -> Self {
        let filters_dir = absolute_path(filters_dir.into());
        let quarantine_dir = filters_dir.join("quarantine");

        Self {
            filter_dirs: vec![filters_dir.clone()],
            filters_dir,
            quarantine_dir,
            current: Arc::new(RwLock::new(Arc::new(CompiledFilterSet::empty()))),
            event_sender: None,
        }
    }

    pub fn with_event_sender(
        mut self,
        event_sender: UnboundedSender<RequestResponseEvent>,
    ) -> Self {
        self.event_sender = Some(event_sender);
        self
    }

    pub fn with_filter_dir(mut self, filter_dir: impl Into<PathBuf>) -> Self {
        self.filter_dirs.push(absolute_path(filter_dir.into()));
        self
    }

    pub fn filters_dir(&self) -> &Path {
        &self.filters_dir
    }

    pub fn filter_dirs(&self) -> &[PathBuf] {
        &self.filter_dirs
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    pub fn ensure_quarantine_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.quarantine_dir)
            .with_context(|| format!("create quarantine dir {}", self.quarantine_dir.display()))
    }

    pub fn current(&self) -> Arc<CompiledFilterSet> {
        self.current.read().clone()
    }

    pub fn reload(&self) -> Result<()> {
        self.ensure_quarantine_dir()?;

        let cwd = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("<unknown>"));

        let loaded = self.load_filter_set().context("load filter set")?;
        let next = loaded.filters;
        let count = next.len();

        self.prune_filter_statuses(loaded.file_names);

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
                filter_dirs = ?self.filter_dirs,
                quarantine_dir = %self.quarantine_dir.display(),
                cwd = %cwd.display(),
                filter_id = %filter.definition.id,
                source_kind = filter.definition.source_kind.as_str(),
                file_name = %filter.definition.file_name,
                script_hash = %filter.definition.script_hash,
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
            filter_dirs = ?self.filter_dirs,
            quarantine_dir = %self.quarantine_dir.display(),
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

        if !self.filter_dirs.iter().any(|dir| dir.exists()) {
            info!(
                filters_dir = %self.filters_dir.display(),
                filter_dirs = ?self.filter_dirs,
                "no filters directory exists; watcher disabled"
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
        FilterSnapshot::read_many(&self.filter_dirs)
    }

    fn load_filter_set(&self) -> Result<LoadedFilterSet> {
        let mut filters = Vec::new();
        let mut file_names = Vec::new();

        for filter_dir in &self.filter_dirs {
            if !filter_dir.exists() {
                debug!(
                        filters_dir = %filter_dir.display(),
                        "filters directory does not exist; skipping"
                    );

                continue;
            }

            let source_kind = if filter_dir == &self.filters_dir {
                FilterSourceKind::Persistent
            } else {
                FilterSourceKind::Generated
            };

            for entry in std::fs::read_dir(filter_dir)
                .with_context(|| format!("read filters dir {}", filter_dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();

                if self.is_quarantined_path(&path) {
                    continue;
                }

                if !is_roto_file(&path) {
                    continue;
                }

                file_names.push(filter_file_name(&path));

                match self.load_filter(&path, source_kind) {
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
        }

        file_names.sort();
        file_names.dedup();

        Ok(LoadedFilterSet {
            filters: CompiledFilterSet::new(filters),
            file_names,
        })
    }

    fn prune_filter_statuses(&self, file_names: Vec<String>) {
        let Some(sender) = self.event_sender.as_ref() else {
            warn!(
                    "filter status event sender is not configured"
                );
            return;
        };

        sender
            .send(RequestResponseEvent::FilterStatusPrune { file_names })
            .unwrap_or_else(|err| {
                warn!(
                        error = ?err,
                        "failed to enqueue filter status prune event"
                    );
            });
    }

    fn load_filter(
        &self,
        path: &Path,
        source_kind: FilterSourceKind,
    ) -> Result<Option<CompiledFilter>> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("read roto filter {}", path.display()))?;

        let (metadata, script) = match parse_filter_source(&source) {
            Ok(parsed) => parsed,
            Err(err) => {
                let file_name = filter_file_name(path);
                let script_hash = script_hash(&source);
                let id = build_filter_id(
                    source_kind,
                    &file_name,
                    None,
                    &script_hash,
                );

                let definition = FilterDefinition {
                    id,
                    source_kind,
                    file_name,
                    script_hash,
                    path: path.to_path_buf(),
                    source,
                    metadata: FilterMetadata::default(),
                    script: String::new(),
                };

                self.record_filter_status(filter_status_from_definition(
                    &definition,
                    priority_from_file_name(path).or(Some(DEFAULT_PRIORITY)),
                    false,
                    None,
                    Some(format!("invalid filter header/front matter: {err}")),
                ));

                return Err(err)
                    .with_context(|| format!("parse filter metadata {}", path.display()));
            }
        };

        if source_kind == FilterSourceKind::Persistent
            && metadata
            .id
            .as_deref()
            .is_some_and(is_reserved_generated_id)
        {
            let file_name = filter_file_name(path);
            let script_hash = script_hash(&source);
            let id = build_filter_id(
                source_kind,
                &file_name,
                metadata.id.as_deref(),
                &script_hash,
            );

            let definition = FilterDefinition {
                id,
                source_kind,
                file_name,
                script_hash,
                path: path.to_path_buf(),
                source,
                metadata,
                script,
            };

            self.record_filter_status(filter_status_from_definition(
                &definition,
                None,
                false,
                None,
                Some(format!(
                    "persistent filter cannot use generated filter id prefix `{GENERATED_FILTER_ID_PREFIX}`"
                )),
            ));

            anyhow::bail!(
                "persistent filter cannot use generated filter id prefix `{GENERATED_FILTER_ID_PREFIX}`"
            );
        }

        let priority = metadata
            .priority
            .unwrap_or_else(|| priority_from_file_name(path).unwrap_or(DEFAULT_PRIORITY));

        let file_name = filter_file_name(path);
        let script_hash = script_hash(&source);
        let id = build_filter_id(
            source_kind,
            &file_name,
            metadata.id.as_deref(),
            &script_hash,
        );

        let definition = FilterDefinition {
            id,
            source_kind,
            file_name,
            script_hash,
            path: path.to_path_buf(),
            source,
            metadata,
            script,
        };

        if !definition.metadata.enabled {
            debug!(
                path = %path.display(),
                "roto filter disabled"
            );

            self.record_filter_status(filter_status_from_definition(
                &definition,
                Some(priority),
                true,
                Some("disabled"),
                None,
            ));

            return Ok(None);
        }

        match compile_filter_definition(definition.clone(), priority) {
            Ok(filter) => {
                self.record_filter_status(filter_status_from_definition(
                    &filter.definition,
                    Some(filter.priority),
                    true,
                    Some(program_kind_for_filter(&filter)),
                    None,
                ));

                Ok(Some(filter))
            }
            Err(err) => {
                self.record_filter_status(filter_status_from_definition(
                    &definition,
                    Some(priority),
                    false,
                    None,
                    Some(err.to_string()),
                ));

                Err(err)
            }
        }
    }

    pub fn validate_filter_file(&self, path: &Path) -> Result<()> {
        self.load_filter(path, FilterSourceKind::Persistent)
            .with_context(|| format!("validate roto filter {}", path.display()))?;

        Ok(())
    }

    pub fn quarantine_filter_file(&self, path: &Path, reason: &str) -> Result<PathBuf> {
        self.ensure_quarantine_dir()?;

        let file_name = path
            .file_name()
            .context("quarantine filter path has no file name")?;

        let destination = unique_quarantine_path(&self.quarantine_dir, file_name);

        std::fs::rename(path, &destination)
            .or_else(|_| {
                std::fs::copy(path, &destination)?;
                std::fs::remove_file(path)
            })
            .with_context(|| {
                format!(
                    "move quarantined filter {} to {}",
                    path.display(),
                    destination.display()
                )
            })?;

        warn!(
            source = %path.display(),
            destination = %destination.display(),
            reason,
            "quarantined roto filter"
        );

        Ok(destination)
    }

    fn is_quarantined_path(&self, path: &Path) -> bool {
        path.starts_with(&self.quarantine_dir)
    }

    fn record_filter_status(&self, status: FilterStatusMetadata) {
        let Some(sender) = self.event_sender.as_ref() else {
            warn!(
                filter_id = %status.filter_id,
                filter = %status.name,
                "filter status event sender is not configured"
            );
            return;
        };

        sender
            .send(RequestResponseEvent::FilterStatus(status))
            .unwrap_or_else(|err| {
                warn!(
                    error = ?err,
                    "failed to enqueue filter status event"
                );
            });
    }
}

fn unique_quarantine_path(dir: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let candidate = dir.join(file_name);

    if !candidate.exists() {
        return candidate;
    }

    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("filter");
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("roto");

    for idx in 1.. {
        let candidate = dir.join(format!("{stem}.quarantine-{idx}.{extension}"));

        if !candidate.exists() {
            return candidate;
        }
    }

    unreachable!("unbounded quarantine path search should always find a candidate")
}

fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
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
    fn read_many(filter_dirs: &[PathBuf]) -> Result<Self> {
        let mut files = Vec::new();

        for filter_dir in filter_dirs {
            let snapshot = Self::read(filter_dir)?;
            files.extend(snapshot.files);
        }

        files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self { files })
    }
    
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

            validate_front_matter_line(&normalized)?;

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

fn validate_front_matter_line(line: &str) -> Result<()> {
    let mut in_string = false;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            _ => {}
        }
    }

    if in_string {
        anyhow::bail!("unterminated string in filter metadata line: {line}");
    }

    Ok(())
}

fn loaded_at_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn program_kind_for_filter(filter: &CompiledFilter) -> &'static str {
    match filter.program {
        RotoProgram::MetadataOnly => "metadata-only",
        RotoProgram::Compiled { .. } => "compiled",
    }
}

fn filter_status_from_definition(
    definition: &FilterDefinition,
    priority: Option<i32>,
    valid: bool,
    program_kind: Option<&str>,
    last_error: Option<String>,
) -> FilterStatusMetadata {
    let name = definition
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| {
            definition
                .path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("unnamed")
                .to_string()
        });

    FilterStatusMetadata {
        filter_id: definition.id.clone(),
        source_kind: definition.source_kind.as_str().to_string(),
        file_name: definition.file_name.clone(),
        path: definition.path.to_string_lossy().to_string(),
        explicit_id: definition.metadata.id.clone(),
        name,
        enabled: definition.metadata.enabled,
        valid,
        priority,
        script_hash: definition.script_hash.clone(),
        script_len: definition.script.len() as i64,
        program_kind: program_kind.map(str::to_string),
        last_error,
        loaded_at: loaded_at_now(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::types::{FilterPhase, FilterRequestView, FilterSourceKind};

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
    fn parse_source_rejects_unterminated_front_matter_string() {
        let source = r#"//! +++
//! name = "broken
//!
//! [trigger]
//! host = ["*example.com", "xxxxxxx]
//! +++

fn ping() -> bool {
    true
}
    "#;

        let err = parse_filter_source(source)
            .expect_err("unterminated front matter string should be invalid");

        assert!(
                err.to_string().contains("unterminated string in filter metadata line")
                    || format!("{err:?}").contains("unterminated string in filter metadata line"),
            );
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
                id: "test-b".to_string(),
                source_kind: FilterSourceKind::Persistent,
                file_name: "b.roto".to_string(),
                script_hash: "empty".to_string(),
                path: PathBuf::from("b.roto"),
                source: String::new(),
                metadata: FilterMetadata::default(),
                script: String::new(),
            },
            100,
        );

        let second = CompiledFilter::metadata_only(
            FilterDefinition {
                id: "test-a".to_string(),
                source_kind: FilterSourceKind::Persistent,
                file_name: "a.roto".to_string(),
                script_hash: "empty".to_string(),
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
                id: "test-api".to_string(),
                source_kind: FilterSourceKind::Persistent,
                file_name: "000-api.roto".to_string(),
                script_hash: stable_hash_hex(source),
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