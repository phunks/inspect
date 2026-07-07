use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::filters::{
    FilterFlow,
    FilterManager,
    FilterRequest,
    FilterRequestView,
    FilterResponse,
    FilterResponseView,
    RequestAction,
    ResponseAction,
};
use crate::filters::runtime_state::RuntimeStateGuard;
use crate::mitm::flow::capture_service::FilterResourceStats;
use crate::mitm::flow::CaptureService;
use crate::mitm::flow::filter_bridge::{
    merge_request_action,
    merge_response_action,
};
use crate::mitm::flow::state_store::{FilterStateStore, StateOpStats};

#[derive(Clone)]
pub(crate) struct FlowFilterRuntime {
    filters: FilterManager,
    capture: CaptureService,
    quarantined_once: Arc<Mutex<HashSet<PathBuf>>>,
    state_store: Option<FilterStateStore>,
}

impl FlowFilterRuntime {
    pub(crate) fn new(
        filters: FilterManager,
        capture: CaptureService,
        state_store: Option<FilterStateStore>,
    ) -> Self {
        Self {
            filters,
            capture,
            quarantined_once: Arc::new(Mutex::new(HashSet::new())),
            state_store,
        }
    }

    pub(crate) fn run_request_filters(
        &self,
        req_view: &FilterRequestView<'_>,
        req: &FilterRequest,
    ) -> RequestAction {
        let filters = self.filters.current();
        let mut matched = 0usize;
        let mut combined = RequestAction::pass();
        let mut needs_reload = false;

        for filter in filters.matching_request(req_view) {
            matched += 1;

            info!(
                filter = filter.name(),
                priority = filter.priority,
                host = req_view.host,
                path = req_view.path,
                method = req_view.method,
                "matched request roto filter"
            );

            let mut resource_stats = self.sweep_state_stats();

            let state_guard = RuntimeStateGuard::enter(
                req.flow_key.clone(),
                filter.name().to_string(),
                self.state_store.clone(),
            );

            let started = Instant::now();
            let result = filter.on_request(req);
            let elapsed = started.elapsed();

            let runtime_state_stats = state_guard.finish();
            resource_stats = resource_stats.merge(runtime_state_stats);

            let mut result_code = if result.is_ok() { 0 } else { 1 };
            if resource_stats.limit_hit {
                result_code = 3;
            }

            if self.is_over_jit_threshold(elapsed) {
                let quarantined = self.quarantine_slow_filter(
                    &filter.definition.path,
                    filter.name(),
                    elapsed,
                    "request",
                );
                needs_reload |= quarantined;
                if quarantined {
                    result_code = 2;
                }
            }

            self.capture.record_filter_exec_stat(
                &req.id,
                req.seq,
                &req.flow_key,
                "request",
                Some(filter.definition.id.as_str()),
                filter.name(),
                elapsed.as_micros() as i64,
                result_code,
                resource_stats,
            );

            match result {
                Ok(action) => {
                    debug!(
                        filter = filter.name(),
                        marks = action.marks.len(),
                        tags = action.tags.len(),
                        notes = action.notes.len(),
                        outbound_http = action.outbound_http.len(),
                        continue_filters = action.continue_filters,
                        synthetic_response = action.synthetic_response.is_some(),
                        request_patch = action.request.is_some(),
                        "request roto filter action"
                    );

                    merge_request_action(&mut combined, action);

                    if !combined.continue_filters {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        filter = filter.name(),
                        error = ?err,
                        "request roto filter failed"
                    );
                }
            }
        }

        if needs_reload {
            self.reload_after_quarantine();
        }

        if matched == 0 {
            info!(
                loaded_filters = filters.len(),
                host = req_view.host,
                path = req_view.path,
                method = req_view.method,
                "no request roto filter matched"
            );
        }

        combined
    }

    pub(crate) fn run_response_filters(
        &self,
        res_view: &FilterResponseView<'_>,
        flow: &FilterFlow,
        res: &FilterResponse,
    ) -> ResponseAction {
        let filters = self.filters.current();
        let mut matched = 0usize;
        let mut combined = ResponseAction::pass();
        let mut needs_reload = false;

        for filter in filters.matching_response(res_view) {
            matched += 1;

            info!(
                filter = filter.name(),
                priority = filter.priority,
                host = res_view.request.host,
                path = res_view.request.path,
                method = res_view.request.method,
                status = res_view.status,
                content_type = res_view.content_type,
                "matched response roto filter"
            );

            let mut resource_stats = self.sweep_state_stats();

            let state_guard = RuntimeStateGuard::enter(
                flow.flow_key.clone(),
                filter.name().to_string(),
                self.state_store.clone(),
            );

            let started = Instant::now();
            let result = filter.on_response(flow, res);
            let elapsed = started.elapsed();

            let runtime_state_stats = state_guard.finish();
            resource_stats = resource_stats.merge(runtime_state_stats);

            let mut result_code = if result.is_ok() { 0 } else { 1 };
            if resource_stats.limit_hit {
                result_code = 3;
            }

            if self.is_over_jit_threshold(elapsed) {
                let quarantined = self.quarantine_slow_filter(
                    &filter.definition.path,
                    filter.name(),
                    elapsed,
                    "response",
                );
                needs_reload |= quarantined;
                if quarantined {
                    result_code = 2;
                }
            }

            self.capture.record_filter_exec_stat(
                &flow.id,
                flow.seq,
                &flow.flow_key,
                "response",
                Some(filter.definition.id.as_str()),
                filter.name(),
                elapsed.as_micros() as i64,
                result_code,
                resource_stats,
            );

            match result {
                Ok(action) => {
                    debug!(
                        filter = filter.name(),
                        marks = action.marks.len(),
                        tags = action.tags.len(),
                        notes = action.notes.len(),
                        outbound_http = action.outbound_http.len(),
                        continue_filters = action.continue_filters,
                        "response roto filter action"
                    );

                    merge_response_action(&mut combined, action);

                    if !combined.continue_filters {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        filter = filter.name(),
                        error = ?err,
                        "response roto filter failed"
                    );
                }
            }
        }

        if needs_reload {
            self.reload_after_quarantine();
        }

        if matched == 0 {
            debug!(
                loaded_filters = filters.len(),
                host = res_view.request.host,
                path = res_view.request.path,
                method = res_view.request.method,
                status = res_view.status,
                content_type = res_view.content_type,
                "no response roto filter matched"
            );
        }

        combined
    }

    pub(crate) fn run_completed_filters(
        &self,
        req_view: &FilterRequestView<'_>,
        flow: &FilterFlow,
    ) {
        let filters = self.filters.current();
        let mut matched = 0usize;
        let mut needs_reload = false;

        for filter in filters.matching_completed(req_view) {
            matched += 1;

            info!(
                filter = filter.name(),
                priority = filter.priority,
                host = req_view.host,
                path = req_view.path,
                method = req_view.method,
                "matched completed roto filter"
            );

            let mut resource_stats = self.sweep_state_stats();

            let state_guard = RuntimeStateGuard::enter(
                flow.flow_key.clone(),
                filter.name().to_string(),
                self.state_store.clone(),
            );

            let started = Instant::now();
            let result = filter.on_completed(flow);
            let elapsed = started.elapsed();

            let runtime_state_stats = state_guard.finish();
            resource_stats = resource_stats.merge(runtime_state_stats);

            let mut result_code = if result.is_ok() { 0 } else { 1 };
            if resource_stats.limit_hit {
                result_code = 3;
            }

            if self.is_over_jit_threshold(elapsed) {
                let quarantined = self.quarantine_slow_filter(
                    &filter.definition.path,
                    filter.name(),
                    elapsed,
                    "completed",
                );
                needs_reload |= quarantined;
                if quarantined {
                    result_code = 2;
                }
            }

            self.capture.record_filter_exec_stat(
                &flow.id,
                flow.seq,
                &flow.flow_key,
                "completed",
                Some(filter.definition.id.as_str()),
                filter.name(),
                elapsed.as_micros() as i64,
                result_code,
                resource_stats,
            );

            match result {
                Ok(action) => {
                    debug!(
                        filter = filter.name(),
                        marks = action.marks.len(),
                        tags = action.tags.len(),
                        notes = action.notes.len(),
                        outbound_http = action.outbound_http.len(),
                        continue_filters = action.continue_filters,
                        "completed roto filter action"
                    );

                    if !action.continue_filters {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        filter = filter.name(),
                        error = ?err,
                        "completed roto filter failed"
                    );
                }
            }
        }

        if needs_reload {
            self.reload_after_quarantine();
        }

        if matched == 0 {
            debug!(
                loaded_filters = filters.len(),
                host = req_view.host,
                path = req_view.path,
                method = req_view.method,
                "no completed roto filter matched"
            );
        }
    }

    fn is_over_jit_threshold(&self, elapsed: Duration) -> bool {
        elapsed > jit_quarantine_threshold()
    }

    fn quarantine_slow_filter(
        &self,
        path: &Path,
        filter_name: &str,
        elapsed: Duration,
        phase: &str,
    ) -> bool {
        let path = path.to_path_buf();

        {
            let mut seen = self.quarantined_once.lock();
            if !seen.insert(path.clone()) {
                return false;
            }
        }

        let reason = format!(
            "roto jit execution too slow: phase={phase}, elapsed_ms={}, threshold_ms={}",
            elapsed.as_millis(),
            jit_quarantine_threshold().as_millis()
        );

        if path.starts_with(&self.capture.paths().generated_filters_dir) {
            match self.capture.paths().quarantine_generated_filter(&path) {
                Ok(destination) => {
                    warn!(
                        filter = filter_name,
                        source = %path.display(),
                        destination = %destination.display(),
                        phase,
                        elapsed_ms = elapsed.as_millis(),
                        threshold_ms = jit_quarantine_threshold().as_millis(),
                        "quarantined slow ephemeral generated roto filter"
                    );
                    return true;
                }
                Err(err) => {
                    warn!(
                        filter = filter_name,
                        source = %path.display(),
                        phase,
                        elapsed_ms = elapsed.as_millis(),
                        threshold_ms = jit_quarantine_threshold().as_millis(),
                        error = ?err,
                        "failed to quarantine slow ephemeral generated roto filter"
                    );
                    return false;
                }
            }
        }

        let persistent_generated_dir = self.filters.filters_dir().join("generated");
        if path.starts_with(&persistent_generated_dir) {
            match self.filters.quarantine_filter_file(&path, &reason) {
                Ok(destination) => {
                    warn!(
                        filter = filter_name,
                        source = %path.display(),
                        destination = %destination.display(),
                        phase,
                        elapsed_ms = elapsed.as_millis(),
                        threshold_ms = jit_quarantine_threshold().as_millis(),
                        "quarantined slow generated roto filter"
                    );
                    return true;
                }
                Err(err) => {
                    warn!(
                        filter = filter_name,
                        source = %path.display(),
                        phase,
                        elapsed_ms = elapsed.as_millis(),
                        threshold_ms = jit_quarantine_threshold().as_millis(),
                        error = ?err,
                        "failed to quarantine slow generated roto filter"
                    );
                    return false;
                }
            }
        }

        warn!(
            filter = filter_name,
            source = %path.display(),
            phase,
            elapsed_ms = elapsed.as_millis(),
            threshold_ms = jit_quarantine_threshold().as_millis(),
            "slow roto filter detected but path is not generated; skip quarantine"
        );

        false
    }

    fn reload_after_quarantine(&self) {
        if let Err(err) = self.filters.reload() {
            warn!(error = ?err, "failed to reload filters after quarantine");
        } else {
            info!("reloaded filters after quarantine");
        }
    }

    fn sweep_state_stats(&self) -> FilterResourceStats {
        let Some(store) = self.state_store.as_ref() else {
            return FilterResourceStats::default();
        };

        let StateOpStats {
            read_bytes,
            write_bytes,
            state_items,
            evicted_items,
            limit_hit,
        } = store.sweep_expired();

        FilterResourceStats {
            state_read_bytes: read_bytes,
            state_write_bytes: write_bytes,
            state_items,
            evicted_items,
            limit_hit,
        }
    }
}

fn jit_quarantine_threshold() -> Duration {
    static THRESHOLD: OnceLock<Duration> = OnceLock::new();

    *THRESHOLD.get_or_init(|| {
        let default_ms = 1000u64;

        let ms = std::env::var("INSPECT_ROTO_JIT_QUARANTINE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default_ms);

        Duration::from_millis(ms)
    })
}