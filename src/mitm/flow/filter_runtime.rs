use tracing::{debug, info};

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
use crate::mitm::flow::filter_bridge::{
    merge_request_action,
    merge_response_action,
};

#[derive(Clone)]
pub(crate) struct FlowFilterRuntime {
    filters: FilterManager,
}

impl FlowFilterRuntime {
    pub(crate) fn new(filters: FilterManager) -> Self {
        Self { filters }
    }

    pub(crate) fn run_request_filters(
        &self,
        req_view: &FilterRequestView<'_>,
        req: &FilterRequest,
    ) -> RequestAction {
        let filters = self.filters.current();
        let mut matched = 0usize;
        let mut combined = RequestAction::pass();

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

            match filter.on_request(req) {
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

            match filter.on_response(flow, res) {
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

            match filter.on_completed(flow) {
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
}