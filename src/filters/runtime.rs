use crate::filters::roto_api::{
    RotoRequest,
    RotoRequestAction,
    RotoResponse,
    RotoResponseAction,
};
use crate::filters::types::{
    CompletedAction,
    FilterBodyPatch,
    FilterDefinition,
    FilterFlow,
    FilterHeader,
    FilterMark,
    FilterRequest,
    FilterRequestPatch,
    FilterRequestView,
    FilterResponse,
    FilterResponsePatch,
    FilterResponseView,
    OutboundHttpJob,
    RequestAction,
    ResponseAction,
    RotoOnRequestFn,
    RotoOnResponseFn,
    RotoRequestActionFn,
    RotoRequestStringFn,
    RotoResponseActionFn,
    RotoResponseStringFn,
};
use roto::{library, NoCtx, RotoString, Runtime, Val};
use regex::Regex;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crate::filters::{runtime_state, FilterSyntheticResponse};

fn plain_error(err: impl std::fmt::Display) -> String {
    console::strip_ansi_codes(&err.to_string()).into_owned()
}

fn decode_base64_roto_string(value: RotoString, label: &str) -> Option<RotoString> {
    let encoded = value.to_string();

    match STANDARD.decode(encoded.as_bytes()) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(text) => Some(text.into()),
            Err(err) => {
                tracing::warn!(field = label, error = ?err, "invalid UTF-8 in base64 action argument");
                None
            }
        },
        Err(err) => {
            tracing::warn!(field = label, error = ?err, "invalid base64 in action argument");
            None
        }
    }
}

#[derive(Clone, Debug)]
pub enum RotoProgram {
    MetadataOnly,
    Compiled {
        script_len: usize,
        filter: Box<CompiledRotoFilter>,
    },
}

#[derive(Clone, Debug)]
pub struct CompiledFilter {
    pub definition: FilterDefinition,
    pub priority: i32,
    pub program: RotoProgram,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RotoRequestData {
    method: RotoString,
    scheme: RotoString,
    host: RotoString,
    path: RotoString,
    query: RotoString,
    content_type: RotoString,
    body_text: RotoString,
}

impl RotoRequestData {
    fn from_filter_request(req: &FilterRequest) -> Self {
        Self {
            method: req.method.as_str().into(),
            scheme: req.scheme.as_str().into(),
            host: req.host.as_str().into(),
            path: req.path.as_str().into(),
            query: req.query.as_str().into(),
            content_type: req
                .body
                .content_type
                .as_deref()
                .unwrap_or_default()
                .into(),
            body_text: req
                .body
                .text
                .as_deref()
                .unwrap_or_default()
                .into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RotoResponseData {
    status: u16,
    version: RotoString,
    content_type: RotoString,
    body_text: RotoString,
}

impl RotoResponseData {
    fn from_filter_response(res: &FilterResponse) -> Self {
        Self {
            status: res.status,
            version: res.version.as_str().into(),
            content_type: res
                .body
                .content_type
                .as_deref()
                .unwrap_or_default()
                .into(),
            body_text: res
                .body
                .text
                .as_deref()
                .unwrap_or_default()
                .into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum RotoBodyRewriteOp {
    ReplaceTextOnce {
        old: RotoString,
        new: RotoString,
    },
    ReplaceTextAll {
        old: RotoString,
        new: RotoString,
    },
    ReplaceRegex {
        pattern: RotoString,
        replacement: RotoString,
    },
    ReplaceTextWhenContains {
        anchor: RotoString,
        old: RotoString,
        new: RotoString,
    },
    ReplaceJsProperty {
        property: RotoString,
        old: RotoString,
        new: RotoString,
    },
    ReplaceCssDeclaration {
        property: RotoString,
        old: RotoString,
        new: RotoString,
    },
    ReplaceHtmlAttribute {
        selector: RotoString,
        attribute: RotoString,
        old: RotoString,
        new: RotoString,
    },
    ApplyJsonPatch {
        patch_json: RotoString,
        content_type: RotoString,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct AppliedBodyRewrite {
    body: String,
    content_type: Option<String>,
}

fn inspect_roto_runtime() -> anyhow::Result<Runtime<NoCtx>> {
    let lib = library! {
        /// HTTP request metadata exposed to inspect Roto filters.
        #[clone] type Request = Val<RotoRequestData>;

        impl Val<RotoRequestData> {
            fn method(req: Val<RotoRequestData>) -> RotoString {
                req.method.clone()
            }

            fn scheme(req: Val<RotoRequestData>) -> RotoString {
                req.scheme.clone()
            }

            fn host(req: Val<RotoRequestData>) -> RotoString {
                req.host.clone()
            }

            fn path(req: Val<RotoRequestData>) -> RotoString {
                req.path.clone()
            }

            fn query(req: Val<RotoRequestData>) -> RotoString {
                req.query.clone()
            }

            fn content_type(req: Val<RotoRequestData>) -> RotoString {
                req.content_type.clone()
            }

            fn body_text(req: Val<RotoRequestData>) -> RotoString {
                req.body_text.clone()
            }

            fn state_get(_req: Val<RotoRequestData>, key: RotoString) -> RotoString {
                runtime_state::state_get_text(key.as_ref())
                    .unwrap_or_default()
                    .into()
            }

            fn state_put(
                _req: Val<RotoRequestData>,
                key: RotoString,
                value: RotoString,
            ) -> bool {
                runtime_state::state_put_text(key.as_ref(), value.as_ref())
            }

            fn state_delete(_req: Val<RotoRequestData>, key: RotoString) -> bool {
                runtime_state::state_delete(key.as_ref())
            }
        }

        /// HTTP response metadata exposed to inspect Roto filters.
        #[clone] type Response = Val<RotoResponseData>;

        impl Val<RotoResponseData> {
            fn status(res: Val<RotoResponseData>) -> u16 {
                res.status
            }

            fn version(res: Val<RotoResponseData>) -> RotoString {
                res.version.clone()
            }

            fn content_type(res: Val<RotoResponseData>) -> RotoString {
                res.content_type.clone()
            }

            fn body_text(res: Val<RotoResponseData>) -> RotoString {
                res.body_text.clone()
            }

            fn state_get(_res: Val<RotoResponseData>, key: RotoString) -> RotoString {
                runtime_state::state_get_text(key.as_ref())
                    .unwrap_or_default()
                    .into()
            }

            fn state_put(
                _res: Val<RotoResponseData>,
                key: RotoString,
                value: RotoString,
            ) -> bool {
                runtime_state::state_put_text(key.as_ref(), value.as_ref())
            }

            fn state_delete(_res: Val<RotoResponseData>, key: RotoString) -> bool {
                runtime_state::state_delete(key.as_ref())
            }
        }

        /// Action returned from request_action(req).
        #[clone] type RequestAction = Val<RotoRequestActionData>;

        impl Val<RotoRequestActionData> {
            fn pass() -> Val<RotoRequestActionData> {
                Val(RotoRequestActionData::default())
            }

            fn stop(
                mut action: Val<RotoRequestActionData>
            ) -> Val<RotoRequestActionData> {
                action.stop = true;
                action
            }

            fn drop(
                mut action: Val<RotoRequestActionData>
            ) -> Val<RotoRequestActionData> {
                action.stop = true;
                action.drop = true;
                action
            }

            fn mark(
                mut action: Val<RotoRequestActionData>,
                label: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.marks.push(label);
                action
            }

            fn set_header(
                mut action: Val<RotoRequestActionData>,
                name: RotoString,
                value: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.set_headers.push((name, value));
                action
            }

            fn remove_header(
                mut action: Val<RotoRequestActionData>,
                name: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.remove_headers.push(name);
                action
            }

            fn set_body_text(
                mut action: Val<RotoRequestActionData>,
                body: RotoString,
                content_type: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_text = Some(body);

                if !content_type.is_empty() {
                    action.body_content_type = Some(content_type);
                }

                action
            }

            fn replace_body_text(
                mut action: Val<RotoRequestActionData>,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextAll {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_once(
                mut action: Val<RotoRequestActionData>,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextOnce {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_once_b64(
                mut action: Val<RotoRequestActionData>,
                old_b64: RotoString,
                new_b64: RotoString,
            ) -> Val<RotoRequestActionData> {
                let Some(old) = decode_base64_roto_string(old_b64, "old_b64") else {
                    return action;
                };
                let Some(new) = decode_base64_roto_string(new_b64, "new_b64") else {
                    return action;
                };

                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextOnce {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_all(
                mut action: Val<RotoRequestActionData>,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextAll {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_all_b64(
                mut action: Val<RotoRequestActionData>,
                old_b64: RotoString,
                new_b64: RotoString,
            ) -> Val<RotoRequestActionData> {
                let Some(old) = decode_base64_roto_string(old_b64, "old_b64") else {
                    return action;
                };
                let Some(new) = decode_base64_roto_string(new_b64, "new_b64") else {
                    return action;
                };

                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextAll {
                    old,
                    new,
                });
                action
            }

            fn replace_body_regex(
                mut action: Val<RotoRequestActionData>,
                pattern: RotoString,
                replacement: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceRegex {
                    pattern,
                    replacement,
                });
                action
            }

            fn replace_body_text_when_contains(
                mut action: Val<RotoRequestActionData>,
                anchor: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextWhenContains {
                    anchor,
                    old,
                    new,
                });
                action
            }

            fn replace_js_property(
                mut action: Val<RotoRequestActionData>,
                property: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceJsProperty {
                    property,
                    old,
                    new,
                });
                action
            }

            fn replace_css_declaration(
                mut action: Val<RotoRequestActionData>,
                property: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceCssDeclaration {
                    property,
                    old,
                    new,
                });
                action
            }

            fn replace_html_attribute(
                mut action: Val<RotoRequestActionData>,
                selector: RotoString,
                attribute: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceHtmlAttribute {
                    selector,
                    attribute,
                    old,
                    new,
                });
                action
            }

            fn apply_json_patch(
                mut action: Val<RotoRequestActionData>,
                patch_json: RotoString,
                content_type: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ApplyJsonPatch {
                    patch_json,
                    content_type,
                });
                action
            }

            fn synthetic_response(
                mut action: Val<RotoRequestActionData>,
                status: u16,
                body: RotoString,
                content_type: RotoString,
            ) -> Val<RotoRequestActionData> {
                action.synthetic_status = Some(status);
                action.synthetic_body = Some(body);

                if !content_type.is_empty() {
                    action.synthetic_content_type = Some(content_type);
                }

                action.stop = true;
                action
            }
        }

        /// Action returned from response_action(res).
        #[clone] type ResponseAction = Val<RotoResponseActionData>;

        impl Val<RotoResponseActionData> {
            fn pass() -> Val<RotoResponseActionData> {
                Val(RotoResponseActionData::default())
            }

            fn stop(mut action: Val<RotoResponseActionData>) -> Val<RotoResponseActionData> {
                action.stop = true;
                action
            }

            fn drop(
                mut action: Val<RotoResponseActionData>
            ) -> Val<RotoResponseActionData> {
                action.stop = true;
                action.drop = true;
                action
            }

            fn mark(
                mut action: Val<RotoResponseActionData>,
                label: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.marks.push(label);
                action
            }

            fn post_json(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
                body: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::Text {
                        body,
                        content_type: "application/json".into(),
                    },
                });

                action
            }

            fn post_text(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
                body: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::Text {
                        body,
                        content_type: "text/plain; charset=utf-8".into(),
                    },
                });

                action
            }

            fn post_request_raw(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::CapturedRequest,
                });

                action
            }

            fn post_response_raw(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::CapturedResponse,
                });

                action
            }

            fn post_request_json(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::CapturedRequestJson,
                });

                action
            }

            fn post_response_json(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::CapturedResponseJson,
                });

                action
            }

            fn post_flow_json(
                mut action: Val<RotoResponseActionData>,
                client: RotoString,
                path: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.outbound_http.push(RotoOutboundHttpData {
                    client,
                    method: "POST".into(),
                    path,
                    body: RotoOutboundHttpBodyData::CapturedFlowJson,
                });

                action
            }

            fn set_status(
                mut action: Val<RotoResponseActionData>,
                status: u16,
            ) -> Val<RotoResponseActionData> {
                action.status = Some(status);
                action
            }

            fn set_header(
                mut action: Val<RotoResponseActionData>,
                name: RotoString,
                value: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.set_headers.push((name, value));
                action
            }

            fn remove_header(
                mut action: Val<RotoResponseActionData>,
                name: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.remove_headers.push(name);
                action
            }

            fn set_body_text(
                mut action: Val<RotoResponseActionData>,
                body: RotoString,
                content_type: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_text = Some(body);

                if !content_type.is_empty() {
                    action.body_content_type = Some(content_type);
                }

                action
            }

            fn replace_body_text_once(
                mut action: Val<RotoResponseActionData>,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextOnce {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_once_b64(
                mut action: Val<RotoResponseActionData>,
                old_b64: RotoString,
                new_b64: RotoString,
            ) -> Val<RotoResponseActionData> {
                let Some(old) = decode_base64_roto_string(old_b64, "old_b64") else {
                    return action;
                };
                let Some(new) = decode_base64_roto_string(new_b64, "new_b64") else {
                    return action;
                };

                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextOnce {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_all(
                mut action: Val<RotoResponseActionData>,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextAll {
                    old,
                    new,
                });
                action
            }

            fn replace_body_text_all_b64(
                mut action: Val<RotoResponseActionData>,
                old_b64: RotoString,
                new_b64: RotoString,
            ) -> Val<RotoResponseActionData> {
                let Some(old) = decode_base64_roto_string(old_b64, "old_b64") else {
                    return action;
                };
                let Some(new) = decode_base64_roto_string(new_b64, "new_b64") else {
                    return action;
                };

                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextAll {
                    old,
                    new,
                });
                action
            }

            fn replace_body_regex(
                mut action: Val<RotoResponseActionData>,
                pattern: RotoString,
                replacement: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceRegex {
                    pattern,
                    replacement,
                });
                action
            }

            fn replace_body_text_when_contains(
                mut action: Val<RotoResponseActionData>,
                anchor: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceTextWhenContains {
                    anchor,
                    old,
                    new,
                });
                action
            }

            fn replace_js_property(
                mut action: Val<RotoResponseActionData>,
                property: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceJsProperty {
                    property,
                    old,
                    new,
                });
                action
            }

            fn replace_css_declaration(
                mut action: Val<RotoResponseActionData>,
                property: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceCssDeclaration {
                    property,
                    old,
                    new,
                });
                action
            }

            fn replace_html_attribute(
                mut action: Val<RotoResponseActionData>,
                selector: RotoString,
                attribute: RotoString,
                old: RotoString,
                new: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ReplaceHtmlAttribute {
                    selector,
                    attribute,
                    old,
                    new,
                });
                action
            }

            fn apply_json_patch(
                mut action: Val<RotoResponseActionData>,
                patch_json: RotoString,
                content_type: RotoString,
            ) -> Val<RotoResponseActionData> {
                action.body_rewrite_ops.push(RotoBodyRewriteOp::ApplyJsonPatch {
                    patch_json,
                    content_type,
                });
                action
            }
        }
    };

    Runtime::<NoCtx>::from_lib(lib).map_err(|err| anyhow::anyhow!("{err}"))
}

fn non_empty_roto_string(value: RotoString) -> Option<String> {
    let value = value.trim().to_string();

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

impl CompiledFilter {
    pub fn metadata_only(definition: FilterDefinition, priority: i32) -> Self {
        Self {
            definition,
            priority,
            program: RotoProgram::MetadataOnly,
        }
    }

    pub fn compiled(
        definition: FilterDefinition,
        priority: i32,
        filter: CompiledRotoFilter,
    ) -> Self {
        let script_len = definition.script.len();

        Self {
            definition,
            priority,
            program: RotoProgram::Compiled {
                script_len,
                filter: Box::new(filter),
            },
        }
    }

    pub fn name(&self) -> &str {
        self.definition
            .metadata
            .name
            .as_deref()
            .unwrap_or_else(|| {
                self.definition
                    .path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unnamed")
            })
    }

    pub fn matches_request(&self, req: &FilterRequestView<'_>) -> bool {
        self.definition.metadata.trigger.matches_request(req)
    }

    pub fn matches_response(&self, res: &FilterResponseView<'_>) -> bool {
        self.definition.metadata.trigger.matches_response(res)
    }

    pub fn matches_completed(&self, req: &FilterRequestView<'_>) -> bool {
        self.definition.metadata.trigger.matches_completed(req)
    }

    pub fn on_request(&self, req: &FilterRequest) -> anyhow::Result<RequestAction> {
        let req_view = RotoRequest::new(req.clone());

        match &self.program {
            RotoProgram::MetadataOnly => {
                let action = RotoRequestAction::pass()
                    .set_header("x-inspect-request-filter", self.name())
                    .mark_color(self.name(), "green");

                tracing::debug!(
                filter = self.name(),
                method = req_view.method(),
                host = req_view.host(),
                path = req_view.path(),
                "executed metadata-only request filter stub"
            );

                Ok(action.into_inner())
            }
            RotoProgram::Compiled { filter, .. } => {
                let req_data = RotoRequestData::from_filter_request(req);

                if let Some(request_action) = filter.request_action.as_ref() {
                    let action = request_action
                        .call(Val(req_data.clone()))
                        .0
                        .into_request_action(req.body.text.as_deref());

                    tracing::info!(
                    filter = self.name(),
                    method = req_view.method(),
                    host = req_view.host(),
                    path = req_view.path(),
                    marks = action.marks.len(),
                    request_patch = action.request.is_some(),
                    synthetic_response = action.synthetic_response.is_some(),
                    continue_filters = action.continue_filters,
                    "executed roto request_action"
                );

                    return Ok(action);
                }

                let Some(on_request) = filter.on_request.as_ref() else {
                    tracing::debug!(
                    filter = self.name(),
                    method = req_view.method(),
                    host = req_view.host(),
                    path = req_view.path(),
                    "compiled roto filter has no on_request; no-op"
                );

                    return Ok(RequestAction::pass());
                };

                if !on_request.call(Val(req_data.clone())) {
                    tracing::debug!(
                    filter = self.name(),
                    method = req_view.method(),
                    host = req_view.host(),
                    path = req_view.path(),
                    "roto on_request returned false"
                );

                    return Ok(RequestAction::pass());
                }

                let label = filter
                    .request_mark
                    .as_ref()
                    .and_then(|function| non_empty_roto_string(function.call(Val(req_data.clone()))))
                    .unwrap_or_else(|| format!("roto:{}", self.name()));

                let mut action = RotoRequestAction::pass()
                    .set_header("x-inspect-roto-request-filter", self.name())
                    .mark_color(label, "green");

                if let (Some(name_fn), Some(value_fn)) = (
                    filter.request_header_name.as_ref(),
                    filter.request_header_value.as_ref(),
                ) && let Some(name) = non_empty_roto_string(name_fn.call(Val(req_data.clone()))) {
                        let value = value_fn.call(Val(req_data.clone())).to_string();
                        action = action.set_header(name, value);
                }

                if let Some(body_fn) = filter.request_body.as_ref() {
                    let body = body_fn.call(Val(req_data.clone())).to_string();

                    let content_type = filter
                        .request_body_content_type
                        .as_ref()
                        .and_then(|function| non_empty_roto_string(function.call(Val(req_data))));

                    action = action.set_body_text(body, content_type);
                }

                tracing::info!(
                    filter = self.name(),
                    method = req_view.method(),
                    host = req_view.host(),
                    path = req_view.path(),
                    "roto on_request returned true"
                );

                Ok(action.into_inner())
            }
        }
    }

    pub fn on_response(
        &self,
        _flow: &FilterFlow,
        res: &FilterResponse,
    ) -> anyhow::Result<ResponseAction> {
        let res_view = RotoResponse::new(res.clone());

        match &self.program {
            RotoProgram::MetadataOnly => {
                let action = RotoResponseAction::pass()
                    .set_header("x-inspect-filter", self.name())
                    .mark_color(format!("filtered:{}", self.name()), "green");

                tracing::debug!(
                filter = self.name(),
                status = res_view.status(),
                content_type = res_view.content_type(),
                "executed metadata-only response filter stub"
            );

                Ok(action.into_inner())
            }
            RotoProgram::Compiled { filter, .. } => {
                let res_data = RotoResponseData::from_filter_response(res);

                if let Some(response_action) = filter.response_action.as_ref() {
                    let action = response_action
                        .call(Val(res_data.clone()))
                        .0
                        .into_response_action(res.body.text.as_deref());

                    tracing::info!(
                        filter = self.name(),
                        status = res_view.status(),
                        content_type = res_view.content_type(),
                        marks = action.marks.len(),
                        response_patch = action.response.is_some(),
                        continue_filters = action.continue_filters,
                        "executed roto response_action"
                    );

                    return Ok(action);
                }

                let Some(on_response) = filter.on_response.as_ref() else {
                    tracing::debug!(
                        filter = self.name(),
                        status = res_view.status(),
                        content_type = res_view.content_type(),
                        "compiled roto filter has no on_response; no-op"
                    );

                    return Ok(ResponseAction::pass());
                };

                if !on_response.call(Val(res_data.clone())) {
                    tracing::debug!(
                        filter = self.name(),
                        status = res_view.status(),
                        content_type = res_view.content_type(),
                        "roto on_response returned false"
                    );

                    return Ok(ResponseAction::pass());
                }

                let label = filter
                    .response_mark
                    .as_ref()
                    .and_then(|function| non_empty_roto_string(function.call(Val(res_data.clone()))))
                    .unwrap_or_else(|| format!("roto-res:{}", self.name()));

                let mut action = RotoResponseAction::pass()
                    .set_header("x-inspect-roto-response-filter", self.name())
                    .mark_color(label, "green");

                if let (Some(name_fn), Some(value_fn)) = (
                    filter.response_header_name.as_ref(),
                    filter.response_header_value.as_ref(),
                ) && let Some(name) = non_empty_roto_string(name_fn.call(Val(res_data.clone()))) {
                        let value = value_fn.call(Val(res_data.clone())).to_string();
                        action = action.set_header(name, value);
                }

                if let Some(body_fn) = filter.response_body.as_ref() {
                    let body = body_fn.call(Val(res_data.clone())).to_string();

                    let content_type = filter
                        .response_body_content_type
                        .as_ref()
                        .and_then(|function| non_empty_roto_string(function.call(Val(res_data))));

                    action = action.set_body_text(body, content_type);
                }

                tracing::info!(
                filter = self.name(),
                status = res_view.status(),
                content_type = res_view.content_type(),
                "roto on_response returned true"
            );

                Ok(action.into_inner())
            }
        }
    }

    pub fn on_completed(&self, _flow: &FilterFlow) -> anyhow::Result<CompletedAction> {
        Ok(CompletedAction::pass())
    }
}

#[derive(Clone, Debug, Default)]
pub struct CompiledFilterSet {
    filters: Vec<CompiledFilter>,
}

impl CompiledFilterSet {
    pub fn new(mut filters: Vec<CompiledFilter>) -> Self {
        filters.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.definition.path.cmp(&b.definition.path))
        });

        Self { filters }
    }

    pub fn empty() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.filters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    pub fn filters(&self) -> &[CompiledFilter] {
        &self.filters
    }

    pub fn matching_request<'a>(
        &'a self,
        req: &'a FilterRequestView<'_>,
    ) -> impl Iterator<Item = &'a CompiledFilter> + 'a {
        self.filters
            .iter()
            .filter(move |filter| filter.matches_request(req))
    }

    pub fn matching_response<'a>(
        &'a self,
        res: &'a FilterResponseView<'_>,
    ) -> impl Iterator<Item = &'a CompiledFilter> + 'a {
        self.filters
            .iter()
            .filter(move |filter| filter.matches_response(res))
    }

    pub fn matching_completed<'a>(
        &'a self,
        req: &'a FilterRequestView<'_>,
    ) -> impl Iterator<Item = &'a CompiledFilter> + 'a {
        self.filters
            .iter()
            .filter(move |filter| filter.matches_completed(req))
    }
}

#[derive(Clone, Debug)]
pub struct RotoCompileInfo {
    pub has_on_request: bool,
    pub has_on_response: bool,
    pub has_request_mark: bool,
    pub has_response_mark: bool,
    pub has_request_header: bool,
    pub has_response_header: bool,
    pub has_request_body: bool,
    pub has_response_body: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CompiledRotoFilter {
    pub on_request: Option<RotoOnRequestFn>,
    pub on_response: Option<RotoOnResponseFn>,
    pub request_action: Option<RotoRequestActionFn>,
    pub response_action: Option<RotoResponseActionFn>,
    pub request_mark: Option<RotoRequestStringFn>,
    pub response_mark: Option<RotoResponseStringFn>,
    pub request_header_name: Option<RotoRequestStringFn>,
    pub request_header_value: Option<RotoRequestStringFn>,
    pub response_header_name: Option<RotoResponseStringFn>,
    pub response_header_value: Option<RotoResponseStringFn>,
    pub request_body: Option<RotoRequestStringFn>,
    pub request_body_content_type: Option<RotoRequestStringFn>,
    pub response_body: Option<RotoResponseStringFn>,
    pub response_body_content_type: Option<RotoResponseStringFn>,
}

impl CompiledRotoFilter {
    pub fn has_on_request(&self) -> bool {
        self.on_request.is_some()
    }

    pub fn has_on_response(&self) -> bool {
        self.on_response.is_some()
    }

    pub fn has_request_action(&self) -> bool {
        self.request_action.is_some()
    }

    pub fn has_response_action(&self) -> bool {
        self.response_action.is_some()
    }

    pub fn has_request_mark(&self) -> bool {
        self.request_mark.is_some()
    }

    pub fn has_response_mark(&self) -> bool {
        self.response_mark.is_some()
    }

    pub fn has_request_header(&self) -> bool {
        self.request_header_name.is_some() && self.request_header_value.is_some()
    }

    pub fn has_response_header(&self) -> bool {
        self.response_header_name.is_some() && self.response_header_value.is_some()
    }

    pub fn has_request_body(&self) -> bool {
        self.request_body.is_some()
    }

    pub fn has_response_body(&self) -> bool {
        self.response_body.is_some()
    }
}


pub fn compile_roto_filter_file(path: &std::path::Path) -> anyhow::Result<CompiledRotoFilter> {
    let runtime = inspect_roto_runtime()?;

    let mut package = runtime
        .compile(path)
        .map_err(|err| anyhow::anyhow!("{}", plain_error(err)))?;

    let ping = package
        .get_function::<fn() -> bool>("ping")
        .map_err(|err| anyhow::anyhow!("{}", plain_error(err)))
        .map_err(|err| {
            anyhow::anyhow!(
                "compiled roto filter must export `fn ping() -> bool`: {}: {err}",
                path.display()
            )
        })?;

    if !ping.call() {
        anyhow::bail!("roto filter ping() returned false: {}", path.display());
    }

    Ok(CompiledRotoFilter {
        on_request: package
            .get_function::<fn(Val<RotoRequestData>) -> bool>(
                "on_request")
            .ok(),
        on_response: package
            .get_function::<fn(Val<RotoResponseData>) -> bool>(
                "on_response")
            .ok(),
        request_action: package
            .get_function::<fn(Val<RotoRequestData>) -> Val<RotoRequestActionData>>(
                "request_action", )
            .ok(),
        response_action: package
            .get_function::<fn(Val<RotoResponseData>) -> Val<RotoResponseActionData>>(
                "response_action", )
            .ok(),
        request_mark: package
            .get_function::<fn(Val<RotoRequestData>) -> RotoString>(
                "request_mark")
            .ok(),
        response_mark: package
            .get_function::<fn(Val<RotoResponseData>) -> RotoString>(
                "response_mark")
            .ok(),
        request_header_name: package
            .get_function::<fn(Val<RotoRequestData>) -> RotoString>(
                "request_header_name")
            .ok(),
        request_header_value: package
            .get_function::<fn(Val<RotoRequestData>) -> RotoString>(
                "request_header_value")
            .ok(),
        response_header_name: package
            .get_function::<fn(Val<RotoResponseData>) -> RotoString>(
                "response_header_name")
            .ok(),
        response_header_value: package
            .get_function::<fn(Val<RotoResponseData>) -> RotoString>(
                "response_header_value")
            .ok(),
        request_body: package
            .get_function::<fn(Val<RotoRequestData>) -> RotoString>(
                "request_body")
            .ok(),
        request_body_content_type: package
            .get_function::<fn(Val<RotoRequestData>) -> RotoString>(
                "request_body_content_type", )
            .ok(),
        response_body: package
            .get_function::<fn(Val<RotoResponseData>) -> RotoString>(
                "response_body")
            .ok(),
        response_body_content_type: package
            .get_function::<fn(Val<RotoResponseData>) -> RotoString>(
                "response_body_content_type",
            )
            .ok(),
    })
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct RotoRequestActionData {
    set_headers: Vec<(RotoString, RotoString)>,
    remove_headers: Vec<RotoString>,
    marks: Vec<RotoString>,
    body_text: Option<RotoString>,
    body_content_type: Option<RotoString>,
    body_rewrite_ops: Vec<RotoBodyRewriteOp>,
    synthetic_status: Option<u16>,
    synthetic_body: Option<RotoString>,
    synthetic_content_type: Option<RotoString>,
    stop: bool,
    drop: bool,
}


impl RotoRequestActionData {
    fn into_request_action(self, original_body_text: Option<&str>) -> RequestAction {
        let mut action = RequestAction::pass();

        action.continue_filters = !self.stop;
        action.drop_client_response = self.drop;

        if let Some(status) = self.synthetic_status {
            let mut headers = Vec::new();

            if let Some(content_type) = self.synthetic_content_type {
                let content_type = content_type.to_string();
                if !content_type.trim().is_empty() {
                    headers.push(FilterHeader {
                        name: "content-type".to_string(),
                        value: content_type,
                    });
                }
            }

            action.synthetic_response = Some(FilterSyntheticResponse {
                status,
                headers,
                body: self
                    .synthetic_body
                    .map(|body| body.to_string().into_bytes())
                    .unwrap_or_default(),
            });

            action.continue_filters = false;
        }

        let rewritten_body_text = apply_body_rewrite_ops(
            original_body_text,
            &self.body_rewrite_ops,
        );

        if !self.set_headers.is_empty()
            || !self.remove_headers.is_empty()
            || self.body_text.is_some()
            || rewritten_body_text.is_some()
        {
            let mut patch = FilterRequestPatch { set_headers: self
                .set_headers
                .into_iter()
                .map(|(name, value)| FilterHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                })
                .collect(),
                remove_headers: self
                    .remove_headers
                    .into_iter()
                    .map(|name| name.to_string())
                    .collect(), ..Default::default()
            };

            if let Some(body_text) = self.body_text {
                patch.body = Some(FilterBodyPatch {
                    bytes: body_text.to_string().into_bytes(),
                    content_type: self.body_content_type.map(|value| value.to_string()),
                });
            } else if let Some(rewrite) = rewritten_body_text {
                patch.body = Some(FilterBodyPatch {
                    bytes: rewrite.body.into_bytes(),
                    content_type: rewrite
                        .content_type
                        .or_else(|| self.body_content_type.map(|value| value.to_string())),
                });
            }

            action.request = Some(patch);
        }

        action.marks = self
            .marks
            .into_iter()
            .map(|label| FilterMark {
                label: label.to_string(),
                color: Some("green".to_string()),
            })
            .collect();

        action
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct RotoResponseActionData {
    status: Option<u16>,
    set_headers: Vec<(RotoString, RotoString)>,
    remove_headers: Vec<RotoString>,
    marks: Vec<RotoString>,
    body_text: Option<RotoString>,
    body_content_type: Option<RotoString>,
    body_rewrite_ops: Vec<RotoBodyRewriteOp>,
    outbound_http: Vec<RotoOutboundHttpData>,
    stop: bool,
    drop: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RotoOutboundHttpData {
    client: RotoString,
    method: RotoString,
    path: RotoString,
    body: RotoOutboundHttpBodyData,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RotoOutboundHttpBodyData {
    Text {
        body: RotoString,
        content_type: RotoString,
    },
    CapturedRequest,
    CapturedResponse,
    CapturedRequestJson,
    CapturedResponseJson,
    CapturedFlowJson,
}

impl RotoResponseActionData {
    fn into_response_action(self, original_body_text: Option<&str>) -> ResponseAction {
        let mut action = ResponseAction::pass();

        action.continue_filters = !self.stop;
        action.drop_client_response = self.drop;

        let rewritten_body_text = apply_body_rewrite_ops(
            original_body_text,
            &self.body_rewrite_ops,
        );

        if self.status.is_some()
            || !self.set_headers.is_empty()
            || !self.remove_headers.is_empty()
            || self.body_text.is_some()
            || rewritten_body_text.is_some()
        {
            let mut patch = FilterResponsePatch {
                status: self.status,
                set_headers: self
                    .set_headers
                    .into_iter()
                    .map(|(name, value)| FilterHeader {
                        name: name.to_string(),
                        value: value.to_string(),
                    })
                    .collect(),
                remove_headers: self
                    .remove_headers
                    .into_iter()
                    .map(|name| name.to_string())
                    .collect(),
                ..Default::default()
            };

            if let Some(body_text) = self.body_text {
                patch.body = Some(FilterBodyPatch {
                    bytes: body_text.to_string().into_bytes(),
                    content_type: self.body_content_type.map(|value| value.to_string()),
                });
            } else if let Some(rewrite) = rewritten_body_text {
                patch.body = Some(FilterBodyPatch {
                    bytes: rewrite.body.into_bytes(),
                    content_type: rewrite
                        .content_type
                        .or_else(|| self.body_content_type.map(|value| value.to_string())),
                });
            }

            action.response = Some(patch);
        }

        action.marks = self
            .marks
            .into_iter()
            .map(|label| FilterMark {
                label: label.to_string(),
                color: Some("green".to_string()),
            })
            .collect();

        action.outbound_http = self
            .outbound_http
            .into_iter()
            .map(|job| {
                let (headers, body) = match job.body {
                    RotoOutboundHttpBodyData::Text { body, content_type } => (
                        vec![FilterHeader {
                            name: "content-type".to_string(),
                            value: content_type.to_string(),
                        }],
                        crate::filters::types::OutboundHttpBodySource::Bytes(
                            body.to_string().into_bytes(),
                        ),
                    ),
                    RotoOutboundHttpBodyData::CapturedRequest => (
                        vec![FilterHeader {
                            name: "content-type".to_string(),
                            value: "application/octet-stream".to_string(),
                        }],
                        crate::filters::types::OutboundHttpBodySource::CapturedRequest,
                    ),
                    RotoOutboundHttpBodyData::CapturedResponse => (
                        vec![FilterHeader {
                            name: "content-type".to_string(),
                            value: "application/octet-stream".to_string(),
                        }],
                        crate::filters::types::OutboundHttpBodySource::CapturedResponse,
                    ),
                    RotoOutboundHttpBodyData::CapturedRequestJson => (
                        vec![FilterHeader {
                            name: "content-type".to_string(),
                            value: "application/json".to_string(),
                        }],
                        crate::filters::types::OutboundHttpBodySource::CapturedRequestJson,
                    ),
                    RotoOutboundHttpBodyData::CapturedResponseJson => (
                        vec![FilterHeader {
                            name: "content-type".to_string(),
                            value: "application/json".to_string(),
                        }],
                        crate::filters::types::OutboundHttpBodySource::CapturedResponseJson,
                    ),
                    RotoOutboundHttpBodyData::CapturedFlowJson => (
                        vec![FilterHeader {
                            name: "content-type".to_string(),
                            value: "application/json".to_string(),
                        }],
                        crate::filters::types::OutboundHttpBodySource::CapturedFlowJson,
                    ),
                };

                OutboundHttpJob {
                    client: job.client.to_string(),
                    method: job.method.to_string(),
                    path: job.path.to_string(),
                    headers,
                    body,
                }
            })
            .collect();

        action
    }
}

fn apply_body_rewrite_ops(
    original_body_text: Option<&str>,
    ops: &[RotoBodyRewriteOp],
) -> Option<AppliedBodyRewrite> {
    if ops.is_empty() {
        return None;
    }

    let mut body = original_body_text?.to_string();
    let mut content_type = None;
    let mut changed = false;

    for op in ops {
        match op {
            RotoBodyRewriteOp::ReplaceTextOnce { old, new } => {
                let old = old.to_string();

                if old.is_empty() || !body.contains(&old) {
                    continue;
                }

                body = body.replacen(&old, new.as_ref(), 1);
                changed = true;
            }
            RotoBodyRewriteOp::ReplaceTextAll { old, new } => {
                let old = old.to_string();

                if old.is_empty() || !body.contains(&old) {
                    continue;
                }

                body = body.replace(&old, new.as_ref());
                changed = true;
            }
            RotoBodyRewriteOp::ReplaceRegex {
                pattern,
                replacement,
            } => {
                let pattern = pattern.to_string();
                let Ok(regex) = Regex::new(&pattern) else {
                    tracing::warn!(
                            pattern,
                            "invalid replace_body_regex pattern in roto filter action"
                        );
                    continue;
                };

                let next = regex
                    .replace_all(&body, replacement.to_string().as_str())
                    .to_string();

                if next != body {
                    body = next;
                    changed = true;
                }
            }
            RotoBodyRewriteOp::ReplaceTextWhenContains { anchor, old, new } => {
                let anchor = anchor.to_string();
                let old = old.to_string();

                if anchor.is_empty()
                    || old.is_empty()
                    || !body.contains(&anchor)
                    || !body.contains(&old)
                {
                    continue;
                }

                body = body.replacen(&old, new.as_ref(), 1);
                changed = true;
            }
            RotoBodyRewriteOp::ReplaceJsProperty { property, old, new }
            | RotoBodyRewriteOp::ReplaceCssDeclaration { property, old, new } => {
                let property = property.to_string();
                let old = old.to_string();

                if property.is_empty()
                    || old.is_empty()
                    || !body.contains(&property)
                    || !body.contains(&old)
                {
                    continue;
                }

                body = body.replacen(&old, new.as_ref(), 1);
                changed = true;
            }
            RotoBodyRewriteOp::ReplaceHtmlAttribute {
                selector,
                attribute,
                old,
                new,
            } => {
                let selector = selector.to_string();
                let attribute = attribute.to_string();
                let old = old.to_string();

                if selector.is_empty()
                    || attribute.is_empty()
                    || old.is_empty()
                    || !body.contains(&selector)
                    || !body.contains(&attribute)
                    || !body.contains(&old)
                {
                    continue;
                }

                body = body.replacen(&old, new.as_ref(), 1);
                changed = true;
            }
            RotoBodyRewriteOp::ApplyJsonPatch {
                patch_json,
                content_type: rewrite_content_type,
            } => {
                let Some(next) = crate::filters::engine::json::patch::apply_json_patch_rfc6902_json(
                    &body,
                    patch_json.as_ref(),
                ) else {
                    tracing::warn!(
                            "failed to apply JSON patch in roto filter action"
                        );
                    continue;
                };

                if next != body {
                    body = next;
                    changed = true;

                    let rewrite_content_type = rewrite_content_type.to_string();
                    if !rewrite_content_type.trim().is_empty() {
                        content_type = Some(rewrite_content_type);
                    }
                }
            }
        }
    }

    changed.then_some(AppliedBodyRewrite {
        body,
        content_type,
    })
}
