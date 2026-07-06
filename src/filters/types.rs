use serde::Deserialize;
use std::path::PathBuf;
use roto::{NoCtx, RotoString, TypedFunc, Val};
use crate::filters::runtime::{RotoRequestActionData, RotoRequestData, RotoResponseActionData, RotoResponseData};

pub type RotoOnRequestFn = TypedFunc<NoCtx, fn(Val<RotoRequestData>) -> bool>;
pub type RotoOnResponseFn = TypedFunc<NoCtx, fn(Val<RotoResponseData>) -> bool>;
pub type RotoRequestStringFn = TypedFunc<NoCtx, fn(Val<RotoRequestData>) -> RotoString>;
pub type RotoResponseStringFn = TypedFunc<NoCtx, fn(Val<RotoResponseData>) -> RotoString>;
pub type RotoRequestActionFn =
TypedFunc<NoCtx, fn(Val<RotoRequestData>) -> Val<RotoRequestActionData>>;
pub type RotoResponseActionFn =
TypedFunc<NoCtx, fn(Val<RotoResponseData>) -> Val<RotoResponseActionData>>;


#[derive(Clone, Debug)]
pub struct FilterDefinition {
    pub path: PathBuf,
    pub source: String,
    pub metadata: FilterMetadata,
    pub script: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct FilterMetadata {
    pub name: Option<String>,
    pub enabled: bool,
    pub priority: Option<i32>,
    pub trigger: FilterTrigger,
}

impl Default for FilterMetadata {
    fn default() -> Self {
        Self {
            name: None,
            enabled: true,
            priority: None,
            trigger: FilterTrigger::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct FilterTrigger {
    pub host: Vec<String>,
    pub path: Vec<String>,
    pub method: Vec<String>,
    pub phase: Vec<FilterPhase>,
}

impl Default for FilterTrigger {
    fn default() -> Self {
        Self {
            host: vec!["*".to_string()],
            path: vec!["*".to_string()],
            method: Vec::new(),
            phase: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilterPhase {
    Request,
    Response,
    Completed,
}

#[derive(Clone, Debug)]
pub struct FilterRequestView<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub method: &'a str,
}

#[derive(Clone, Debug)]
pub struct FilterResponseView<'a> {
    pub request: FilterRequestView<'a>,
    pub status: u16,
    pub content_type: Option<&'a str>,
}

impl FilterTrigger {
    pub fn matches_request(&self, req: &FilterRequestView<'_>) -> bool {
        self.matches_phase(FilterPhase::Request)
            && self.matches_host(req.host)
            && self.matches_path(req.path)
            && self.matches_method(req.method)
    }

    pub fn matches_response(&self, res: &FilterResponseView<'_>) -> bool {
        self.matches_phase(FilterPhase::Response)
            && self.matches_host(res.request.host)
            && self.matches_path(res.request.path)
            && self.matches_method(res.request.method)
    }

    pub fn matches_completed(&self, req: &FilterRequestView<'_>) -> bool {
        self.matches_phase(FilterPhase::Completed)
            && self.matches_host(req.host)
            && self.matches_path(req.path)
            && self.matches_method(req.method)
    }

    fn matches_phase(&self, phase: FilterPhase) -> bool {
        self.phase.is_empty() || self.phase.contains(&phase)
    }

    fn matches_host(&self, host: &str) -> bool {
        matches_any_glob(&self.host, &host.to_ascii_lowercase())
    }

    fn matches_path(&self, path: &str) -> bool {
        matches_any_glob(&self.path, path)
    }

    fn matches_method(&self, method: &str) -> bool {
        self.method.is_empty()
            || self
            .method
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(method))
    }
}

fn matches_any_glob(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| glob_match(pattern, value))
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();

    if !pattern.contains('*') {
        return pattern == value;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');

    let parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if parts.is_empty() {
        return true;
    }

    let mut rest = value.as_str();

    for (idx, part) in parts.iter().enumerate() {
        if idx == 0 && !starts_with_wildcard {
            let Some(next) = rest.strip_prefix(part) else {
                return false;
            };
            rest = next;
            continue;
        }

        let Some(found_idx) = rest.find(part) else {
            return false;
        };

        rest = &rest[found_idx + part.len()..];
    }

    ends_with_wildcard || rest.is_empty()
}

#[derive(Clone, Debug)]
pub struct FilterRequest {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub version: String,
    pub headers: Vec<FilterHeader>,
    pub body: FilterBody,
    pub tls_sni: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilterResponse {
    pub status: u16,
    pub version: String,
    pub headers: Vec<FilterHeader>,
    pub body: FilterBody,
    pub upstream_status: Option<u16>,
    pub elapsed_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct FilterFlow {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub request: FilterRequest,
    pub response: Option<FilterResponse>,
}

#[derive(Clone, Debug)]
pub struct FilterHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct FilterBody {
    pub bytes: Vec<u8>,
    pub text: Option<String>,
    pub content_type: Option<String>,
    pub encoding: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RequestAction {
    pub request: Option<FilterRequestPatch>,
    pub synthetic_response: Option<FilterSyntheticResponse>,
    pub marks: Vec<FilterMark>,
    pub tags: Vec<String>,
    pub notes: Vec<String>,
    pub outbound_http: Vec<OutboundHttpJob>,
    pub continue_filters: bool,
    pub drop_client_response: bool,
}

impl RequestAction {
    pub fn pass() -> Self {
        Self {
            continue_filters: true,
            ..Self::default()
        }
    }

    pub fn stop(mut self) -> Self {
        self.continue_filters = false;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResponseAction {
    pub response: Option<FilterResponsePatch>,
    pub marks: Vec<FilterMark>,
    pub tags: Vec<String>,
    pub notes: Vec<String>,
    pub outbound_http: Vec<OutboundHttpJob>,
    pub continue_filters: bool,
    pub drop_client_response: bool,
}

impl ResponseAction {
    pub fn pass() -> Self {
        Self {
            continue_filters: true,
            ..Self::default()
        }
    }

    pub fn stop(mut self) -> Self {
        self.continue_filters = false;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct CompletedAction {
    pub marks: Vec<FilterMark>,
    pub tags: Vec<String>,
    pub notes: Vec<String>,
    pub outbound_http: Vec<OutboundHttpJob>,
    pub continue_filters: bool,
}

impl CompletedAction {
    pub fn pass() -> Self {
        Self {
            continue_filters: true,
            ..Self::default()
        }
    }

    pub fn stop(mut self) -> Self {
        self.continue_filters = false;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct FilterRequestPatch {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub set_headers: Vec<FilterHeader>,
    pub remove_headers: Vec<String>,
    pub body: Option<FilterBodyPatch>,
}

#[derive(Clone, Debug, Default)]
pub struct FilterResponsePatch {
    pub status: Option<u16>,
    pub set_headers: Vec<FilterHeader>,
    pub remove_headers: Vec<String>,
    pub body: Option<FilterBodyPatch>,
}

#[derive(Clone, Debug)]
pub struct FilterBodyPatch {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilterSyntheticResponse {
    pub status: u16,
    pub headers: Vec<FilterHeader>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct FilterMark {
    pub label: String,
    pub color: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OutboundHttpJob {
    pub client: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<FilterHeader>,
    pub body: OutboundHttpBodySource,
}

#[derive(Clone, Debug)]
pub enum OutboundHttpBodySource {
    Bytes(Vec<u8>),
    CapturedRequest,
    CapturedResponse,
    CapturedRequestJson,
    CapturedResponseJson,
    CapturedFlowJson,
}

#[derive(Clone, Debug, Default)]
pub struct OutboundHttpBody {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilterHttpRequest {
    pub client: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<FilterHeader>,
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_supports_exact_match() {
        assert!(glob_match("example.com", "example.com"));
        assert!(glob_match("/mock", "/mock"));
        assert!(!glob_match("example.com", "api.example.com"));
        assert!(!glob_match("/mock", "/mock/extra"));
    }

    #[test]
    fn glob_match_supports_wildcards() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("api.*.example.com", "api.dev.example.com"));
        assert!(glob_match("/api/*", "/api/users"));
        assert!(glob_match("/v1/*", "/v1/test"));
        assert!(glob_match("*", "/anything"));
    }

    #[test]
    fn trigger_matches_request() {
        let trigger = FilterTrigger {
            host: vec!["*.example.com".to_string()],
            path: vec!["/api/*".to_string()],
            method: vec!["GET".to_string()],
            phase: vec![FilterPhase::Request],
        };

        assert!(trigger.matches_request(&FilterRequestView {
            host: "api.example.com",
            path: "/api/users",
            method: "GET",
        }));

        assert!(!trigger.matches_request(&FilterRequestView {
            host: "api.example.com",
            path: "/admin",
            method: "GET",
        }));

        assert!(!trigger.matches_request(&FilterRequestView {
            host: "api.example.com",
            path: "/api/users",
            method: "POST",
        }));
    }
}
