use std::fmt;
use std::path::PathBuf;

use crate::filters::{
    GeneratedRewriteExtractor,
    GeneratedRewriteRequestInput,
    GeneratedRewriteResponseInput,
    GeneratedRewriteDraft,
    GeneratedFilter,
    GeneratedFilterAction,
    BodyAnchor,
    BodyRewriteOperation,
    FilterManager,
    extract_body_rewrite_intent,
    save_generated_filter_and_reload,
    validate_json_patch_operations
};
use crate::filters::engine::diff::{
    BodyDiffSource,
    DiffEvent,
    DiffNode,
    DiffPath,
    DiffSource
};
use crate::filters::engine::json::capture::{
    json_patch_operations_from_diff_events,
    push_json_body_delete_event,
    push_json_body_diff_events,
    push_json_body_insert_event,
};
use crate::filters::types::{
    FilterBody,
    FilterHeader,
    FilterRequest,
    FilterResponse,
};
use crate::mitm::capture::CapturePaths;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditableHttpMessageKind {
    Request,
    Response,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditableHttpBody {
    Text {
        text: String,
        content_type: Option<String>,
    },
    Binary {
        bytes_len: usize,
        content_type: Option<String>,
    },
    Empty,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableHttpMessage {
    pub kind: EditableHttpMessageKind,
    pub method: Option<String>,
    pub scheme: Option<String>,
    pub host: String,
    pub path: String,
    pub query: String,
    pub status: Option<u16>,
    pub headers: Vec<EditableHttpHeader>,
    pub body: EditableHttpBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableHttpMessageDiff {
    pub kind: EditableHttpMessageKind,
    pub method_changed: bool,
    pub host_changed: bool,
    pub path_changed: bool,
    pub query_changed: bool,
    pub status_changed: bool,
    pub added_headers: Vec<EditableHttpHeader>,
    pub removed_headers: Vec<EditableHttpHeader>,
    pub changed_headers: Vec<EditableHeaderChange>,
    pub body_changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableHeaderChange {
    pub name: String,
    pub original_value: String,
    pub edited_value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableHttpMessageParseError {
    message: String,
}

impl EditableHttpMessageParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EditableHttpMessageParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for EditableHttpMessageParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditedFilterGenerationError {
    Parse(EditableHttpMessageParseError),
    NoChanges,
    WrongMessageKind {
        expected: EditableHttpMessageKind,
        actual: EditableHttpMessageKind,
    },
    MissingResponseStatus,
}

impl fmt::Display for EditedFilterGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "failed to parse edited HTTP message: {err}"),
            Self::NoChanges => write!(f, "edited HTTP message has no changes"),
            Self::WrongMessageKind { expected, actual } => {
                write!(
                    f,
                    "edited HTTP message kind mismatch: expected {expected:?}, got {actual:?}",
                )
            }
            Self::MissingResponseStatus => write!(f, "edited response is missing status"),
        }
    }
}

impl std::error::Error for EditedFilterGenerationError {}

impl From<EditableHttpMessageParseError> for EditedFilterGenerationError {
    fn from(err: EditableHttpMessageParseError) -> Self {
        Self::Parse(err)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditableFilterSession {
    Request {
        name: String,
        original: EditableHttpMessage,
        edited_text: String,
    },
    Response {
        name: String,
        request_context: EditableHttpMessage,
        original: EditableHttpMessage,
        edited_text: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableFilterSessionPreview {
    pub has_changes: bool,
    pub changes_text: String,
    pub generated_roto: Option<String>,
    pub error: Option<String>,
}

impl EditableFilterSessionPreview {
    pub fn to_panel_text(&self) -> String {
        let mut out = String::new();

        if let Some(error) = &self.error {
            out.push_str("Error:\n");
            out.push_str("  ");
            out.push_str(error);
            out.push_str("\n\n");
        }

        out.push_str(&self.changes_text);

        if let Some(generated_roto) = &self.generated_roto {
            out.push_str("\nGenerated Roto:\n");
            out.push_str(generated_roto);
        }

        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableFilterSessionSaveResult {
    pub path: PathBuf,
    pub generated_roto: String,
    pub preview: EditableFilterSessionPreview,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EditableFilterSessionError {
    Parse(EditableHttpMessageParseError),
    NoChanges,
    WrongMessageKind {
        expected: EditableHttpMessageKind,
        actual: EditableHttpMessageKind,
    },
    MissingResponseStatus,
    Save(String),
}

impl fmt::Display for EditableFilterSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "failed to parse editable filter session: {err}"),
            Self::NoChanges => write!(f, "editable filter session has no changes"),
            Self::WrongMessageKind { expected, actual } => {
                write!(
                    f,
                    "editable filter session kind mismatch: expected {expected:?}, got {actual:?}",
                )
            }
            Self::MissingResponseStatus => write!(f, "editable response is missing status"),
            Self::Save(err) => write!(f, "failed to save generated filter: {err}"),
        }
    }
}

impl std::error::Error for EditableFilterSessionError {}

impl From<EditableHttpMessageParseError> for EditableFilterSessionError {
    fn from(err: EditableHttpMessageParseError) -> Self {
        Self::Parse(err)
    }
}

impl From<EditedFilterGenerationError> for EditableFilterSessionError {
    fn from(err: EditedFilterGenerationError) -> Self {
        match err {
            EditedFilterGenerationError::Parse(err) => Self::Parse(err),
            EditedFilterGenerationError::NoChanges => Self::NoChanges,
            EditedFilterGenerationError::WrongMessageKind { expected, actual } => {
                Self::WrongMessageKind { expected, actual }
            }
            EditedFilterGenerationError::MissingResponseStatus => Self::MissingResponseStatus,
        }
    }
}

impl EditableFilterSession {
    pub fn request(name: impl Into<String>, request: &FilterRequest) -> Self {
        let name = name.into();
        let original = EditableHttpMessage::from_filter_request(request);
        let edited_text = original.to_edit_text();

        Self::Request {
            name,
            original,
            edited_text,
        }
    }

    pub fn response(
        name: impl Into<String>,
        request: &FilterRequest,
        response: &FilterResponse,
    ) -> Self {
        let name = name.into();
        let request_context = EditableHttpMessage::from_filter_request(request);
        let original = EditableHttpMessage::from_filter_response(request, response);
        let edited_text = original.to_edit_text();

        Self::Response {
            name,
            request_context,
            original,
            edited_text,
        }
    }

    pub fn save_generated(
        &self,
        capture_paths: &CapturePaths,
        filter_manager: &FilterManager,
    ) -> Result<EditableFilterSessionSaveResult, EditableFilterSessionError> {
        let preview = self.preview();
        let filter = self.generate_filter()?;
        let generated_roto = filter.to_roto_source();

        let saved = save_generated_filter_and_reload(
            capture_paths,
            filter_manager,
            &filter,
        )
            .map_err(|err| EditableFilterSessionError::Save(err.to_string()))?;

        Ok(EditableFilterSessionSaveResult {
            path: saved.path,
            generated_roto,
            preview,
        })
    }

    pub fn preview(&self) -> EditableFilterSessionPreview {
        let diff = match self.diff() {
            Ok(diff) => diff,
            Err(err) => {
                return EditableFilterSessionPreview {
                    has_changes: false,
                    changes_text: String::new(),
                    generated_roto: None,
                    error: Some(err.to_string()),
                };
            }
        };

        let edited = match self.edited_message() {
            Ok(edited) => edited,
            Err(err) => {
                return EditableFilterSessionPreview {
                    has_changes: false,
                    changes_text: String::new(),
                    generated_roto: None,
                    error: Some(err.to_string()),
                };
            }
        };

        let has_changes = diff.has_changes();
        let mut changes_text = format_editable_diff(&diff);
        let semantic_events = self.original().semantic_diff(&edited);

        if !semantic_events.is_empty() {
            changes_text.push_str("\nSemantic diff:\n");

            for event in semantic_events {
                changes_text.push_str("  ");
                changes_text.push_str(&event.summary());
                changes_text.push('\n');
            }
        }

        if !has_changes {
            return EditableFilterSessionPreview {
                has_changes: false,
                changes_text,
                generated_roto: None,
                error: None,
            };
        }

        match self.generate_filter() {
            Ok(filter) => EditableFilterSessionPreview {
                has_changes: true,
                changes_text,
                generated_roto: Some(filter.to_roto_source()),
                error: None,
            },
            Err(err) => EditableFilterSessionPreview {
                has_changes: true,
                changes_text,
                generated_roto: None,
                error: Some(err.to_string()),
            },
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Request { name, .. } | Self::Response { name, .. } => name,
        }
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        match self {
            Self::Request { name: current, .. } | Self::Response { name: current, .. } => {
                *current = name.into();
            }
        }
    }

    pub fn original(&self) -> &EditableHttpMessage {
        match self {
            Self::Request { original, .. } | Self::Response { original, .. } => original,
        }
    }

    pub fn edited_text(&self) -> &str {
        match self {
            Self::Request { edited_text, .. } | Self::Response { edited_text, .. } => {
                edited_text
            }
        }
    }

    pub fn set_edited_text(&mut self, edited_text: impl Into<String>) {
        match self {
            Self::Request { edited_text: current, .. }
            | Self::Response { edited_text: current, .. } => {
                *current = edited_text.into();
            }
        }
    }

    pub fn reset(&mut self) {
        match self {
            Self::Request {
                original,
                edited_text,
                ..
            }
            | Self::Response {
                original,
                edited_text,
                ..
            } => {
                *edited_text = original.to_edit_text();
            }
        }
    }

    pub fn edited_message(&self) -> Result<EditableHttpMessage, EditableFilterSessionError> {
        match self {
            Self::Request {
                original,
                edited_text,
                ..
            }
            | Self::Response {
                original,
                edited_text,
                ..
            } => {
                Ok(EditableHttpMessage::parse_edit_text(
                    edited_text,
                    Some(original),
                )?)
            }
        }
    }

    pub fn diff(&self) -> Result<EditableHttpMessageDiff, EditableFilterSessionError> {
        let edited = self.edited_message()?;
        Ok(self.original().diff(&edited))
    }

    pub fn has_changes(&self) -> Result<bool, EditableFilterSessionError> {
        Ok(self.diff()?.has_changes())
    }

    pub fn generate_filter(&self) -> Result<GeneratedFilter, EditableFilterSessionError> {
        match self {
            Self::Request {
                name,
                original,
                edited_text,
            } => {
                let edited = EditableHttpMessage::parse_edit_text(
                    edited_text,
                    Some(original),
                )?;

                if edited.kind != EditableHttpMessageKind::Request {
                    return Err(EditableFilterSessionError::WrongMessageKind {
                        expected: EditableHttpMessageKind::Request,
                        actual: edited.kind,
                    });
                }

                extract_request_filter_from_edit(name.clone(), original, &edited)
                    .ok_or(EditableFilterSessionError::NoChanges)
            }
            Self::Response {
                name,
                request_context,
                original,
                edited_text,
            } => {
                let edited = EditableHttpMessage::parse_edit_text(
                    edited_text,
                    Some(original),
                )?;

                if edited.kind != EditableHttpMessageKind::Response {
                    return Err(EditableFilterSessionError::WrongMessageKind {
                        expected: EditableHttpMessageKind::Response,
                        actual: edited.kind,
                    });
                }

                if edited.status.is_none() {
                    return Err(EditableFilterSessionError::MissingResponseStatus);
                }

                extract_response_filter_from_edit(
                    name.clone(),
                    request_context,
                    original,
                    &edited,
                )
                    .ok_or(EditableFilterSessionError::NoChanges)
            }
        }
    }
}

impl EditableHttpMessage {
    pub fn from_filter_request(request: &FilterRequest) -> Self {
        Self {
            kind: EditableHttpMessageKind::Request,
            method: Some(request.method.clone()),
            scheme: Some(request.scheme.clone()),
            host: request.host.clone(),
            path: request.path.clone(),
            query: request.query.clone(),
            status: None,
            headers: editable_headers_from_filter_headers(&request.headers),
            body: editable_body_from_filter_body(&request.body),
        }
    }

    pub fn semantic_diff(&self, edited: &Self) -> Vec<DiffEvent> {
        let mut events = Vec::new();

        push_optional_string_replace(
            &mut events,
            DiffPath::method(),
            self.method.as_deref(),
            edited.method.as_deref(),
            DiffSource::HttpMeta,
        );
        push_optional_string_replace(
            &mut events,
            DiffPath::scheme(),
            self.scheme.as_deref(),
            edited.scheme.as_deref(),
            DiffSource::HttpMeta,
        );
        push_string_replace(
            &mut events,
            DiffPath::host(),
            &self.host,
            &edited.host,
            DiffSource::Url,
        );
        push_string_replace(
            &mut events,
            DiffPath::path(),
            &self.path,
            &edited.path,
            DiffSource::Url,
        );
        push_string_replace(
            &mut events,
            DiffPath::query(),
            &self.query,
            &edited.query,
            DiffSource::Url,
        );

        if self.status != edited.status {
            match (self.status, edited.status) {
                (Some(old), Some(new)) => events.push(DiffEvent::Replace {
                    path: DiffPath::status(),
                    old: DiffNode::Number(old.to_string()),
                    new: DiffNode::Number(new.to_string()),
                    source: DiffSource::HttpMeta,
                }),
                (Some(old), None) => events.push(DiffEvent::Delete {
                    path: DiffPath::status(),
                    old: DiffNode::Number(old.to_string()),
                    source: DiffSource::HttpMeta,
                }),
                (None, Some(new)) => events.push(DiffEvent::Insert {
                    path: DiffPath::status(),
                    node: DiffNode::Number(new.to_string()),
                    source: DiffSource::HttpMeta,
                }),
                (None, None) => {}
            }
        }

        push_header_diff_events(&mut events, &self.headers, &edited.headers);
        push_body_diff_events(&mut events, &self.body, &edited.body);

        events
    }

    pub fn to_filter_headers(&self) -> Vec<FilterHeader> {
        self.headers
            .iter()
            .map(|header| FilterHeader {
                name: header.name.clone(),
                value: header.value.clone(),
            })
            .collect()
    }

    pub fn from_filter_response(request: &FilterRequest, response: &FilterResponse) -> Self {
        Self {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: Some(request.scheme.clone()),
            host: request.host.clone(),
            path: request.path.clone(),
            query: request.query.clone(),
            status: Some(response.status),
            headers: editable_headers_from_filter_headers(&response.headers),
            body: editable_body_from_filter_body(&response.body),
        }
    }

    pub fn from_filter_response_without_request_context(response: &FilterResponse) -> Self {
        Self {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: String::new(),
            path: "/".to_string(),
            query: String::new(),
            status: Some(response.status),
            headers: editable_headers_from_filter_headers(&response.headers),
            body: editable_body_from_filter_body(&response.body),
        }
    }

    pub fn to_edit_text(&self) -> String {
        let mut out = String::new();

        match self.kind {
            EditableHttpMessageKind::Request => {
                out.push_str("kind: request\n");
                out.push_str("method: ");
                out.push_str(self.method.as_deref().unwrap_or(""));
                out.push('\n');
                out.push_str("scheme: ");
                out.push_str(self.scheme.as_deref().unwrap_or(""));
                out.push('\n');
            }
            EditableHttpMessageKind::Response => {
                out.push_str("kind: response\n");
                out.push_str("status: ");
                if let Some(status) = self.status {
                    out.push_str(&status.to_string());
                }
                out.push('\n');
            }
        }

        out.push_str("host: ");
        out.push_str(&self.host);
        out.push('\n');
        out.push_str("path: ");
        out.push_str(&self.path);
        out.push('\n');
        out.push_str("query: ");
        out.push_str(&self.query);
        out.push('\n');
        out.push('\n');

        out.push_str("headers:\n");

        for header in &self.headers {
            out.push_str(&header.name);
            out.push_str(": ");
            out.push_str(&header.value);
            out.push('\n');
        }

        out.push('\n');
        out.push_str("body:\n");

        match &self.body {
            EditableHttpBody::Text { text, .. } => {
                out.push_str(text);
                if !text.ends_with('\n') {
                    out.push('\n');
                }
            }
            EditableHttpBody::Binary {
                bytes_len,
                content_type,
            } => {
                out.push_str("# binary body is not editable\n");
                out.push_str("# bytes_len: ");
                out.push_str(&bytes_len.to_string());
                out.push('\n');

                if let Some(content_type) = content_type {
                    out.push_str("# content_type: ");
                    out.push_str(content_type);
                    out.push('\n');
                }
            }
            EditableHttpBody::Empty => {}
        }

        out
    }

    pub fn parse_edit_text(
        text: &str,
        original: Option<&EditableHttpMessage>,
    ) -> Result<Self, EditableHttpMessageParseError> {
        let sections = split_edit_text_sections(text);

        let mut kind = original
            .map(|message| message.kind.clone())
            .unwrap_or(EditableHttpMessageKind::Request);
        let mut method = original.and_then(|message| message.method.clone());
        let mut scheme = original.and_then(|message| message.scheme.clone());
        let mut host = original
            .map(|message| message.host.clone())
            .unwrap_or_default();
        let mut path = original
            .map(|message| message.path.clone())
            .unwrap_or_else(|| "/".to_string());
        let mut query = original
            .map(|message| message.query.clone())
            .unwrap_or_default();
        let mut status = original.and_then(|message| message.status);
        let mut body_content_type = original
            .and_then(|message| message.body_content_type().map(ToOwned::to_owned));

        for line in sections.meta.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value)) = line.split_once(':') else {
                return Err(EditableHttpMessageParseError::new(format!(
                    "invalid meta line: {line:?}"
                )));
            };

            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            match key.as_str() {
                "kind" => {
                    kind = match value {
                        "request" => EditableHttpMessageKind::Request,
                        "response" => EditableHttpMessageKind::Response,
                        _ => {
                            return Err(EditableHttpMessageParseError::new(format!(
                                "invalid kind: {value:?}"
                            )));
                        }
                    };
                }
                "method" => method = empty_to_none(value),
                "scheme" => scheme = empty_to_none(value),
                "host" => host = value.to_string(),
                "path" => path = value.to_string(),
                "query" => query = value.to_string(),
                "status" => {
                    status = if value.is_empty() {
                        None
                    } else {
                        Some(value.parse::<u16>().map_err(|_| {
                            EditableHttpMessageParseError::new(format!(
                                "invalid status: {value:?}"
                            ))
                        })?)
                    };
                }
                "content-type" | "content_type" => {
                    body_content_type = empty_to_none(value);
                }
                _ => {
                    return Err(EditableHttpMessageParseError::new(format!(
                        "unknown meta key: {key:?}"
                    )));
                }
            }
        }

        let headers = parse_edit_headers(sections.headers)?;

        let body = if let Some(original) = original {
            match &original.body {
                EditableHttpBody::Binary {
                    bytes_len,
                    content_type,
                } => EditableHttpBody::Binary {
                    bytes_len: *bytes_len,
                    content_type: content_type.clone(),
                },
                EditableHttpBody::Text { text: original_text, content_type } => {
                    let normalized_body_text = if !original_text.ends_with('\n')
                        && sections.body.len() == original_text.len() + 1
                        && sections.body.starts_with(original_text)
                        && sections.body.ends_with('\n') {
                        original_text.clone()
                    } else {
                        sections.body.to_string()
                    };

                    EditableHttpBody::Text {
                        text: normalized_body_text,
                        content_type: body_content_type.or_else(|| content_type.clone()),
                    }
                }
                EditableHttpBody::Empty => {
                    if sections.body.is_empty() {
                        EditableHttpBody::Empty
                    } else {
                        EditableHttpBody::Text {
                            text: sections.body.to_string(),
                            content_type: body_content_type,
                        }
                    }
                }
            }
        } else if sections.body.is_empty() {
            EditableHttpBody::Empty
        } else {
            EditableHttpBody::Text {
                text: sections.body.to_string(),
                content_type: body_content_type,
            }
        };

        Ok(Self {
            kind,
            method,
            scheme,
            host,
            path,
            query,
            status,
            headers,
            body,
        })
    }

    pub fn diff(&self, edited: &Self) -> EditableHttpMessageDiff {
        let added_headers = edited
            .headers
            .iter()
            .filter(|edited_header| {
                self.header_value(&edited_header.name).is_none()
            })
            .cloned()
            .collect();

        let removed_headers = self
            .headers
            .iter()
            .filter(|original_header| {
                edited.header_value(&original_header.name).is_none()
            })
            .cloned()
            .collect();

        let changed_headers = self
            .headers
            .iter()
            .filter_map(|original_header| {
                let edited_value = edited.header_value(&original_header.name)?;

                if original_header.value == edited_value {
                    return None;
                }

                Some(EditableHeaderChange {
                    name: original_header.name.clone(),
                    original_value: original_header.value.clone(),
                    edited_value: edited_value.to_string(),
                })
            })
            .collect();

        EditableHttpMessageDiff {
            kind: self.kind.clone(),
            method_changed: self.method != edited.method,
            host_changed: self.host != edited.host,
            path_changed: self.path != edited.path,
            query_changed: self.query != edited.query,
            status_changed: self.status != edited.status,
            added_headers,
            removed_headers,
            changed_headers,
            body_changed: self.body_text() != edited.body_text(),
        }
    }

    pub fn has_text_body(&self) -> bool {
        matches!(self.body, EditableHttpBody::Text { .. })
    }

    pub fn body_text(&self) -> Option<&str> {
        match &self.body {
            EditableHttpBody::Text { text, .. } => Some(text),
            EditableHttpBody::Binary { .. } | EditableHttpBody::Empty => None,
        }
    }

    pub fn body_content_type(&self) -> Option<&str> {
        match &self.body {
            EditableHttpBody::Text { content_type, .. }
            | EditableHttpBody::Binary { content_type, .. } => content_type.as_deref(),
            EditableHttpBody::Empty => None,
        }
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    pub fn to_request_input(&self) -> GeneratedRewriteRequestInput {
        let mut input = GeneratedRewriteRequestInput::new(
            self.host.clone(),
            self.method.clone().unwrap_or_else(|| "GET".to_string()),
            self.path.clone(),
            self.query.clone(),
        );

        if let Some(body_text) = self.body_text() {
            input = input.with_body_text(body_text.to_string());
        }

        input
    }

    pub fn to_response_input(&self) -> Option<GeneratedRewriteResponseInput> {
        let status = self.status?;

        let mut input = GeneratedRewriteResponseInput::new(status);

        if let Some(content_type) = self.body_content_type() {
            input = input.with_content_type(content_type.to_string());
        }

        if let Some(body_text) = self.body_text() {
            input = input.with_body_text(body_text.to_string());
        }

        Some(input)
    }
}

impl EditableHttpMessageDiff {
    pub fn has_changes(&self) -> bool {
        self.method_changed
            || self.host_changed
            || self.path_changed
            || self.query_changed
            || self.status_changed
            || !self.added_headers.is_empty()
            || !self.removed_headers.is_empty()
            || !self.changed_headers.is_empty()
            || self.body_changed
    }

    pub fn header_actions(&self) -> Vec<GeneratedFilterAction> {
        let mut actions = Vec::new();

        match self.kind {
            EditableHttpMessageKind::Request => {
                for header in &self.removed_headers {
                    actions.push(GeneratedFilterAction::RemoveRequestHeader(
                        header.name.clone(),
                    ));
                }

                for header in &self.changed_headers {
                    actions.push(GeneratedFilterAction::SetRequestHeader {
                        name: header.name.clone(),
                        value: header.edited_value.clone(),
                    });
                }

                for header in &self.added_headers {
                    actions.push(GeneratedFilterAction::SetRequestHeader {
                        name: header.name.clone(),
                        value: header.value.clone(),
                    });
                }
            }
            EditableHttpMessageKind::Response => {
                for header in &self.removed_headers {
                    actions.push(GeneratedFilterAction::RemoveResponseHeader(
                        header.name.clone(),
                    ));
                }

                for header in &self.changed_headers {
                    actions.push(GeneratedFilterAction::SetResponseHeader {
                        name: header.name.clone(),
                        value: header.edited_value.clone(),
                    });
                }

                for header in &self.added_headers {
                    actions.push(GeneratedFilterAction::SetResponseHeader {
                        name: header.name.clone(),
                        value: header.value.clone(),
                    });
                }
            }
        }

        actions
    }
}

pub fn extract_request_rewrite_from_edit(
    original: &EditableHttpMessage,
    edited: &EditableHttpMessage,
) -> Option<GeneratedRewriteDraft> {
    if original.kind != EditableHttpMessageKind::Request
        || edited.kind != EditableHttpMessageKind::Request
    {
        return None;
    }

    let diff = original.diff(edited);

    if !diff.has_changes() {
        return None;
    }

    Some(GeneratedRewriteExtractor::request(
        original.to_request_input(),
        edited.to_request_input(),
    ))
}

pub fn extract_request_filter_from_edit(
    name: impl Into<String>,
    original: &EditableHttpMessage,
    edited: &EditableHttpMessage,
) -> Option<GeneratedFilter> {
    if original.kind != EditableHttpMessageKind::Request
        || edited.kind != EditableHttpMessageKind::Request
    {
        return None;
    }

    let diff = original.diff(edited);

    if !diff.has_changes() {
        return None;
    }

    let mut filter = GeneratedRewriteExtractor::request(
        original.to_request_input(),
        edited.to_request_input(),
    )
        .into_filter(name);

    filter.extend_actions(diff.header_actions());

    if diff.removed_headers.iter().any(|h| h.name.eq_ignore_ascii_case("host")) {
        filter.add_action(GeneratedFilterAction::Drop);
        filter.add_rewrite_note("host header removed; auto-added drop() to suppress client response");
    }
    
    let semantic_events = original.semantic_diff(edited);
    let json_patch_operations = json_patch_operations_from_diff_events(&semantic_events);

    if !json_patch_operations.is_empty()
        && let Some(edited_body) = edited.body_text()
    {
        let content_type = edited
            .body_content_type()
            .unwrap_or("application/json; charset=utf-8")
            .to_string();

        let validation_ok = original
            .body_text()
            .is_some_and(|original_body| {
                validate_json_patch_operations(
                    original_body,
                    edited_body,
                    &json_patch_operations,
                )
            });

        filter.replace_request_body_rewrite_action(
            GeneratedFilterAction::ApplyRequestJsonPatch {
                operations: json_patch_operations,
                resulting_body: edited_body.to_string(),
                content_type,
            },
        );

        if validation_ok {
            filter.add_rewrite_note("generated JSON patch validates against edited request body");
        } else {
            filter.add_rewrite_note("generated JSON patch did not validate; falling back to set_body_text output");
        }
    } else if let (Some(original_body), Some(edited_body)) =
        (original.body_text(), edited.body_text())
        && let Some(intent) = extract_body_rewrite_intent(
        original_body,
        edited_body,
        original.body_content_type().or(edited.body_content_type()),
    )
        && let Some(action) = request_body_action_from_intent(&intent)
    {
        filter.replace_request_body_rewrite_action(action);
        filter.add_rewrite_note(format!(
            "semantic body rewrite: language={}, confidence={:?}",
            intent.language.as_label(),
            intent.confidence,
        ));

        match intent.anchor {
            BodyAnchor::ContainsAll(values) => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: contains all {:?}",
                    values,
                ));
            }
            BodyAnchor::JsProperty { property } => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: javascript property {:?}",
                    property,
                ));
            }
            BodyAnchor::CssDeclaration { property } => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: css declaration {:?}",
                    property,
                ));
            }
            BodyAnchor::HtmlAttribute { element, attribute } => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: html attribute {:?} on {:?}",
                    attribute,
                    element,
                ));
            }
            _ => {}
        }
    }

    Some(filter)
}

pub fn generate_request_filter_from_edited_text(
    name: impl Into<String>,
    request: &FilterRequest,
    edited_text: &str,
) -> Result<GeneratedFilter, EditedFilterGenerationError> {
    let original = EditableHttpMessage::from_filter_request(request);
    let edited = EditableHttpMessage::parse_edit_text(edited_text, Some(&original))?;

    if edited.kind != EditableHttpMessageKind::Request {
        return Err(EditedFilterGenerationError::WrongMessageKind {
            expected: EditableHttpMessageKind::Request,
            actual: edited.kind,
        });
    }

    extract_request_filter_from_edit(name, &original, &edited)
        .ok_or(EditedFilterGenerationError::NoChanges)
}

pub fn extract_response_rewrite_from_edit(
    request_context: &EditableHttpMessage,
    original: &EditableHttpMessage,
    edited: &EditableHttpMessage,
) -> Option<GeneratedRewriteDraft> {
    if original.kind != EditableHttpMessageKind::Response
        || edited.kind != EditableHttpMessageKind::Response
    {
        return None;
    }

    let diff = original.diff(edited);

    if !diff.has_changes() {
        return None;
    }

    let request = request_context.to_request_input();
    let original_response = original.to_response_input()?;
    let edited_response = edited.to_response_input()?;

    Some(GeneratedRewriteExtractor::response(
        &request,
        original_response,
        edited_response,
    ))
}

pub fn extract_response_filter_from_edit(
    name: impl Into<String>,
    request_context: &EditableHttpMessage,
    original: &EditableHttpMessage,
    edited: &EditableHttpMessage,
) -> Option<GeneratedFilter> {
    if original.kind != EditableHttpMessageKind::Response
        || edited.kind != EditableHttpMessageKind::Response
    {
        return None;
    }

    let diff = original.diff(edited);

    if !diff.has_changes() {
        return None;
    }

    let request = request_context.to_request_input();
    let original_response = original.to_response_input()?;
    let edited_response = edited.to_response_input()?;

    let mut filter = GeneratedRewriteExtractor::response(
        &request,
        original_response,
        edited_response,
    )
        .into_filter(name);

    filter.extend_actions(diff.header_actions());

    let semantic_events = original.semantic_diff(edited);
    let json_patch_operations = json_patch_operations_from_diff_events(&semantic_events);

    if !json_patch_operations.is_empty()
        && let Some(edited_body) = edited.body_text()
    {
        let content_type = edited
            .body_content_type()
            .unwrap_or("application/json; charset=utf-8")
            .to_string();

        let validation_ok = original
            .body_text()
            .is_some_and(|original_body| {
                validate_json_patch_operations(
                    original_body,
                    edited_body,
                    &json_patch_operations,
                )
            });

        filter.replace_response_body_rewrite_action(
            GeneratedFilterAction::ApplyResponseJsonPatch {
                operations: json_patch_operations,
                resulting_body: edited_body.to_string(),
                content_type,
            },
        );

        if validation_ok {
            filter.add_rewrite_note("generated JSON patch validates against edited response body");
        } else {
            filter.add_rewrite_note("generated JSON patch did not validate; falling back to set_body_text output");
        }
    } else if let (Some(original_body), Some(edited_body)) =
        (original.body_text(), edited.body_text())
        && let Some(intent) = extract_body_rewrite_intent(
        original_body,
        edited_body,
        original.body_content_type().or(edited.body_content_type()),
    )
        && let Some(action) = response_body_action_from_intent(&intent)
    {
        filter.replace_response_body_rewrite_action(action);
        filter.add_rewrite_note(format!(
            "semantic body rewrite: language={}, confidence={:?}",
            intent.language.as_label(),
            intent.confidence,
        ));

        match intent.anchor {
            BodyAnchor::ContainsAll(values) => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: contains all {:?}",
                    values,
                ));
            }
            BodyAnchor::JsProperty { property } => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: javascript property {:?}",
                    property,
                ));
            }
            BodyAnchor::CssDeclaration { property } => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: css declaration {:?}",
                    property,
                ));
            }
            BodyAnchor::HtmlAttribute { element, attribute } => {
                filter.add_rewrite_note(format!(
                    "semantic anchor: html attribute {:?} on {:?}",
                    attribute,
                    element,
                ));
            }
            _ => {}
        }
    }

    Some(filter)
}

pub fn generate_response_filter_from_edited_text(
    name: impl Into<String>,
    request: &FilterRequest,
    response: &FilterResponse,
    edited_text: &str,
) -> Result<GeneratedFilter, EditedFilterGenerationError> {
    let request_context = EditableHttpMessage::from_filter_request(request);
    let original = EditableHttpMessage::from_filter_response(request, response);
    let edited = EditableHttpMessage::parse_edit_text(edited_text, Some(&original))?;

    if edited.kind != EditableHttpMessageKind::Response {
        return Err(EditedFilterGenerationError::WrongMessageKind {
            expected: EditableHttpMessageKind::Response,
            actual: edited.kind,
        });
    }

    if edited.status.is_none() {
        return Err(EditedFilterGenerationError::MissingResponseStatus);
    }

    extract_response_filter_from_edit(name, &request_context, &original, &edited)
        .ok_or(EditedFilterGenerationError::NoChanges)
}

fn editable_headers_from_filter_headers(headers: &[FilterHeader]) -> Vec<EditableHttpHeader> {
    headers
        .iter()
        .map(|header| EditableHttpHeader {
            name: header.name.clone(),
            value: header.value.clone(),
        })
        .collect()
}

fn editable_body_from_filter_body(body: &FilterBody) -> EditableHttpBody {
    if let Some(text) = &body.text {
        return EditableHttpBody::Text {
            text: text.clone(),
            content_type: body.content_type.clone(),
        };
    }

    if body.bytes.is_empty() {
        EditableHttpBody::Empty
    } else {
        EditableHttpBody::Binary {
            bytes_len: body.bytes.len(),
            content_type: body.content_type.clone(),
        }
    }
}

fn push_optional_string_replace(
    events: &mut Vec<DiffEvent>,
    path: DiffPath,
    old: Option<&str>,
    new: Option<&str>,
    source: DiffSource,
) {
    if old == new {
        return;
    }

    match (old, new) {
        (Some(old), Some(new)) => events.push(DiffEvent::Replace {
            path,
            old: DiffNode::String(old.to_string()),
            new: DiffNode::String(new.to_string()),
            source,
        }),
        (Some(old), None) => events.push(DiffEvent::Delete {
            path,
            old: DiffNode::String(old.to_string()),
            source,
        }),
        (None, Some(new)) => events.push(DiffEvent::Insert {
            path,
            node: DiffNode::String(new.to_string()),
            source,
        }),
        (None, None) => {}
    }
}

fn push_string_replace(
    events: &mut Vec<DiffEvent>,
    path: DiffPath,
    old: &str,
    new: &str,
    source: DiffSource,
) {
    if old == new {
        return;
    }

    events.push(DiffEvent::Replace {
        path,
        old: DiffNode::String(old.to_string()),
        new: DiffNode::String(new.to_string()),
        source,
    });
}

fn push_header_diff_events(
    events: &mut Vec<DiffEvent>,
    original: &[EditableHttpHeader],
    edited: &[EditableHttpHeader],
) {
    for original_header in original {
        match find_header(edited, &original_header.name) {
            Some(edited_header) if edited_header.value != original_header.value => {
                events.push(DiffEvent::Replace {
                    path: DiffPath::header(original_header.name.to_ascii_lowercase()),
                    old: DiffNode::Header {
                        name: original_header.name.clone(),
                        value: original_header.value.clone(),
                    },
                    new: DiffNode::Header {
                        name: edited_header.name.clone(),
                        value: edited_header.value.clone(),
                    },
                    source: DiffSource::Header,
                });
            }
            Some(_) => {}
            None => {
                events.push(DiffEvent::Delete {
                    path: DiffPath::header(original_header.name.to_ascii_lowercase()),
                    old: DiffNode::Header {
                        name: original_header.name.clone(),
                        value: original_header.value.clone(),
                    },
                    source: DiffSource::Header,
                });
            }
        }
    }

    for edited_header in edited {
        if find_header(original, &edited_header.name).is_none() {
            events.push(DiffEvent::Insert {
                path: DiffPath::header(edited_header.name.to_ascii_lowercase()),
                node: DiffNode::Header {
                    name: edited_header.name.clone(),
                    value: edited_header.value.clone(),
                },
                source: DiffSource::Header,
            });
        }
    }
}

fn find_header<'a>(
    headers: &'a [EditableHttpHeader],
    name: &str,
) -> Option<&'a EditableHttpHeader> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
}

fn push_body_diff_events(
    events: &mut Vec<DiffEvent>,
    original: &EditableHttpBody,
    edited: &EditableHttpBody,
) {
    if original == edited {
        return;
    }

    match (original, edited) {
        (
            EditableHttpBody::Text {
                text: old,
                content_type: old_content_type,
            },
            EditableHttpBody::Text {
                text: new,
                content_type: new_content_type,
            },
        ) => {
            if push_json_body_diff_events(
                events,
                old,
                new,
                old_content_type.as_deref().or(new_content_type.as_deref()),
            ) {
                return;
            }

            events.push(DiffEvent::Replace {
                path: DiffPath::body(),
                old: DiffNode::Text(old.clone()),
                new: DiffNode::Text(new.clone()),
                source: DiffSource::Body(BodyDiffSource::Text),
            });
        }
        (EditableHttpBody::Empty, EditableHttpBody::Text { text, content_type }) => {
            if push_json_body_insert_event(events, text, content_type.as_deref()) {
                return;
            }

            events.push(DiffEvent::Insert {
                path: DiffPath::body(),
                node: DiffNode::Text(text.clone()),
                source: DiffSource::Body(BodyDiffSource::Text),
            });
        }
        (EditableHttpBody::Text { text, content_type }, EditableHttpBody::Empty) => {
            if push_json_body_delete_event(events, text, content_type.as_deref()) {
                return;
            }

            events.push(DiffEvent::Delete {
                path: DiffPath::body(),
                old: DiffNode::Text(text.clone()),
                source: DiffSource::Body(BodyDiffSource::Text),
            });
        }
        (EditableHttpBody::Binary { bytes_len, content_type }, EditableHttpBody::Empty) => {
            events.push(DiffEvent::Delete {
                path: DiffPath::body(),
                old: DiffNode::Binary {
                    bytes_len: *bytes_len,
                    content_type: content_type.clone(),
                },
                source: DiffSource::Body(BodyDiffSource::Binary),
            });
        }
        (EditableHttpBody::Empty, EditableHttpBody::Binary { bytes_len, content_type }) => {
            events.push(DiffEvent::Insert {
                path: DiffPath::body(),
                node: DiffNode::Binary {
                    bytes_len: *bytes_len,
                    content_type: content_type.clone(),
                },
                source: DiffSource::Body(BodyDiffSource::Binary),
            });
        }
        (EditableHttpBody::Empty, EditableHttpBody::Empty) => {}
        (_, EditableHttpBody::Binary { bytes_len, content_type }) => {
            events.push(DiffEvent::Replace {
                path: DiffPath::body(),
                old: body_to_diff_node(original),
                new: DiffNode::Binary {
                    bytes_len: *bytes_len,
                    content_type: content_type.clone(),
                },
                source: DiffSource::Body(BodyDiffSource::Binary),
            });
        }
        (EditableHttpBody::Binary { .. }, _) => {
            events.push(DiffEvent::Replace {
                path: DiffPath::body(),
                old: body_to_diff_node(original),
                new: body_to_diff_node(edited),
                source: DiffSource::Body(BodyDiffSource::Binary),
            });
        }
    }
}

fn body_to_diff_node(body: &EditableHttpBody) -> DiffNode {
    match body {
        EditableHttpBody::Text { text, .. } => DiffNode::Text(text.clone()),
        EditableHttpBody::Binary {
            bytes_len,
            content_type,
        } => DiffNode::Binary {
            bytes_len: *bytes_len,
            content_type: content_type.clone(),
        },
        EditableHttpBody::Empty => DiffNode::Null,
    }
}

#[derive(Clone, Copy, Debug)]
struct EditTextSections<'a> {
    meta: &'a str,
    headers: &'a str,
    body: &'a str,
}

fn split_edit_text_sections(text: &str) -> EditTextSections<'_> {
    let headers_marker = "\nheaders:\n";
    let body_marker = "\nbody:\n";

    let (meta, after_meta) = match text.find(headers_marker) {
        Some(idx) => (&text[..idx], &text[idx + headers_marker.len()..]),
        None => {
            return EditTextSections {
                meta: text,
                headers: "",
                body: "",
            };
        }
    };

    let (headers, body) = match after_meta.find(body_marker) {
        Some(idx) => (&after_meta[..idx], &after_meta[idx + body_marker.len()..]),
        None => (after_meta, ""),
    };

    EditTextSections {
        meta,
        headers,
        body,
    }
}

fn parse_edit_headers(
    text: &str,
) -> Result<Vec<EditableHttpHeader>, EditableHttpMessageParseError> {
    let mut headers = Vec::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(EditableHttpMessageParseError::new(format!(
                "invalid header line: {line:?}"
            )));
        };

        let name = name.trim();
        let value = value.trim();

        if name.is_empty() {
            return Err(EditableHttpMessageParseError::new(
                "header name must not be empty",
            ));
        }

        headers.push(EditableHttpHeader {
            name: name.to_string(),
            value: value.to_string(),
        });
    }

    Ok(headers)
}

fn empty_to_none(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn format_editable_diff(diff: &EditableHttpMessageDiff) -> String {
    let mut out = String::new();

    out.push_str("Changes:\n");

    if !diff.has_changes() {
        out.push_str("  none\n");
        return out;
    }

    if diff.method_changed {
        out.push_str("  method changed\n");
    }

    if diff.host_changed {
        out.push_str("  host changed\n");
    }

    if diff.path_changed {
        out.push_str("  path changed\n");
    }

    if diff.query_changed {
        out.push_str("  query changed\n");
    }

    if diff.status_changed {
        out.push_str("  status changed\n");
    }

    for header in &diff.removed_headers {
        out.push_str("  removed header ");
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.value);
        out.push('\n');
    }

    for header in &diff.changed_headers {
        out.push_str("  header ");
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.original_value);
        out.push_str(" -> ");
        out.push_str(&header.edited_value);
        out.push('\n');
    }

    for header in &diff.added_headers {
        out.push_str("  added header ");
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.value);
        out.push('\n');
    }

    if diff.body_changed {
        out.push_str("  body changed\n");
    }

    out
}

fn request_body_action_from_intent(
    intent: &crate::filters::BodyRewriteIntent,
) -> Option<GeneratedFilterAction> {
    match &intent.operation {
        BodyRewriteOperation::ReplaceText { old, new }
        | BodyRewriteOperation::ReplaceTextOnce { old, new } => {
            Some(GeneratedFilterAction::ReplaceRequestBodyTextOnce {
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceTextAll { old, new } => {
            Some(GeneratedFilterAction::ReplaceRequestBodyTextAll {
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceRegex { pattern, replacement } => {
            Some(GeneratedFilterAction::ReplaceRequestBodyRegex {
                pattern: pattern.clone(),
                replacement: replacement.clone(),
            })
        }
        BodyRewriteOperation::ReplaceTextWhenContains { anchor, old, new } => {
            Some(GeneratedFilterAction::ReplaceRequestBodyTextWhenContains {
                anchor: anchor.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceJsProperty { property, old, new } => {
            Some(GeneratedFilterAction::ReplaceRequestJsProperty {
                property: property.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceCssDeclaration { property, old, new } => {
            Some(GeneratedFilterAction::ReplaceRequestCssDeclaration {
                property: property.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceHtmlAttribute {
            selector,
            attribute,
            old,
            new,
        } => Some(GeneratedFilterAction::ReplaceRequestHtmlAttribute {
            selector: selector.clone(),
            attribute: attribute.clone(),
            old: old.clone(),
            new: new.clone(),
        }),
        BodyRewriteOperation::ReplaceWholeBody { .. }
        | BodyRewriteOperation::InsertText { .. }
        | BodyRewriteOperation::DeleteText { .. }
        | BodyRewriteOperation::JsonPatch { .. } => None,
    }
}

fn response_body_action_from_intent(
    intent: &crate::filters::BodyRewriteIntent,
) -> Option<GeneratedFilterAction> {
    match &intent.operation {
        BodyRewriteOperation::ReplaceText { old, new }
        | BodyRewriteOperation::ReplaceTextOnce { old, new } => {
            Some(GeneratedFilterAction::ReplaceResponseBodyTextOnce {
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceTextAll { old, new } => {
            Some(GeneratedFilterAction::ReplaceResponseBodyTextAll {
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceRegex { pattern, replacement } => {
            Some(GeneratedFilterAction::ReplaceResponseBodyRegex {
                pattern: pattern.clone(),
                replacement: replacement.clone(),
            })
        }
        BodyRewriteOperation::ReplaceTextWhenContains { anchor, old, new } => {
            Some(GeneratedFilterAction::ReplaceResponseBodyTextWhenContains {
                anchor: anchor.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceJsProperty { property, old, new } => {
            Some(GeneratedFilterAction::ReplaceResponseJsProperty {
                property: property.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceCssDeclaration { property, old, new } => {
            Some(GeneratedFilterAction::ReplaceResponseCssDeclaration {
                property: property.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        }
        BodyRewriteOperation::ReplaceHtmlAttribute {
            selector,
            attribute,
            old,
            new,
        } => Some(GeneratedFilterAction::ReplaceResponseHtmlAttribute {
            selector: selector.clone(),
            attribute: attribute.clone(),
            old: old.clone(),
            new: new.clone(),
        }),
        BodyRewriteOperation::ReplaceWholeBody { .. }
        | BodyRewriteOperation::InsertText { .. }
        | BodyRewriteOperation::DeleteText { .. }
        | BodyRewriteOperation::JsonPatch { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_diff_detects_header_events() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            status: None,
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                EditableHttpHeader {
                    name: "accept".to_string(),
                    value: "*/*".to_string(),
                },
            ],
            body: EditableHttpBody::Empty,
        };

        let edited = EditableHttpMessage {
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "close".to_string(),
                },
                EditableHttpHeader {
                    name: "x-added".to_string(),
                    value: "true".to_string(),
                },
            ],
            ..original.clone()
        };

        let events = original.semantic_diff(&edited);
        let summaries = events
            .iter()
            .map(DiffEvent::summary)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(summaries.contains("replace /headers/connection"));
        assert!(summaries.contains("delete /headers/accept"));
        assert!(summaries.contains("insert /headers/x-added"));
    }

    #[test]
    fn semantic_diff_detects_status_and_body_events() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(404),
            headers: Vec::new(),
            body: EditableHttpBody::Text {
                text: "{\"error\":\"not found\"}".to_string(),
                content_type: Some("application/json".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            status: Some(200),
            body: EditableHttpBody::Text {
                text: "{\"ok\":true}".to_string(),
                content_type: Some("application/json".to_string()),
            },
            ..original.clone()
        };

        let events = original.semantic_diff(&edited);
        let summaries = events
            .iter()
            .map(DiffEvent::summary)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(summaries.contains("replace /status: 404 -> 200"));
        assert!(summaries.contains("delete /body/error"));
        assert!(summaries.contains("insert /body/ok"));
        assert!(!summaries.contains("replace /body:"));
    }

    #[test]
    fn preview_contains_semantic_diff() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            }],
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let mut session = EditableFilterSession::request("edit request", &request);
        let edited_text = session
            .edited_text()
            .replace("connection: keep-alive", "connection: close");

        session.set_edited_text(edited_text);

        let panel = session.preview().to_panel_text();

        assert!(panel.contains("Semantic diff:"));
        assert!(panel.contains("replace /headers/connection"));
    }

    #[test]
    fn editable_request_session_preview_contains_changes_and_roto() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            }],
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let mut session = EditableFilterSession::request("edit request", &request);
        let edited_text = session
            .edited_text()
            .replace("connection: keep-alive", "connection: close");

        session.set_edited_text(edited_text);

        let preview = session.preview();
        let panel = preview.to_panel_text();

        assert!(preview.has_changes);
        assert!(preview.error.is_none());
        assert!(panel.contains("Changes:"));
        assert!(panel.contains("header connection: keep-alive -> close"));
        assert!(panel.contains("Generated Roto:"));
        assert!(panel.contains(".set_header(\"connection\", \"close\")"));
    }

    #[test]
    fn editable_response_session_preview_contains_changes_and_roto() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: Some("api.example.com".to_string()),
        };

        let response = FilterResponse {
            status: 404,
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            }],
            body: FilterBody {
                bytes: br#"{"error":"not found"}"#.to_vec(),
                text: Some(r#"{"error":"not found"}"#.to_string()),
                content_type: Some("application/json; charset=utf-8".to_string()),
                encoding: None,
                truncated: false,
            },
            upstream_status: Some(404),
            elapsed_ms: Some(12),
        };

        let mut session = EditableFilterSession::response("edit response", &request, &response);
        let edited_text = session
            .edited_text()
            .replace("status: 404", "status: 200")
            .replace(r#"{"error":"not found"}"#, r#"{"ok":true}"#);

        session.set_edited_text(edited_text);

        let preview = session.preview();
        let panel = preview.to_panel_text();

        assert!(preview.has_changes);
        assert!(preview.error.is_none());
        assert!(panel.contains("status changed"));
        assert!(panel.contains("body changed"));
        assert!(panel.contains("Generated Roto:"));
        assert!(panel.contains(".set_status(200)"));
        assert!(panel.contains(".apply_json_patch("));
        assert!(panel.contains("\"op\": \"remove\""));
        assert!(panel.contains("\"path\": \"/error\""));
        assert!(panel.contains("\"op\": \"add\""));
        assert!(panel.contains("\"path\": \"/ok\""));
    }

    #[test]
    fn unchanged_editable_session_preview_has_no_generated_roto() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let session = EditableFilterSession::request("edit request", &request);
        let preview = session.preview();
        let panel = preview.to_panel_text();

        assert!(!preview.has_changes);
        assert!(preview.generated_roto.is_none());
        assert!(preview.error.is_none());
        assert!(panel.contains("Changes:"));
        assert!(panel.contains("none"));
    }

    #[test]
    fn editable_request_session_generates_filter() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            }],
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let mut session = EditableFilterSession::request("edit request", &request);
        let edited_text = session
            .edited_text()
            .replace("connection: keep-alive", "connection: close");

        session.set_edited_text(edited_text);

        assert!(session.has_changes().expect("session diff should work"));

        let filter = session
            .generate_filter()
            .expect("changed request session should generate filter");
        let source = filter.to_roto_source();

        assert!(source.contains("fn request_action(req: Request) -> RequestAction"));
        assert!(source.contains(".set_header(\"connection\", \"close\")"));
    }

    #[test]
    fn editable_response_session_generates_filter() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: Some("api.example.com".to_string()),
        };

        let response = FilterResponse {
            status: 404,
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            }],
            body: FilterBody {
                bytes: br#"{"error":"not found"}"#.to_vec(),
                text: Some(r#"{"error":"not found"}"#.to_string()),
                content_type: Some("application/json; charset=utf-8".to_string()),
                encoding: None,
                truncated: false,
            },
            upstream_status: Some(404),
            elapsed_ms: Some(12),
        };

        let mut session = EditableFilterSession::response("edit response", &request, &response);
        let edited_text = session
            .edited_text()
            .replace("status: 404", "status: 200")
            .replace(r#"{"error":"not found"}"#, r#"{"ok":true}"#);

        session.set_edited_text(edited_text);

        assert!(session.has_changes().expect("session diff should work"));

        let filter = session
            .generate_filter()
            .expect("changed response session should generate filter");
        let source = filter.to_roto_source();

        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".apply_json_patch("));
        assert!(source.contains("\"op\": \"remove\""));
        assert!(source.contains("\"path\": \"/error\""));
        assert!(source.contains("\"op\": \"add\""));
        assert!(source.contains("\"path\": \"/ok\""));
    }

    #[test]
    fn editable_session_reset_restores_original_text() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            }],
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let mut session = EditableFilterSession::request("edit request", &request);
        let original_text = session.edited_text().to_string();

        session.set_edited_text("broken");
        assert_ne!(session.edited_text(), original_text);

        session.reset();
        assert_eq!(session.edited_text(), original_text);
    }

    #[test]
    fn editable_session_returns_no_changes() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let session = EditableFilterSession::request("edit request", &request);

        assert!(!session.has_changes().expect("session diff should work"));

        let err = session
            .generate_filter()
            .expect_err("unchanged session should not generate filter");

        assert_eq!(err, EditableFilterSessionError::NoChanges);
    }

    #[test]
    fn facade_generates_request_filter_from_edited_text() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            }],
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let original = EditableHttpMessage::from_filter_request(&request);
        let edited_text = original
            .to_edit_text()
            .replace("connection: keep-alive", "connection: close");

        let filter = generate_request_filter_from_edited_text(
            "edited request",
            &request,
            &edited_text,
        )
            .expect("edited request should generate filter");

        let source = filter.to_roto_source();

        assert!(source.contains("fn request_action(req: Request) -> RequestAction"));
        assert!(source.contains(".set_header(\"connection\", \"close\")"));
    }

    #[test]
    fn facade_generates_response_filter_from_edited_text() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: Some("api.example.com".to_string()),
        };

        let response = FilterResponse {
            status: 404,
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            }],
            body: FilterBody {
                bytes: br#"{"error":"not found"}"#.to_vec(),
                text: Some(r#"{"error":"not found"}"#.to_string()),
                content_type: Some("application/json; charset=utf-8".to_string()),
                encoding: None,
                truncated: false,
            },
            upstream_status: Some(404),
            elapsed_ms: Some(12),
        };

        let original = EditableHttpMessage::from_filter_response(&request, &response);
        let edited_text = original
            .to_edit_text()
            .replace("status: 404", "status: 200")
            .replace(r#"{"error":"not found"}"#, r#"{"ok":true}"#);

        let filter = generate_response_filter_from_edited_text(
            "edited response",
            &request,
            &response,
            &edited_text,
        )
            .expect("edited response should generate filter");

        let source = filter.to_roto_source();

        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(source.contains("res.status() == 404"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".apply_json_patch("));
        assert!(source.contains("\"op\": \"remove\""));
        assert!(source.contains("\"path\": \"/error\""));
        assert!(source.contains("\"op\": \"add\""));
        assert!(source.contains("\"path\": \"/ok\""));
    }

    #[test]
    fn facade_returns_no_changes_for_unmodified_request_text() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let original = EditableHttpMessage::from_filter_request(&request);
        let edited_text = original.to_edit_text();

        let err = generate_request_filter_from_edited_text(
            "unchanged request",
            &request,
            &edited_text,
        )
            .expect_err("unchanged request should not generate filter");

        assert_eq!(err, EditedFilterGenerationError::NoChanges);
    }

    #[test]
    fn converts_filter_request_to_editable_message() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "POST".to_string(),
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            path: "/v1/users".to_string(),
            query: "debug=true".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                FilterHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                FilterHeader {
                    name: "x-test".to_string(),
                    value: "true".to_string(),
                },
            ],
            body: FilterBody {
                bytes: br#"{"name":"alice"}"#.to_vec(),
                text: Some(r#"{"name":"alice"}"#.to_string()),
                content_type: Some("application/json".to_string()),
                encoding: None,
                truncated: false,
            },
            tls_sni: Some("api.example.com".to_string()),
        };

        let editable = EditableHttpMessage::from_filter_request(&request);

        assert_eq!(editable.kind, EditableHttpMessageKind::Request);
        assert_eq!(editable.method.as_deref(), Some("POST"));
        assert_eq!(editable.scheme.as_deref(), Some("https"));
        assert_eq!(editable.host, "api.example.com");
        assert_eq!(editable.path, "/v1/users");
        assert_eq!(editable.query, "debug=true");
        assert_eq!(editable.header_value("content-type"), Some("application/json"));
        assert_eq!(editable.body_text(), Some(r#"{"name":"alice"}"#));

        let edit_text = editable.to_edit_text();

        assert!(edit_text.contains("kind: request"));
        assert!(edit_text.contains("method: POST"));
        assert!(edit_text.contains("host: api.example.com"));
        assert!(edit_text.contains("content-type: application/json"));
        assert!(edit_text.contains(r#"{"name":"alice"}"#));
    }

    #[test]
    fn converts_filter_response_to_editable_message() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: FilterBody {
                bytes: Vec::new(),
                text: None,
                content_type: None,
                encoding: None,
                truncated: false,
            },
            tls_sni: Some("api.example.com".to_string()),
        };

        let response = FilterResponse {
            status: 404,
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            }],
            body: FilterBody {
                bytes: br#"{"error":"not found"}"#.to_vec(),
                text: Some(r#"{"error":"not found"}"#.to_string()),
                content_type: Some("application/json; charset=utf-8".to_string()),
                encoding: None,
                truncated: false,
            },
            upstream_status: Some(404),
            elapsed_ms: Some(12),
        };

        let editable = EditableHttpMessage::from_filter_response(&request, &response);

        assert_eq!(editable.kind, EditableHttpMessageKind::Response);
        assert_eq!(editable.status, Some(404));
        assert_eq!(editable.host, "api.example.com");
        assert_eq!(editable.path, "/v1/users/123");
        assert_eq!(
            editable.header_value("content-type"),
            Some("application/json; charset=utf-8"),
        );
        assert_eq!(editable.body_text(), Some(r#"{"error":"not found"}"#));

        let edit_text = editable.to_edit_text();

        assert!(edit_text.contains("kind: response"));
        assert!(edit_text.contains("status: 404"));
        assert!(edit_text.contains("host: api.example.com"));
        assert!(edit_text.contains(r#"{"error":"not found"}"#));
    }

    #[test]
    fn binary_filter_body_becomes_non_editable_binary_body() {
        let request = FilterRequest {
            id: "req-1".to_string(),
            seq: 1,
            flow_key: "flow-1".to_string(),
            method: "POST".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            path: "/upload".to_string(),
            query: String::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![FilterHeader {
                name: "content-type".to_string(),
                value: "application/octet-stream".to_string(),
            }],
            body: FilterBody {
                bytes: vec![0, 1, 2, 3, 4],
                text: None,
                content_type: Some("application/octet-stream".to_string()),
                encoding: None,
                truncated: false,
            },
            tls_sni: None,
        };

        let editable = EditableHttpMessage::from_filter_request(&request);

        assert_eq!(
            editable.body,
            EditableHttpBody::Binary {
                bytes_len: 5,
                content_type: Some("application/octet-stream".to_string()),
            },
        );

        let edit_text = editable.to_edit_text();

        assert!(edit_text.contains("# binary body is not editable"));
        assert!(edit_text.contains("# bytes_len: 5"));
    }

    #[test]
    fn serializes_and_parses_request_edit_text() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            status: None,
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                EditableHttpHeader {
                    name: "accept".to_string(),
                    value: "*/*".to_string(),
                },
            ],
            body: EditableHttpBody::Text {
                text: "hello\n".to_string(),
                content_type: Some("text/plain; charset=utf-8".to_string()),
            },
        };

        let text = original.to_edit_text();
        let edited_text = text
            .replace("connection: keep-alive", "connection: close")
            .replace("hello", "rewritten");

        let edited = EditableHttpMessage::parse_edit_text(&edited_text, Some(&original))
            .expect("edit text should parse");
        let diff = original.diff(&edited);

        assert!(diff.has_changes());
        assert_eq!(edited.header_value("connection"), Some("close"));
        assert_eq!(edited.body_text(), Some("rewritten\n"));
        assert_eq!(diff.changed_headers.len(), 1);
        assert!(diff.body_changed);
    }

    #[test]
    fn parses_added_and_removed_headers_from_edit_text() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            status: None,
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                EditableHttpHeader {
                    name: "accept".to_string(),
                    value: "*/*".to_string(),
                },
            ],
            body: EditableHttpBody::Empty,
        };

        let edited_text = r#"kind: request
method: GET
scheme: https
host: example.com
path: /
query:

headers:
connection: close
x-added: true

body:
"#;

        let edited = EditableHttpMessage::parse_edit_text(edited_text, Some(&original))
            .expect("edit text should parse");
        let diff = original.diff(&edited);

        assert_eq!(diff.added_headers.len(), 1);
        assert_eq!(diff.removed_headers.len(), 1);
        assert_eq!(diff.changed_headers.len(), 1);
        assert_eq!(diff.added_headers[0].name, "x-added");
        assert_eq!(diff.removed_headers[0].name, "accept");
        assert_eq!(diff.changed_headers[0].name, "connection");
    }

    #[test]
    fn serializes_and_parses_response_edit_text() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(404),
            headers: vec![EditableHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: EditableHttpBody::Text {
                text: "{\"error\":\"not found\"}".to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
        };

        let text = original.to_edit_text();
        let edited_text = text
            .replace("status: 404", "status: 200")
            .replace("{\"error\":\"not found\"}", "{\"ok\":true}");

        let edited = EditableHttpMessage::parse_edit_text(&edited_text, Some(&original))
            .expect("edit text should parse");

        assert_eq!(edited.status, Some(200));
        assert_eq!(edited.body_text(), Some("{\"ok\":true}\n"));

        let diff = original.diff(&edited);

        assert!(diff.status_changed);
        assert!(diff.body_changed);
    }

    #[test]
    fn edit_text_can_generate_request_filter() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            status: None,
            headers: vec![EditableHttpHeader {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            }],
            body: EditableHttpBody::Empty,
        };

        let edited_text = r#"kind: request
method: GET
scheme: https
host: example.com
path: /
query:

headers:
connection: close
x-added: true

body:
"#;

        let edited = EditableHttpMessage::parse_edit_text(edited_text, Some(&original))
            .expect("edit text should parse");

        let filter = extract_request_filter_from_edit("edit request", &original, &edited)
            .expect("request edit should produce filter");
        let source = filter.to_roto_source();

        assert!(source.contains(".set_header(\"connection\", \"close\")"));
        assert!(source.contains(".set_header(\"x-added\", \"true\")"));
    }

    #[test]
    fn detects_header_add_remove_change() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            status: None,
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                EditableHttpHeader {
                    name: "accept".to_string(),
                    value: "*/*".to_string(),
                },
            ],
            body: EditableHttpBody::Empty,
        };

        let edited = EditableHttpMessage {
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "close".to_string(),
                },
                EditableHttpHeader {
                    name: "x-added".to_string(),
                    value: "true".to_string(),
                },
            ],
            ..original.clone()
        };

        let diff = original.diff(&edited);

        assert!(diff.has_changes());
        assert_eq!(diff.added_headers.len(), 1);
        assert_eq!(diff.removed_headers.len(), 1);
        assert_eq!(diff.changed_headers.len(), 1);
        assert_eq!(diff.changed_headers[0].name, "connection");
    }

    #[test]
    fn request_header_diff_generates_request_header_actions() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "example.com".to_string(),
            path: "/".to_string(),
            query: String::new(),
            status: None,
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                EditableHttpHeader {
                    name: "accept".to_string(),
                    value: "*/*".to_string(),
                },
            ],
            body: EditableHttpBody::Empty,
        };

        let edited = EditableHttpMessage {
            headers: vec![
                EditableHttpHeader {
                    name: "connection".to_string(),
                    value: "close".to_string(),
                },
                EditableHttpHeader {
                    name: "x-added".to_string(),
                    value: "true".to_string(),
                },
            ],
            ..original.clone()
        };

        let filter = extract_request_filter_from_edit("edit request headers", &original, &edited)
            .expect("request edit should produce filter");
        let source = filter.to_roto_source();

        assert!(source.contains("fn request_action(req: Request) -> RequestAction"));
        assert!(source.contains(".remove_header(\"accept\")"));
        assert!(source.contains(".set_header(\"connection\", \"close\")"));
        assert!(source.contains(".set_header(\"x-added\", \"true\")"));
    }

    #[test]
    fn response_header_diff_generates_response_header_actions() {
        let request = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: None,
            headers: Vec::new(),
            body: EditableHttpBody::Empty,
        };

        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(404),
            headers: vec![
                EditableHttpHeader {
                    name: "server".to_string(),
                    value: "old".to_string(),
                },
                EditableHttpHeader {
                    name: "cache-control".to_string(),
                    value: "private".to_string(),
                },
            ],
            body: EditableHttpBody::Text {
                text: "{\"error\":\"not found\"}".to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            status: Some(200),
            headers: vec![
                EditableHttpHeader {
                    name: "server".to_string(),
                    value: "new".to_string(),
                },
                EditableHttpHeader {
                    name: "x-added".to_string(),
                    value: "true".to_string(),
                },
            ],
            body: EditableHttpBody::Text {
                text: "{\"ok\":true}".to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
            ..original.clone()
        };

        let filter = extract_response_filter_from_edit(
            "edit response",
            &request,
            &original,
            &edited,
        )
            .expect("response edit should produce filter");
        let source = filter.to_roto_source();

        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".apply_json_patch("));
        assert!(source.contains("\"op\": \"remove\""));
        assert!(source.contains("\"path\": \"/error\""));
        assert!(source.contains("\"op\": \"add\""));
        assert!(source.contains("\"path\": \"/ok\""));
        assert!(source.contains(".remove_header(\"cache-control\")"));
        assert!(source.contains(".set_header(\"server\", \"new\")"));
        assert!(source.contains(".set_header(\"x-added\", \"true\")"));
    }

    #[test]
    fn extracts_response_rewrite_from_edit() {
        let request = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: None,
            headers: Vec::new(),
            body: EditableHttpBody::Empty,
        };

        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(404),
            headers: Vec::new(),
            body: EditableHttpBody::Text {
                text: "{\"error\":\"not found\"}".to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            status: Some(200),
            body: EditableHttpBody::Text {
                text: "{\"ok\":true}".to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
            ..original.clone()
        };

        let draft = extract_response_rewrite_from_edit(&request, &original, &edited)
            .expect("response edit should produce rewrite draft");

        assert!(draft.has_changes());
    }
}