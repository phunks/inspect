use std::fmt::Write;
use crate::filters::{
    json_patch_operations_to_rfc6902_json,
    write_json_patch_comments,
    GeneratedJsonPatchOperation
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFilter {
    pub id: Option<String>,
    pub name: String,
    pub priority: i32,
    pub enabled: bool,
    pub phase: GeneratedFilterPhase,
    pub trigger: GeneratedFilterTrigger,
    pub conditions: Vec<GeneratedFilterCondition>,
    pub actions: Vec<GeneratedFilterAction>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFilterBuilder {
    name: String,
    priority: i32,
    enabled: bool,
    phase: GeneratedFilterPhase,
    trigger: GeneratedFilterTrigger,
    conditions: Vec<GeneratedFilterCondition>,
    actions: Vec<GeneratedFilterAction>,
}



#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedDiffAnchor {
    pub text: String,
    pub confidence: GeneratedDiffConfidence,
    pub source: GeneratedDiffAnchorSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedDiffConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedDiffAnchorSource {
    Line,
    Prefix,
    WholeOriginal,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedDiffStrategy {
    LineAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRewriteRequestInput {
    pub host: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub body_text: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRewriteResponseInput {
    pub status: u16,
    pub content_type: Option<String>,
    pub body_text: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRewriteExtractor {
    diff_strategy: GeneratedDiffStrategy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRewriteRequest {
    pub host: String,
    pub original_method: String,
    pub edited_method: String,
    pub original_path: String,
    pub edited_path: String,
    pub original_query: String,
    pub edited_query: String,
    pub original_body_text: Option<String>,
    pub edited_body_text: Option<String>,
    pub diff_strategy: GeneratedDiffStrategy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRewriteResponse {
    pub host: String,
    pub request_method: String,
    pub request_path: String,
    pub original_status: u16,
    pub edited_status: u16,
    pub original_content_type: Option<String>,
    pub edited_content_type: Option<String>,
    pub original_body_text: Option<String>,
    pub edited_body_text: Option<String>,
    pub diff_strategy: GeneratedDiffStrategy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedRewriteDraft {
    Request(GeneratedRewriteRequest),
    Response(GeneratedRewriteResponse),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedFilterPhase {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedFilterSelectionTarget {
    RequestHost,
    RequestPath,
    RequestQuery,
    RequestMethod,
    ResponseStatus,
    ResponseContentType,
    ResponseBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFilterTrigger {
    pub host: Vec<String>,
    pub path: Vec<String>,
    pub method: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedFilterCondition {
    RequestHostEq(String),
    RequestHostContains(String),
    RequestPathEq(String),
    RequestPathContains(String),
    RequestMethodEq(String),
    RequestQueryContains(String),
    ResponseStatusEq(u16),
    ResponseStatusAtLeast(u16),
    ResponseContentTypeContains(String),
    ResponseBodyContains(String),
    ResponseBodyContainsAll(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedFilterAction {
    Mark(String),
    SetRequestHeader {
        name: String,
        value: String,
    },
    RemoveRequestHeader(String),
    SetRequestBodyText {
        body: String,
        content_type: String,
    },
    ReplaceRequestBodyText {
        old: String,
        new: String,
    },
    ReplaceRequestBodyTextOnce {
        old: String,
        new: String,
    },
    ReplaceRequestBodyTextAll {
        old: String,
        new: String,
    },
    ReplaceRequestBodyRegex {
        pattern: String,
        replacement: String,
    },
    ReplaceRequestBodyTextWhenContains {
        anchor: String,
        old: String,
        new: String,
    },
    ReplaceRequestJsProperty {
        property: String,
        old: String,
        new: String,
    },
    ReplaceRequestCssDeclaration {
        property: String,
        old: String,
        new: String,
    },
    ReplaceRequestHtmlAttribute {
        selector: String,
        attribute: String,
        old: String,
        new: String,
    },
    ApplyRequestJsonPatch {
        operations: Vec<GeneratedJsonPatchOperation>,
        resulting_body: String,
        content_type: String,
    },
    SyntheticResponse {
        status: u16,
        body: String,
        content_type: String,
    },
    SetResponseStatus(u16),
    SetResponseHeader {
        name: String,
        value: String,
    },
    RemoveResponseHeader(String),
    SetResponseBodyText {
        body: String,
        content_type: String,
    },
    ReplaceResponseBodyText {
        old: String,
        new: String,
    },
    ReplaceResponseBodyTextOnce {
        old: String,
        new: String,
    },
    ReplaceResponseBodyTextAll {
        old: String,
        new: String,
    },
    ReplaceResponseBodyRegex {
        pattern: String,
        replacement: String,
    },
    ReplaceResponseBodyTextWhenContains {
        anchor: String,
        old: String,
        new: String,
    },
    ReplaceResponseJsProperty {
        property: String,
        old: String,
        new: String,
    },
    ReplaceResponseCssDeclaration {
        property: String,
        old: String,
        new: String,
    },
    ReplaceResponseHtmlAttribute {
        selector: String,
        attribute: String,
        old: String,
        new: String,
    },
    ApplyResponseJsonPatch {
        operations: Vec<GeneratedJsonPatchOperation>,
        resulting_body: String,
        content_type: String,
    },
    Stop,
    Drop,
}

impl GeneratedFilter {
    pub fn response_body_contains(
        name: impl Into<String>,
        body_fragment: impl Into<String>,
        mark: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            name: name.into(),
            priority: 9000,
            enabled: true,
            phase: GeneratedFilterPhase::Response,
            trigger: GeneratedFilterTrigger::default(),
            conditions: vec![GeneratedFilterCondition::ResponseBodyContains(
                body_fragment.into(),
            )],
            actions: vec![GeneratedFilterAction::Mark(mark.into())],
            notes: Vec::new(),
        }
    }

    pub fn from_rewrite_draft(name: impl Into<String>, draft: GeneratedRewriteDraft) -> Self {
        draft.into_filter(name)
    }

    pub fn builder(name: impl Into<String>, phase: GeneratedFilterPhase) -> GeneratedFilterBuilder {
        GeneratedFilterBuilder::new(name, phase)
    }

    pub fn request(name: impl Into<String>) -> GeneratedFilterBuilder {
        GeneratedFilterBuilder::request(name)
    }

    pub fn response(name: impl Into<String>) -> GeneratedFilterBuilder {
        GeneratedFilterBuilder::response(name)
    }

    pub fn response_status(
        name: impl Into<String>,
        status: u16,
        mark: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            name: name.into(),
            priority: 9000,
            enabled: true,
            phase: GeneratedFilterPhase::Response,
            trigger: GeneratedFilterTrigger::default(),
            conditions: vec![GeneratedFilterCondition::ResponseStatusEq(status)],
            actions: vec![GeneratedFilterAction::Mark(mark.into())],
            notes: Vec::new(),
        }
    }

    pub fn request_path_contains(
        name: impl Into<String>,
        path_fragment: impl Into<String>,
        mark: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            name: name.into(),
            priority: 9000,
            enabled: true,
            phase: GeneratedFilterPhase::Request,
            trigger: GeneratedFilterTrigger::default(),
            conditions: vec![GeneratedFilterCondition::RequestPathContains(
                path_fragment.into(),
            )],
            actions: vec![GeneratedFilterAction::Mark(mark.into())],
            notes: Vec::new(),
        }
    }

    pub fn add_rewrite_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn add_action(&mut self, action: GeneratedFilterAction) {
        self.actions.push(action);
    }

    pub fn extend_actions<I>(&mut self, actions: I)
    where
        I: IntoIterator<Item = GeneratedFilterAction>,
    {
        self.actions.extend(actions);
    }

    pub fn replace_response_body_rewrite_action(
        &mut self,
        action: GeneratedFilterAction,
    ) {
        self.actions.retain(|existing| {
            !matches!(
                    existing,
                    GeneratedFilterAction::SetResponseBodyText { .. }
                        | GeneratedFilterAction::ReplaceResponseBodyText { .. }
                        | GeneratedFilterAction::ReplaceResponseBodyTextOnce { .. }
                        | GeneratedFilterAction::ReplaceResponseBodyTextAll { .. }
                        | GeneratedFilterAction::ReplaceResponseBodyRegex { .. }
                        | GeneratedFilterAction::ReplaceResponseBodyTextWhenContains { .. }
                        | GeneratedFilterAction::ReplaceResponseJsProperty { .. }
                        | GeneratedFilterAction::ReplaceResponseCssDeclaration { .. }
                        | GeneratedFilterAction::ReplaceResponseHtmlAttribute { .. }
                        | GeneratedFilterAction::ApplyResponseJsonPatch { .. }
                )
        });

        self.actions.push(action);
    }

    pub fn replace_request_body_rewrite_action(
        &mut self,
        action: GeneratedFilterAction,
    ) {
        self.actions.retain(|existing| {
            !matches!(
                    existing,
                    GeneratedFilterAction::SetRequestBodyText { .. }
                        | GeneratedFilterAction::ReplaceRequestBodyText { .. }
                        | GeneratedFilterAction::ReplaceRequestBodyTextOnce { .. }
                        | GeneratedFilterAction::ReplaceRequestBodyTextAll { .. }
                        | GeneratedFilterAction::ReplaceRequestBodyRegex { .. }
                        | GeneratedFilterAction::ReplaceRequestBodyTextWhenContains { .. }
                        | GeneratedFilterAction::ReplaceRequestJsProperty { .. }
                        | GeneratedFilterAction::ReplaceRequestCssDeclaration { .. }
                        | GeneratedFilterAction::ReplaceRequestHtmlAttribute { .. }
                        | GeneratedFilterAction::ApplyRequestJsonPatch { .. }
                )
        });

        self.actions.push(action);
    }
    
    pub fn to_roto_source(&self) -> String {
        let mut out = String::new();

        self.write_front_matter(&mut out);
        out.push('\n');
        out.push_str("// Generated by inspect pattern extractor.\n");
        out.push_str("// Move this file to ./filters/ if you want to promote it to a normal filter.\n");

        for note in &self.notes {
            out.push_str("// ");
            out.push_str(note);
            out.push('\n');
        }

        if !self.notes.is_empty() {
            out.push_str("// TODO: convert this draft into concrete rewrite actions when the required Roto APIs are available.\n");
        }

        out.push('\n');
        out.push_str("fn ping() -> bool {\n");
        out.push_str("    true\n");
        out.push_str("}\n\n");

        match self.phase {
            GeneratedFilterPhase::Request => self.write_request_action(&mut out),
            GeneratedFilterPhase::Response => self.write_response_action(&mut out),
        }

        out
    }

    fn write_front_matter(&self, out: &mut String) {
        let phase = self.phase.as_roto_phase();

        writeln!(out, "//! +++").expect("write to String should not fail");
        if let Some(id) = self.id.as_deref() {
            writeln!(out, "//! id = {}", toml_string(id)).expect("write to String should not fail");
        }
        writeln!(out, "//! name = {}", toml_string(&self.name)).expect("write to String should not fail");
        writeln!(out, "//! enabled = {}", self.enabled).expect("write to String should not fail");
        writeln!(out, "//! priority = {}", self.priority).expect("write to String should not fail");
        writeln!(out, "//!").expect("write to String should not fail");
        writeln!(out, "//! [trigger]").expect("write to String should not fail");
        writeln!(out, "//! host = {}", toml_string_array(&self.trigger.host)).expect("write to String should not fail");
        writeln!(out, "//! path = {}", toml_string_array(&self.trigger.path)).expect("write to String should not fail");
        writeln!(out, "//! method = {}", toml_string_array(&self.trigger.method)).expect("write to String should not fail");
        writeln!(out, "//! phase = [{}]", toml_string(phase)).expect("write to String should not fail");
        writeln!(out, "//! +++").expect("write to String should not fail");
    }

    fn write_request_action(&self, out: &mut String) {
        out.push_str("fn request_action(req: Request) -> RequestAction {\n");

        if self.conditions.is_empty() {
            out.push_str("    ");
            self.write_request_action_chain(out);
            out.push('\n');
            out.push_str("}\n");
            return;
        }

        out.push_str("    if ");
        self.write_conditions(out);
        out.push_str(" {\n");
        out.push_str("        ");
        self.write_request_action_chain(out);
        out.push('\n');
        out.push_str("    } else {\n");
        out.push_str("        RequestAction.pass()\n");
        out.push_str("    }\n");
        out.push_str("}\n");
    }

    fn write_response_action(&self, out: &mut String) {
        out.push_str("fn response_action(res: Response) -> ResponseAction {\n");

        if self.conditions.is_empty() {
            out.push_str("    ");
            self.write_response_action_chain(out);
            out.push('\n');
            out.push_str("}\n");
            return;
        }

        out.push_str("    if ");
        self.write_conditions(out);
        out.push_str(" {\n");
        out.push_str("        ");
        self.write_response_action_chain(out);
        out.push('\n');
        out.push_str("    } else {\n");
        out.push_str("        ResponseAction.pass()\n");
        out.push_str("    }\n");
        out.push_str("}\n");
    }

    fn write_conditions(&self, out: &mut String) {
        for (idx, condition) in self.conditions.iter().enumerate() {
            if idx > 0 {
                out.push_str("\n        && ");
            }

            condition.write_roto(out);
        }
    }

    fn write_request_action_chain(&self, out: &mut String) {
        out.push_str("RequestAction.pass()");

        for action in &self.actions {
            action.write_request_roto(out);
        }
    }

    fn write_response_action_chain(&self, out: &mut String) {
        out.push_str("ResponseAction.pass()");

        for action in &self.actions {
            action.write_response_roto(out);
        }
    }
}

impl GeneratedFilterBuilder {
    pub fn new(name: impl Into<String>, phase: GeneratedFilterPhase) -> Self {
        Self {
            name: name.into(),
            priority: 9000,
            enabled: true,
            phase,
            trigger: GeneratedFilterTrigger::default(),
            conditions: Vec::new(),
            actions: Vec::new(),
        }
    }

    pub fn from_selected_text(
        name: impl Into<String>,
        target: GeneratedFilterSelectionTarget,
        selected_text: impl AsRef<str>,
    ) -> Self {
        let phase = target.default_phase();
        Self::new(name, phase).selected_text(target, selected_text)
    }

    pub fn request(name: impl Into<String>) -> Self {
        Self::new(name, GeneratedFilterPhase::Request)
    }

    pub fn response(name: impl Into<String>) -> Self {
        Self::new(name, GeneratedFilterPhase::Response)
    }

    pub fn priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn request_context(
        mut self,
        host: impl Into<String>,
        path: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        self.trigger.host = vec![host.into()];
        self.trigger.path = vec![path.into()];
        self.trigger.method = vec![method.into()];
        self
    }

    pub fn host_trigger(mut self, host: impl Into<String>) -> Self {
        self.trigger.host = vec![host.into()];
        self
    }

    pub fn path_trigger(mut self, path: impl Into<String>) -> Self {
        self.trigger.path = vec![path.into()];
        self
    }

    pub fn method_trigger(mut self, method: impl Into<String>) -> Self {
        self.trigger.method = vec![method.into()];
        self
    }

    pub fn host_triggers<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trigger.host = hosts.into_iter().map(Into::into).collect();
        self
    }

    pub fn path_triggers<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trigger.path = paths.into_iter().map(Into::into).collect();
        self
    }

    pub fn method_triggers<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trigger.method = methods.into_iter().map(Into::into).collect();
        self
    }

    pub fn host_eq(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::RequestHostEq(value.into()));
        self
    }

    pub fn host_contains(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::RequestHostContains(value.into()));
        self
    }

    pub fn path_eq(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::RequestPathEq(value.into()));
        self
    }

    pub fn path_contains(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::RequestPathContains(value.into()));
        self
    }

    pub fn method_eq(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::RequestMethodEq(value.into()));
        self
    }

    pub fn query_contains(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::RequestQueryContains(value.into()));
        self
    }

    pub fn status_eq(mut self, value: u16) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::ResponseStatusEq(value));
        self
    }

    pub fn status_at_least(mut self, value: u16) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::ResponseStatusAtLeast(value));
        self
    }

    pub fn content_type_contains(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::ResponseContentTypeContains(value.into()));
        self
    }

    pub fn body_contains(mut self, value: impl Into<String>) -> Self {
        self.conditions
            .push(GeneratedFilterCondition::ResponseBodyContains(value.into()));
        self
    }

    pub fn body_contains_all<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.conditions
            .push(GeneratedFilterCondition::ResponseBodyContainsAll(
                values.into_iter().map(Into::into).collect(),
            ));
        self
    }

    pub fn selected_text(
        mut self,
        target: GeneratedFilterSelectionTarget,
        selected_text: impl AsRef<str>,
    ) -> Self {
        let Some(selected_text) = normalize_selected_text(selected_text.as_ref()) else {
            return self;
        };

        match target {
            GeneratedFilterSelectionTarget::RequestHost => {
                self.phase = GeneratedFilterPhase::Request;
                self.conditions
                    .push(GeneratedFilterCondition::RequestHostContains(selected_text));
            }
            GeneratedFilterSelectionTarget::RequestPath => {
                self.phase = GeneratedFilterPhase::Request;
                self.conditions
                    .push(GeneratedFilterCondition::RequestPathContains(selected_text));
            }
            GeneratedFilterSelectionTarget::RequestQuery => {
                self.phase = GeneratedFilterPhase::Request;
                self.conditions
                    .push(GeneratedFilterCondition::RequestQueryContains(selected_text));
            }
            GeneratedFilterSelectionTarget::RequestMethod => {
                self.phase = GeneratedFilterPhase::Request;
                self.conditions
                    .push(GeneratedFilterCondition::RequestMethodEq(selected_text));
            }
            GeneratedFilterSelectionTarget::ResponseStatus => {
                self.phase = GeneratedFilterPhase::Response;

                if let Ok(status) = selected_text.parse::<u16>() {
                    self.conditions
                        .push(GeneratedFilterCondition::ResponseStatusEq(status));
                }
            }
            GeneratedFilterSelectionTarget::ResponseContentType => {
                self.phase = GeneratedFilterPhase::Response;
                self.conditions
                    .push(GeneratedFilterCondition::ResponseContentTypeContains(selected_text));
            }
            GeneratedFilterSelectionTarget::ResponseBody => {
                self.phase = GeneratedFilterPhase::Response;
                self.conditions
                    .push(GeneratedFilterCondition::ResponseBodyContains(selected_text));
            }
        }

        self
    }

    pub fn condition(mut self, condition: GeneratedFilterCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn mark(mut self, label: impl Into<String>) -> Self {
        self.actions.push(GeneratedFilterAction::Mark(label.into()));
        self
    }

    pub fn set_request_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::SetRequestHeader {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn remove_request_header(mut self, name: impl Into<String>) -> Self {
        self.actions
            .push(GeneratedFilterAction::RemoveRequestHeader(name.into()));
        self
    }

    pub fn set_request_body_text(
        mut self,
        body: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::SetRequestBodyText {
            body: body.into(),
            content_type: content_type.into(),
        });
        self
    }

    pub fn replace_request_body_text(
        mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceRequestBodyText {
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn replace_request_body_text_once(
        mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceRequestBodyTextOnce {
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn replace_request_body_text_all(
        mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceRequestBodyTextAll {
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn replace_request_body_regex(
        mut self,
        pattern: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceRequestBodyRegex {
            pattern: pattern.into(),
            replacement: replacement.into(),
        });
        self
    }

    pub fn replace_request_body_text_when_contains(
        mut self,
        anchor: impl Into<String>,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceRequestBodyTextWhenContains {
            anchor: anchor.into(),
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn apply_request_json_patch(
        mut self,
        operations: Vec<GeneratedJsonPatchOperation>,
        resulting_body: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ApplyRequestJsonPatch {
            operations,
            resulting_body: resulting_body.into(),
            content_type: content_type.into(),
        });
        self
    }

    pub fn synthetic_response(
        mut self,
        status: u16,
        body: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::SyntheticResponse {
            status,
            body: body.into(),
            content_type: content_type.into(),
        });
        self
    }

    pub fn set_response_status(mut self, status: u16) -> Self {
        self.actions
            .push(GeneratedFilterAction::SetResponseStatus(status));
        self
    }

    pub fn set_response_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::SetResponseHeader {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn remove_response_header(mut self, name: impl Into<String>) -> Self {
        self.actions
            .push(GeneratedFilterAction::RemoveResponseHeader(name.into()));
        self
    }

    pub fn set_response_body_text(
        mut self,
        body: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::SetResponseBodyText {
            body: body.into(),
            content_type: content_type.into(),
        });
        self
    }

    pub fn replace_response_body_text(
        mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceResponseBodyText {
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn replace_response_body_text_once(
        mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceResponseBodyTextOnce {
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn replace_response_body_text_all(
        mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceResponseBodyTextAll {
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn replace_response_body_regex(
        mut self,
        pattern: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceResponseBodyRegex {
            pattern: pattern.into(),
            replacement: replacement.into(),
        });
        self
    }

    pub fn replace_response_body_text_when_contains(
        mut self,
        anchor: impl Into<String>,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ReplaceResponseBodyTextWhenContains {
            anchor: anchor.into(),
            old: old.into(),
            new: new.into(),
        });
        self
    }

    pub fn apply_response_json_patch(
        mut self,
        operations: Vec<GeneratedJsonPatchOperation>,
        resulting_body: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.actions.push(GeneratedFilterAction::ApplyResponseJsonPatch {
            operations,
            resulting_body: resulting_body.into(),
            content_type: content_type.into(),
        });
        self
    }

    pub fn stop(mut self) -> Self {
        self.actions.push(GeneratedFilterAction::Stop);
        self
    }

    pub fn drop(mut self) -> Self {
        self.actions.push(GeneratedFilterAction::Drop);
        self
    }

    pub fn build(mut self) -> GeneratedFilter {
        if self.actions.is_empty() {
            let label = generated_mark_label(&self.name);
            self.actions.push(GeneratedFilterAction::Mark(label));
        }

        GeneratedFilter {
            id: Some(format!("inspect-generated:{}", uuid::Uuid::new_v4())),
            name: self.name,
            priority: self.priority,
            enabled: self.enabled,
            phase: self.phase,
            trigger: self.trigger.normalized(),
            conditions: self.conditions,
            actions: self.actions,
            notes: Vec::new(),
        }
    }
}

impl GeneratedRewriteRequestInput {
    pub fn new(
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            method: method.into(),
            path: path.into(),
            query: query.into(),
            body_text: None,
        }
    }

    pub fn with_body_text(mut self, body_text: impl Into<String>) -> Self {
        self.body_text = Some(body_text.into());
        self
    }

    pub fn has_changes_against(&self, edited: &Self) -> bool {
        self.host != edited.host
            || self.method != edited.method
            || self.path != edited.path
            || self.query != edited.query
            || self.body_text != edited.body_text
    }
}

impl GeneratedRewriteResponseInput {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            content_type: None,
            body_text: None,
        }
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    pub fn with_body_text(mut self, body_text: impl Into<String>) -> Self {
        self.body_text = Some(body_text.into());
        self
    }

    pub fn has_changes_against(&self, edited: &Self) -> bool {
        self.status != edited.status
            || self.content_type != edited.content_type
            || self.body_text != edited.body_text
    }
}

impl GeneratedRewriteExtractor {
    pub fn new(diff_strategy: GeneratedDiffStrategy) -> Self {
        Self { diff_strategy }
    }

    pub fn line_anchor() -> Self {
        Self::new(GeneratedDiffStrategy::LineAnchor)
    }

    pub fn extract_request(
        &self,
        original: GeneratedRewriteRequestInput,
        edited: GeneratedRewriteRequestInput,
    ) -> GeneratedRewriteDraft {
        GeneratedRewriteDraft::Request(GeneratedRewriteRequest {
            host: choose_original_host(&original.host, &edited.host),
            original_method: original.method,
            edited_method: edited.method,
            original_path: original.path,
            edited_path: edited.path,
            original_query: original.query,
            edited_query: edited.query,
            original_body_text: original.body_text,
            edited_body_text: edited.body_text,
            diff_strategy: self.diff_strategy,
        })
    }

    pub fn extract_response(
        &self,
        request: &GeneratedRewriteRequestInput,
        original: GeneratedRewriteResponseInput,
        edited: GeneratedRewriteResponseInput,
    ) -> GeneratedRewriteDraft {
        GeneratedRewriteDraft::Response(GeneratedRewriteResponse {
            host: request.host.clone(),
            request_method: request.method.clone(),
            request_path: request.path.clone(),
            original_status: original.status,
            edited_status: edited.status,
            original_content_type: original.content_type,
            edited_content_type: edited.content_type,
            original_body_text: original.body_text,
            edited_body_text: edited.body_text,
            diff_strategy: self.diff_strategy,
        })
    }

    pub fn request(
        original: GeneratedRewriteRequestInput,
        edited: GeneratedRewriteRequestInput,
    ) -> GeneratedRewriteDraft {
        Self::line_anchor().extract_request(original, edited)
    }

    pub fn response(
        request: &GeneratedRewriteRequestInput,
        original: GeneratedRewriteResponseInput,
        edited: GeneratedRewriteResponseInput,
    ) -> GeneratedRewriteDraft {
        Self::line_anchor().extract_response(request, original, edited)
    }

    pub fn request_filter(
        name: impl Into<String>,
        original: GeneratedRewriteRequestInput,
        edited: GeneratedRewriteRequestInput,
    ) -> GeneratedFilter {
        Self::request(original, edited).into_filter(name)
    }

    pub fn response_filter(
        name: impl Into<String>,
        request: &GeneratedRewriteRequestInput,
        original: GeneratedRewriteResponseInput,
        edited: GeneratedRewriteResponseInput,
    ) -> GeneratedFilter {
        Self::response(request, original, edited).into_filter(name)
    }
}

impl GeneratedRewriteDraft {
    pub fn into_filter(self, name: impl Into<String>) -> GeneratedFilter {
        match self {
            Self::Request(request) => request.into_filter(name),
            Self::Response(response) => response.into_filter(name),
        }
    }

    pub fn has_changes(&self) -> bool {
        match self {
            Self::Request(request) => request.has_changes(),
            Self::Response(response) => response.has_changes(),
        }
    }
}

impl GeneratedRewriteRequest {
    pub fn has_changes(&self) -> bool {
        self.original_method != self.edited_method
            || self.original_path != self.edited_path
            || self.original_query != self.edited_query
            || self.original_body_text != self.edited_body_text
    }

    pub fn into_filter(self, name: impl Into<String>) -> GeneratedFilter {
        let name = name.into();
        let mark = generated_mark_label(&name);

        let original_body_text = self.original_body_text.clone();
        let edited_body_text = self.edited_body_text.clone();

        let mut builder = GeneratedFilterBuilder::request(name)
            .host_trigger(self.host)
            .path_trigger(path_trigger_for_original_path(&self.original_path))
            .method_trigger(self.original_method.clone())
            .path_eq(self.original_path.clone())
            .mark(mark);

        if !self.original_query.is_empty() {
            builder = builder.query_contains(self.original_query.clone());
        }

        if self.original_method != self.edited_method {
            builder = builder.condition(GeneratedFilterCondition::RequestMethodEq(
                self.original_method.clone(),
            ));
        }

        let body_changed = original_body_text != edited_body_text;

        if body_changed
            && let Some(body) = edited_body_text
        {
            builder = builder.set_request_body_text(body, "text/plain; charset=utf-8");
        }

        let mut filter = builder.build();
        filter.add_rewrite_note(format!(
            "request rewrite draft: method {:?} -> {:?}, path {:?} -> {:?}, query {:?} -> {:?}",
            self.original_method,
            self.edited_method,
            self.original_path,
            self.edited_path,
            self.original_query,
            self.edited_query,
        ));

        if self.original_path != self.edited_path {
            filter.add_rewrite_note(
                "request path changed, but set_path() is not exposed in the current Roto API",
            );
        }

        if self.original_query != self.edited_query {
            filter.add_rewrite_note(
                "request query changed, but set_query() is not exposed in the current Roto API",
            );
        }

        if body_changed {
            filter.add_rewrite_note(
                "request body changed; generated set_body_text() uses path/method/query conditions as the match anchor",
            );
        }

        filter
    }
}

impl GeneratedRewriteResponse {
    pub fn has_changes(&self) -> bool {
        self.original_status != self.edited_status
            || self.original_content_type != self.edited_content_type
            || self.original_body_text != self.edited_body_text
    }

    pub fn into_filter(self, name: impl Into<String>) -> GeneratedFilter {
        let name = name.into();
        let mark = generated_mark_label(&name);

        let original_content_type = self.original_content_type.clone();
        let edited_content_type = self.edited_content_type.clone();
        let edited_body_text = self.edited_body_text.clone();

        let mut builder = GeneratedFilterBuilder::response(name)
            .host_trigger(self.host)
            .path_trigger(path_trigger_for_original_path(&self.request_path))
            .method_trigger(self.request_method)
            .status_eq(self.original_status)
            .mark(mark);

        if let Some(content_type) = self.original_content_type.as_deref()
            && !content_type.trim().is_empty()
        {
            builder = builder.content_type_contains(content_type_prefix(content_type));
        }

        if let Some(anchor) = response_body_rewrite_anchor(
            self.original_body_text.as_deref(),
            self.edited_body_text.as_deref(),
            self.diff_strategy,
        ) {
            builder = builder.condition(anchor);
        }

        if self.original_status != self.edited_status {
            builder = builder.set_response_status(self.edited_status);
        }

        if self.original_body_text != self.edited_body_text
            && let Some(body) = edited_body_text
        {
            let content_type = edited_content_type
                .clone()
                .or(original_content_type.clone())
                .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());

            builder = builder.set_response_body_text(body, content_type);
        }

        let mut filter = builder.build();
        filter.add_rewrite_note(format!(
            "response rewrite draft: status {} -> {}, content-type {:?} -> {:?}",
            self.original_status,
            self.edited_status,
            original_content_type,
            edited_content_type,
        ));
        filter
    }
}

impl Default for GeneratedFilterTrigger {
    fn default() -> Self {
        Self {
            host: vec!["*".to_string()],
            path: vec!["*".to_string()],
            method: Vec::new(),
        }
    }
}

impl GeneratedFilterTrigger {
    fn normalized(mut self) -> Self {
        if self.host.is_empty() {
            self.host.push("*".to_string());
        }

        if self.path.is_empty() {
            self.path.push("*".to_string());
        }

        self
    }
}

impl GeneratedFilterPhase {
    fn as_roto_phase(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

impl GeneratedFilterSelectionTarget {
    fn default_phase(self) -> GeneratedFilterPhase {
        match self {
            Self::RequestHost
            | Self::RequestPath
            | Self::RequestQuery
            | Self::RequestMethod => GeneratedFilterPhase::Request,
            Self::ResponseStatus
            | Self::ResponseContentType
            | Self::ResponseBody => GeneratedFilterPhase::Response,
        }
    }
}

impl GeneratedFilterCondition {
    fn write_roto(&self, out: &mut String) {
        match self {
            Self::RequestHostEq(value) => {
                write!(out, "req.host() == {}", roto_string(value)).expect("write to String should not fail");
            }
            Self::RequestHostContains(value) => {
                write!(out, "req.host().contains({})", roto_string(value)).expect("write to String should not fail");
            }
            Self::RequestPathEq(value) => {
                write!(out, "req.path() == {}", roto_string(value)).expect("write to String should not fail");
            }
            Self::RequestPathContains(value) => {
                write!(out, "req.path().contains({})", roto_string(value)).expect("write to String should not fail");
            }
            Self::RequestMethodEq(value) => {
                write!(out, "req.method() == {}", roto_string(value)).expect("write to String should not fail");
            }
            Self::RequestQueryContains(value) => {
                write!(out, "req.query().contains({})", roto_string(value)).expect("write to String should not fail");
            }
            Self::ResponseStatusEq(value) => {
                write!(out, "res.status() == {value}").expect("write to String should not fail");
            }
            Self::ResponseStatusAtLeast(value) => {
                write!(out, "res.status() >= {value}").expect("write to String should not fail");
            }
            Self::ResponseContentTypeContains(value) => {
                write!(out, "res.content_type().contains({})", roto_string(value)).expect("write to String should not fail");
            }
            Self::ResponseBodyContains(value) => {
                write!(out, "res.body_text().contains({})", roto_string(value)).expect("write to String should not fail");
            }
            Self::ResponseBodyContainsAll(values) => {
                if values.is_empty() {
                    out.push_str("true");
                    return;
                }

                for (idx, value) in values.iter().enumerate() {
                    if idx > 0 {
                        out.push_str("\n        && ");
                    }

                    write!(out, "res.body_text().contains({})", roto_string(value))
                        .expect("write to String should not fail");
                }
            }
        }
    }
}

impl GeneratedFilterAction {
    fn write_request_roto(&self, out: &mut String) {
        match self {
            Self::Mark(label) => {
                write!(out, "\n            .mark({})", roto_string(label))
                    .expect("write to String should not fail");
            }
            Self::SetRequestHeader { name, value } => {
                write!(
                    out,
                    "\n            .set_header({}, {})",
                    roto_string(name),
                    roto_string(value),
                )
                    .expect("write to String should not fail");
            }
            Self::RemoveRequestHeader(name) => {
                write!(out, "\n            .remove_header({})", roto_string(name))
                    .expect("write to String should not fail");
            }
            Self::SetRequestBodyText { body, content_type } => {
                write!(
                    out,
                    "\n            .set_body_text({}, {})",
                    roto_string(body),
                    roto_string(content_type),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestBodyText { old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text({}, {})",
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestBodyTextOnce { old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text_once({}, {})",
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestBodyTextAll { old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text_all({}, {})",
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestBodyRegex { pattern, replacement } => {
                write!(
                    out,
                    "\n            .replace_body_regex({}, {})",
                    roto_string(pattern),
                    roto_string(replacement),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestBodyTextWhenContains { anchor, old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text_when_contains({}, {}, {})",
                    roto_string(anchor),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestJsProperty { property, old, new } => {
                write!(
                    out,
                    "\n            .replace_js_property({}, {}, {})",
                    roto_string(property),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestCssDeclaration { property, old, new } => {
                write!(
                    out,
                    "\n            .replace_css_declaration({}, {}, {})",
                    roto_string(property),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceRequestHtmlAttribute {
                selector,
                attribute,
                old,
                new,
            } => {
                write!(
                    out,
                    "\n            .replace_html_attribute({}, {}, {}, {})",
                    roto_string(selector),
                    roto_string(attribute),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ApplyRequestJsonPatch {
                operations,
                resulting_body: _,
                content_type,
            } => {
                write_json_patch_comments(out, operations);
                write!(
                    out,
                    "\n            .apply_json_patch({}, {})",
                    roto_string(&json_patch_operations_to_rfc6902_json(operations)),
                    roto_string(content_type),
                )
                    .expect("write to String should not fail");
            }
            Self::SyntheticResponse {
                status,
                body,
                content_type,
            } => {
                write!(
                    out,
                    "\n            .synthetic_response({}, {}, {})",
                    status,
                    roto_string(body),
                    roto_string(content_type),
                )
                    .expect("write to String should not fail");
            }
            Self::Stop => {
                out.push_str("\n            .stop()");
            }
            Self::Drop => {
                out.push_str("\n            .drop()");
            }
            Self::SetResponseStatus(_)
            | Self::SetResponseHeader { .. }
            | Self::RemoveResponseHeader(_)
            | Self::SetResponseBodyText { .. }
            | Self::ReplaceResponseBodyText { .. }
            | Self::ReplaceResponseBodyTextOnce { .. }
            | Self::ReplaceResponseBodyTextAll { .. }
            | Self::ReplaceResponseBodyRegex { .. }
            | Self::ReplaceResponseBodyTextWhenContains { .. }
            | Self::ReplaceResponseJsProperty { .. }
            | Self::ReplaceResponseCssDeclaration { .. }
            | Self::ReplaceResponseHtmlAttribute { .. }
            | Self::ApplyResponseJsonPatch { .. } => {
                out.push_str("\n            // unsupported response action in request filter");
            }
        }
    }

    fn write_response_roto(&self, out: &mut String) {
        match self {
            Self::Mark(label) => {
                write!(out, "\n            .mark({})", roto_string(label))
                    .expect("write to String should not fail");
            }
            Self::SetResponseStatus(status) => {
                write!(out, "\n            .set_status({status})")
                    .expect("write to String should not fail");
            }
            Self::SetResponseHeader { name, value } => {
                write!(
                    out,
                    "\n            .set_header({}, {})",
                    roto_string(name),
                    roto_string(value),
                )
                    .expect("write to String should not fail");
            }
            Self::RemoveResponseHeader(name) => {
                write!(out, "\n            .remove_header({})", roto_string(name))
                    .expect("write to String should not fail");
            }
            Self::SetResponseBodyText { body, content_type } => {
                write!(
                    out,
                    "\n            .set_body_text({}, {})",
                    roto_string(body),
                    roto_string(content_type),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseBodyText { old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text({}, {})",
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseBodyTextOnce { old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text_once({}, {})",
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseBodyTextAll { old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text_all({}, {})",
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseBodyRegex { pattern, replacement } => {
                write!(
                    out,
                    "\n            .replace_body_regex({}, {})",
                    roto_string(pattern),
                    roto_string(replacement),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseBodyTextWhenContains { anchor, old, new } => {
                write!(
                    out,
                    "\n            .replace_body_text_when_contains({}, {}, {})",
                    roto_string(anchor),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseJsProperty { property, old, new } => {
                write!(
                    out,
                    "\n            .replace_js_property({}, {}, {})",
                    roto_string(property),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseCssDeclaration { property, old, new } => {
                write!(
                    out,
                    "\n            .replace_css_declaration({}, {}, {})",
                    roto_string(property),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ReplaceResponseHtmlAttribute {
                selector,
                attribute,
                old,
                new,
            } => {
                write!(
                    out,
                    "\n            .replace_html_attribute({}, {}, {}, {})",
                    roto_string(selector),
                    roto_string(attribute),
                    roto_string(old),
                    roto_string(new),
                )
                    .expect("write to String should not fail");
            }
            Self::ApplyResponseJsonPatch {
                operations,
                resulting_body: _,
                content_type,
            } => {
                write_json_patch_comments(out, operations);
                write!(
                    out,
                    "\n            .apply_json_patch({}, {})",
                    roto_string(&json_patch_operations_to_rfc6902_json(operations)),
                    roto_string(content_type),
                )
                    .expect("write to String should not fail");
            }
            Self::Stop => {
                out.push_str("\n            .stop()");
            }
            Self::Drop => {
                out.push_str("\n            .drop()");
            }
            Self::SetRequestHeader { .. }
            | Self::RemoveRequestHeader(_)
            | Self::SetRequestBodyText { .. }
            | Self::ReplaceRequestBodyText { .. }
            | Self::ReplaceRequestBodyTextOnce { .. }
            | Self::ReplaceRequestBodyTextAll { .. }
            | Self::ReplaceRequestBodyRegex { .. }
            | Self::ReplaceRequestBodyTextWhenContains { .. }
            | Self::ReplaceRequestJsProperty { .. }
            | Self::ReplaceRequestCssDeclaration { .. }
            | Self::ReplaceRequestHtmlAttribute { .. }
            | Self::ApplyRequestJsonPatch { .. }
            | Self::SyntheticResponse { .. } => {
                out.push_str("\n            // unsupported request action in response filter");
            }
        }
    }
}

fn toml_string_array(values: &[String]) -> String {
    let mut out = String::new();
    out.push('[');

    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }

        out.push_str(&toml_string(value));
    }

    out.push(']');
    out
}

fn toml_string(value: &str) -> String {
    quoted_string(value)
}

fn roto_string(value: &str) -> String {
    quoted_string(value)
}

fn generated_mark_label(name: &str) -> String {
    let slug = slugify_label(name);

    if slug.is_empty() {
        "generated".to_string()
    } else {
        format!("generated-{slug}")
    }
}

fn choose_original_host(original_host: &str, edited_host: &str) -> String {
    if !original_host.trim().is_empty() {
        original_host.to_string()
    } else {
        edited_host.to_string()
    }
}

#[allow(unused)]
fn body_rewrite_anchor(
    original_body_text: Option<&str>,
    edited_body_text: Option<&str>,
    strategy: GeneratedDiffStrategy,
) -> Option<GeneratedFilterCondition> {
    let original = original_body_text?.trim();
    let edited = edited_body_text?.trim();

    if original.is_empty() || original == edited {
        return None;
    }

    diff_anchor(original, edited, strategy)
        .map(|anchor| GeneratedFilterCondition::ResponseBodyContains(anchor.text))
}

fn response_body_rewrite_anchor(
    original_body_text: Option<&str>,
    edited_body_text: Option<&str>,
    strategy: GeneratedDiffStrategy,
) -> Option<GeneratedFilterCondition> {
    let original = original_body_text?.trim();
    let edited = edited_body_text?.trim();

    if original.is_empty() || original == edited {
        return None;
    }

    diff_anchor(original, edited, strategy)
        .map(|anchor| GeneratedFilterCondition::ResponseBodyContains(anchor.text))
}

fn diff_anchor(
    original: &str,
    edited: &str,
    strategy: GeneratedDiffStrategy,
) -> Option<GeneratedDiffAnchor> {
    match strategy {
        GeneratedDiffStrategy::LineAnchor => line_diff_anchor(original, edited),
    }
}

fn line_diff_anchor(original: &str, edited: &str) -> Option<GeneratedDiffAnchor> {
    common_text_anchor(original, edited).map(|text| GeneratedDiffAnchor {
        confidence: if edited.contains(&text) {
            GeneratedDiffConfidence::High
        } else {
            GeneratedDiffConfidence::Low
        },
        source: GeneratedDiffAnchorSource::Line,
        text,
    })
}

fn common_text_anchor(original: &str, edited: &str) -> Option<String> {
    const MIN_ANCHOR_CHARS: usize = 8;
    const MAX_ANCHOR_CHARS: usize = 96;

    for line in original.lines().map(str::trim) {
        if line.chars().count() < MIN_ANCHOR_CHARS {
            continue;
        }

        let anchor = line
            .chars()
            .take(MAX_ANCHOR_CHARS)
            .collect::<String>();

        if edited.contains(&anchor) {
            return Some(anchor);
        }
    }

    let anchor = original
        .chars()
        .take(MAX_ANCHOR_CHARS)
        .collect::<String>();

    if anchor.chars().count() >= MIN_ANCHOR_CHARS {
        Some(anchor)
    } else {
        None
    }
}

fn path_trigger_for_original_path(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return "*".to_string();
    }

    if path.ends_with('/') {
        format!("{path}*")
    } else if let Some((prefix, _)) = path.rsplit_once('/') {
        if prefix.is_empty() {
            "/*".to_string()
        } else {
            format!("{prefix}/*")
        }
    } else {
        "*".to_string()
    }
}

fn content_type_prefix(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_string()
}

fn normalize_selected_text(selected_text: &str) -> Option<String> {
    const MAX_SELECTED_TEXT_CHARS: usize = 4096;

    let selected_text = selected_text.trim();

    if selected_text.is_empty() {
        return None;
    }

    let normalized = selected_text
        .chars()
        .take(MAX_SELECTED_TEXT_CHARS)
        .collect::<String>();

    Some(normalized)
}

fn slugify_label(name: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;

    for ch in name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_was_dash = false;
            continue;
        }

        if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }

    out.trim_matches('-').to_string()
}

fn quoted_string(value: &str) -> String {
    let mut out = String::new();
    out.push('"');

    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                write!(out, "\\u{{{:x}}}", ch as u32).expect("write to String should not fail");
            }
            ch => out.push(ch),
        }
    }

    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_response_body_contains_filter() {
        let filter = GeneratedFilter::response_body_contains(
            "body apple",
            "apple",
            "generated-apple",
        );

        let source = filter.to_roto_source();

        assert!(source.contains("name = \"body apple\""));
        assert!(source.contains("phase = [\"response\"]"));
        assert!(source.contains("fn ping() -> bool"));
        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(source.contains("res.body_text().contains(\"apple\")"));
        assert!(source.contains(".mark(\"generated-apple\")"));
    }

    #[test]
    fn extractor_builds_request_rewrite_draft() {
        let original = GeneratedRewriteRequestInput::new(
            "api.example.com",
            "POST",
            "/v1/users/123",
            "debug=false",
        )
            .with_body_text("{\"name\":\"old\"}");

        let edited = GeneratedRewriteRequestInput::new(
            "api.example.com",
            "POST",
            "/v1/users/123",
            "debug=true",
        )
            .with_body_text("{\"name\":\"new\"}");

        let draft = GeneratedRewriteExtractor::request(original, edited);

        assert!(draft.has_changes());

        let filter = draft.into_filter("rewrite request");
        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"request\"]"));
        assert!(source.contains("host = [\"api.example.com\"]"));
        assert!(source.contains("path = [\"/v1/users/*\"]"));
        assert!(source.contains("method = [\"POST\"]"));
        assert!(source.contains("req.path() == \"/v1/users/123\""));
        assert!(source.contains("req.query().contains(\"debug=false\")"));
        assert!(source.contains("request rewrite draft"));
        assert!(source.contains("set_query() is not exposed"));
    }

    #[test]
    fn extractor_builds_response_rewrite_filter() {
        let request = GeneratedRewriteRequestInput::new(
            "api.example.com",
            "GET",
            "/v1/users/123",
            "",
        );

        let original = GeneratedRewriteResponseInput::new(404)
            .with_content_type("application/json; charset=utf-8")
            .with_body_text("{\"error\":\"not found\",\"id\":123}");

        let edited = GeneratedRewriteResponseInput::new(200)
            .with_content_type("application/json; charset=utf-8")
            .with_body_text("{\"ok\":true,\"id\":123}");

        let filter = GeneratedRewriteExtractor::response_filter(
            "rewrite response",
            &request,
            original,
            edited,
        );

        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"response\"]"));
        assert!(source.contains("host = [\"api.example.com\"]"));
        assert!(source.contains("path = [\"/v1/users/*\"]"));
        assert!(source.contains("method = [\"GET\"]"));
        assert!(source.contains("res.status() == 404"));
        assert!(source.contains("res.content_type().contains(\"application/json\")"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".set_body_text(\"{\\\"ok\\\":true,\\\"id\\\":123}\", \"application/json; charset=utf-8\")"));
    }

    #[test]
    fn rewrite_inputs_detect_no_changes() {
        let original = GeneratedRewriteRequestInput::new(
            "example.com",
            "GET",
            "/",
            "",
        );

        let edited = original.clone();

        assert!(!original.has_changes_against(&edited));

        let draft = GeneratedRewriteExtractor::request(original, edited);

        assert!(!draft.has_changes());
    }

    #[test]
    fn rewrite_request_draft_generates_request_filter() {
        let draft = GeneratedRewriteDraft::Request(GeneratedRewriteRequest {
            host: "api.example.com".to_string(),
            original_method: "POST".to_string(),
            edited_method: "POST".to_string(),
            original_path: "/v1/users/123".to_string(),
            edited_path: "/v1/users/123".to_string(),
            original_query: "debug=false".to_string(),
            edited_query: "debug=true".to_string(),
            original_body_text: Some("{\"name\":\"old\"}".to_string()),
            edited_body_text: Some("{\"name\":\"new\"}".to_string()),
            diff_strategy: GeneratedDiffStrategy::LineAnchor,
        });

        let filter = GeneratedFilter::from_rewrite_draft("rewrite request", draft);
        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"request\"]"));
        assert!(source.contains("host = [\"api.example.com\"]"));
        assert!(source.contains("path = [\"/v1/users/*\"]"));
        assert!(source.contains("method = [\"POST\"]"));
        assert!(source.contains("req.path() == \"/v1/users/123\""));
        assert!(source.contains("req.query().contains(\"debug=false\")"));
        assert!(source.contains("request rewrite draft"));
        assert!(source.contains("request body changed"));
    }

    #[test]
    fn rewrite_response_draft_generates_response_filter() {
        let draft = GeneratedRewriteDraft::Response(GeneratedRewriteResponse {
            host: "api.example.com".to_string(),
            request_method: "GET".to_string(),
            request_path: "/v1/users/123".to_string(),
            original_status: 404,
            edited_status: 200,
            original_content_type: Some("application/json; charset=utf-8".to_string()),
            edited_content_type: Some("application/json; charset=utf-8".to_string()),
            original_body_text: Some("{\"error\":\"not found\",\"id\":123}".to_string()),
            edited_body_text: Some("{\"ok\":true,\"id\":123}".to_string()),
            diff_strategy: GeneratedDiffStrategy::LineAnchor,
        });

        let filter = GeneratedFilter::from_rewrite_draft("rewrite response", draft);
        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"response\"]"));
        assert!(source.contains("host = [\"api.example.com\"]"));
        assert!(source.contains("path = [\"/v1/users/*\"]"));
        assert!(source.contains("method = [\"GET\"]"));
        assert!(source.contains("res.status() == 404"));
        assert!(source.contains("res.content_type().contains(\"application/json\")"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".set_body_text(\"{\\\"ok\\\":true,\\\"id\\\":123}\", \"application/json; charset=utf-8\")"));
        assert!(source.contains("response rewrite draft"));
        assert!(source.contains(".mark(\"generated-rewrite-response\")"));
    }

    #[test]
    fn builder_generates_response_rewrite_actions() {
        let filter = GeneratedFilterBuilder::response("rewrite response")
            .request_context("api.example.com", "/v1/test", "GET")
            .status_eq(500)
            .mark("generated-error")
            .set_response_status(200)
            .set_response_header("x-generated", "true")
            .set_response_body_text("ok\n", "text/plain; charset=utf-8")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("ResponseAction.pass()"));
        assert!(source.contains(".mark(\"generated-error\")"));
        assert!(source.contains(".set_status(200)"));
        assert!(source.contains(".set_header(\"x-generated\", \"true\")"));
        assert!(source.contains(".set_body_text(\"ok\\n\", \"text/plain; charset=utf-8\")"));
    }

    #[test]
    fn builder_generates_request_rewrite_actions() {
        let filter = GeneratedFilterBuilder::request("rewrite request")
            .request_context("api.example.com", "/v1/test", "POST")
            .path_eq("/v1/test")
            .mark("generated-request")
            .set_request_header("x-generated", "true")
            .set_request_body_text("rewritten\n", "text/plain; charset=utf-8")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("RequestAction.pass()"));
        assert!(source.contains(".mark(\"generated-request\")"));
        assert!(source.contains(".set_header(\"x-generated\", \"true\")"));
        assert!(source.contains(".set_body_text(\"rewritten\\n\", \"text/plain; charset=utf-8\")"));
    }

    #[test]
    fn selected_response_body_generates_response_condition() {
        let filter = GeneratedFilterBuilder::from_selected_text(
            "selected body",
            GeneratedFilterSelectionTarget::ResponseBody,
            "permission denied",
        )
            .request_context("api.example.com", "/v1/users/123", "GET")
            .path_trigger("/v1/*")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"response\"]"));
        assert!(source.contains("host = [\"api.example.com\"]"));
        assert!(source.contains("path = [\"/v1/*\"]"));
        assert!(source.contains("method = [\"GET\"]"));
        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(source.contains("res.body_text().contains(\"permission denied\")"));
        assert!(source.contains(".mark(\"generated-selected-body\")"));
    }

    #[test]
    fn selected_request_path_generates_request_condition() {
        let filter = GeneratedFilterBuilder::from_selected_text(
            "selected path",
            GeneratedFilterSelectionTarget::RequestPath,
            "/login",
        )
            .request_context("example.com", "/login", "POST")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"request\"]"));
        assert!(source.contains("fn request_action(req: Request) -> RequestAction"));
        assert!(source.contains("req.path().contains(\"/login\")"));
    }

    #[test]
    fn selected_response_status_generates_status_condition() {
        let filter = GeneratedFilterBuilder::from_selected_text(
            "selected status",
            GeneratedFilterSelectionTarget::ResponseStatus,
            "404",
        )
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"response\"]"));
        assert!(source.contains("res.status() == 404"));
    }

    #[test]
    fn empty_selected_text_is_ignored() {
        let filter = GeneratedFilterBuilder::from_selected_text(
            "empty selection",
            GeneratedFilterSelectionTarget::ResponseBody,
            "   ",
        )
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("fn response_action(res: Response) -> ResponseAction"));
        assert!(!source.contains("contains("));
        assert!(source.contains("ResponseAction.pass()"));
    }

    #[test]
    fn builder_generates_response_filter_from_selected_body() {
        let filter = GeneratedFilterBuilder::response("selected denied body")
            .request_context("api.example.com", "/v1/users/123", "GET")
            .path_trigger("/v1/*")
            .status_eq(403)
            .content_type_contains("json")
            .body_contains("permission denied")
            .mark("generated-denied")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("name = \"selected denied body\""));
        assert!(source.contains("host = [\"api.example.com\"]"));
        assert!(source.contains("path = [\"/v1/*\"]"));
        assert!(source.contains("method = [\"GET\"]"));
        assert!(source.contains("phase = [\"response\"]"));
        assert!(source.contains("res.status() == 403"));
        assert!(source.contains("res.content_type().contains(\"json\")"));
        assert!(source.contains("res.body_text().contains(\"permission denied\")"));
        assert!(source.contains(".mark(\"generated-denied\")"));
    }

    #[test]
    fn builder_generates_request_filter_from_selected_path() {
        let filter = GeneratedFilterBuilder::request("selected login path")
            .request_context("example.com", "/login", "POST")
            .path_contains("/login")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains("host = [\"example.com\"]"));
        assert!(source.contains("path = [\"/login\"]"));
        assert!(source.contains("method = [\"POST\"]"));
        assert!(source.contains("phase = [\"request\"]"));
        assert!(source.contains("fn request_action(req: Request) -> RequestAction"));
        assert!(source.contains("req.path().contains(\"/login\")"));
        assert!(source.contains(".mark(\"generated-selected-login-path\")"));
    }

    #[test]
    fn builder_uses_default_mark_when_mark_is_omitted() {
        let filter = GeneratedFilterBuilder::response("body apple")
            .body_contains("apple")
            .build();

        let source = filter.to_roto_source();

        assert!(source.contains(".mark(\"generated-body-apple\")"));
    }

    #[test]
    fn generates_request_path_contains_filter() {
        let filter = GeneratedFilter::request_path_contains(
            "path login",
            "/login",
            "generated-login",
        );

        let source = filter.to_roto_source();

        assert!(source.contains("phase = [\"request\"]"));
        assert!(source.contains("fn request_action(req: Request) -> RequestAction"));
        assert!(source.contains("req.path().contains(\"/login\")"));
        assert!(source.contains(".mark(\"generated-login\")"));
    }

    #[test]
    fn escapes_strings() {
        let filter = GeneratedFilter::response_body_contains(
            "quote test",
            "a\"b\\c\n",
            "m\"ark",
        );

        let source = filter.to_roto_source();

        assert!(source.contains("res.body_text().contains(\"a\\\"b\\\\c\\n\")"));
        assert!(source.contains(".mark(\"m\\\"ark\")"));
    }

    #[test]
    fn generates_all_body_conditions() {
        let filter = GeneratedFilter {
            id: None,
            name: "all".to_string(),
            priority: 9000,
            enabled: true,
            phase: GeneratedFilterPhase::Response,
            trigger: GeneratedFilterTrigger::default(),
            conditions: vec![GeneratedFilterCondition::ResponseBodyContainsAll(vec![
                "apple".to_string(),
                "banana".to_string(),
            ])],
            actions: vec![GeneratedFilterAction::Mark("fruit".to_string())],
            notes: vec![],
        };

        let source = filter.to_roto_source();

        assert!(source.contains("res.body_text().contains(\"apple\")"));
        assert!(source.contains("res.body_text().contains(\"banana\")"));
    }
}