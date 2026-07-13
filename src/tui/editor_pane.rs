use std::cell::Cell;
use std::io::Read;
use std::rc::Rc;

use tuie::prelude::*;
use chord_macro::chord;
use flate2::read::GzDecoder;
use crate::filters::{EditableFilterSession, EditableFilterSessionPreview, EditableHttpBody, EditableHttpHeader, EditableHttpMessage, EditableHttpMessageKind, FilterManager};
use crate::mitm::capture::CapturePaths;
use crate::tui::PacketRowEditContext;
use crate::tui::tab::{
    DetailEditState,
    DetailMessagePartSelection,
    DetailPrimaryTabSelection,
};
use crate::tui::theme;

struct SaveResultPopup {
    root: Box<Pane>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
}

impl SaveResultPopup {
    fn new(
        title: impl Into<String>,
        message: impl Into<String>,
        popup_id: Rc<Cell<Option<WidgetId>>>,
    ) -> Box<Self> {
        let root = Pane::new()
            .vertical()
            .width(72)
            .height(12)
            .padding(Spacing::balanced(2))
            .gap(1)
            .style(Style::new().bg(theme::popup_bg()))
            .bordered()
            .border_style(Style::new().fg(theme::accent_fg()).bold())
            .children([
                Text::new()
                    .content(title.into().bold()) as Box<dyn Widget>,
                Pane::new()
                    .vertical()
                    .flex(1)
                    .y_scroll(Scrollbar::AutoHide)
                    .children([
                        Text::new()
                            .content(message.into())
                            .overflow(TextOverflow::WRAP) as Box<dyn Widget>,
                    ]) as Box<dyn Widget>,
                Text::new()
                    .content("Enter/Esc/q: OK".fg(theme::muted_fg()).dim())
                    .align(Align::End) as Box<dyn Widget>,
            ]);

        Box::new(Self {
            root,
            popup_id,
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }
}

impl DelegateWidget for SaveResultPopup {
    fn get_delegate(&self) -> &dyn Widget {
        self.root.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.root.as_mut()
    }

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.peek() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(Enter | Esc | q) => {
                queue.next();
                self.close();
                InputResult::Handled
            }
            _ => self.root.on_input(queue),
        }
    }
}

fn open_save_result_popup(
    title: impl Into<String>,
    message: impl Into<String>,
) {
    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));
    let popup = SaveResultPopup::new(title, message, popup_id.clone());
    let id = popup.get_id().untyped();

    popup_id.set(Some(id));

    tuie::open_popup(
        Popup::new(popup)
            .dismissible(),
    );
}

pub struct EditPanel {
    root: Box<Pane>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
    input_id: WidgetId<Input>,
    preview_id: WidgetId<Text>,
    preview_scroll_id: WidgetId<Pane>,
    edited_text: String,
    session: Option<EditableFilterSession>,
    preview: EditableFilterSessionPreview,
}

impl EditPanel {
    fn new(
        row: PacketRowEditContext,
        detail: DetailEditState,
        popup_id: Rc<Cell<Option<WidgetId>>>,
    ) -> Box<Self> {
        let title = row.title();
        let session = editable_session_from_detail(&row, &detail);
        let editable_text = session
            .as_ref()
            .map(|session| session.edited_text().to_string())
            .unwrap_or_else(|| editable_text_from_detail(&row, &detail));
        let preview = session
            .as_ref()
            .map(EditableFilterSession::preview)
            .unwrap_or_else(|| EditableFilterSessionPreview {
                has_changes: false,
                changes_text: "Edit preview is unavailable for this selection.\nSelect request/response meta or body.".to_string(),
                generated_roto: None,
                error: None,
            });
        let preview_text = preview.to_panel_text();

        let mut input_id = WidgetId::EMPTY;
        let mut preview_id = WidgetId::EMPTY;
        let mut preview_scroll_id = WidgetId::EMPTY;

        let terminal = tuie::get_runtime_info().size;
        let popup_height = terminal.y.saturating_sub(4).clamp(12, 40);
        let popup_width = terminal.x.saturating_sub(4).min(112);

        let content = Pane::new()
            .vertical()
            .flex(1)
            .gap(0)
            .style(Style::new().fg(theme::panel_fg()).bg(theme::panel_inner_bg()))
            .children([
                Text::new()
                    .content(format!("{title}    Esc: close  S: save  ^J/^K: scroll  ^Z: undo").fg(theme::panel_fg()).bold())
                    .style(Style::new().bg(theme::panel_inner_bg())) as Box<dyn Widget>,
                Pane::new()
                    .horizontal()
                    .flex(1)
                    .gap(1)
                    .children([
                        Pane::new()
                            .vertical()
                            .flex(1)
                            .bordered()
                            .border_style(Style::new().fg(theme::panel_border_fg()))
                            .style(Style::new().fg(theme::panel_fg()).bg(theme::panel_inner_bg()))
                            .children([
                                Input::new()
                                    .content(editable_text.clone())
                                    .bindings(ModernBindings::new)
                                    .multiline()
                                    .wrap()
                                    .style(Style::new().fg(theme::panel_fg()).bg(theme::panel_inner_bg()))
                                    .id(&mut input_id) as Box<dyn Widget>,
                            ]).y_scroll(Scrollbar::AutoHide) as Box<dyn Widget>,
                        Pane::new()
                            .vertical()
                            .flex(1)
                            .bordered()
                            .border_style(Style::new().fg(theme::panel_border_fg()))
                            .style(Style::new().fg(theme::panel_fg()).bg(theme::panel_inner_bg()))
                            .id(&mut preview_scroll_id)
                            .y_scroll(Scrollbar::AutoHide)
                            .children([
                                Text::new()
                                    .content(preview_text)
                                    .overflow(TextOverflow::WRAP)
                                    .style(Style::new().fg(theme::panel_fg()).bg(theme::panel_inner_bg()))
                                    .id(&mut preview_id) as Box<dyn Widget>,
                            ]) as Box<dyn Widget>,
                    ]) as Box<dyn Widget>,
            ]);

        let root = Pane::new()
            .vertical()
            .width(popup_width)
            .height(popup_height)
            .padding(Spacing::balanced(1))
            .style(Style::new().fg(theme::panel_fg()).bg(theme::panel_outer_bg()))
            .children([
                Pane::new()
                    .vertical()
                    .flex(1)
                    .bordered()
                    .border_style(Style::new().fg(theme::panel_border_fg()).bold())
                    .children([
                        content as Box<dyn Widget>,
                    ]) as Box<dyn Widget>,
            ]);

        Box::new(Self {
            root,
            popup_id,
            input_id,
            preview_id,
            preview_scroll_id,
            edited_text: editable_text,
            session,
            preview,
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn scroll_preview_by(&mut self, delta: i32) {
        if let Some(pane) = self.root.get_widget_mut(self.preview_scroll_id) {
            pane.scroll_by(delta);
        }
        tuie::dirty_layout();
    }

    fn scroll_preview_to(&mut self, progress: f32) {
        if let Some(pane) = self.root.get_widget_mut(self.preview_scroll_id) {
            pane.set_scroll_progress(Axis2D::Y, progress);
        }
        tuie::dirty_layout();
    }

    fn refresh_preview(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.set_edited_text(self.edited_text.clone());
            self.preview = session.preview();
        } else {
            self.preview = EditableFilterSessionPreview {
                has_changes: false,
                changes_text: format!(
                    "Edit preview is unavailable for this selection.\n\nCurrent editable text length: {} bytes",
                    self.edited_text.len(),
                ),
                generated_roto: None,
                error: None,
            };
        }

        if let Some(preview_text) = self.root.get_widget_mut(self.preview_id) {
            preview_text.set_content(self.preview.to_panel_text());
        }

        tuie::dirty_layout();
    }

    fn save_current(&mut self) {
        self.refresh_preview();

        let Some(session) = self.session.as_ref() else {
            open_save_result_popup(
                "Save failed",
                "This selection could not be converted into an editable filter session.",
            );
            return;
        };

        if let Err(err) = session.has_changes() {
            open_save_result_popup(
                "Save failed",
                format!("Could not compute changes:\n\n{err}"),
            );
            return;
        }

        if matches!(session.has_changes(), Ok(false)) {
            open_save_result_popup(
                "Nothing to save",
                "No changes were detected, so no generated filter was written.",
            );
            return;
        }

        let capture_paths = CapturePaths::new();
        let filter_manager = FilterManager::new("./filters")
            .with_filter_dir(capture_paths.generated_filters_dir.clone());

        match session.save_generated(&capture_paths, &filter_manager) {
            Ok(saved) => {
                open_save_result_popup(
                    "Generated filter saved",
                    format!(
                        "Saved generated Roto filter:\n\n{}\n\nFilters were validated and reloaded.",
                        saved.path.display(),
                    ),
                );
            }
            Err(err) => {
                open_save_result_popup(
                    "Save failed",
                    format!(
                        "Failed to save generated filter:\n\n{err}",
                    ),
                );
            }
        }
    }

    pub fn input_id(&self) -> WidgetId<Input> {
        self.input_id
    }
}

pub fn open_edit_popup(row: PacketRowEditContext, detail: DetailEditState) {
    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));

    let panel = EditPanel::new(
        row,
        detail,
        popup_id.clone(),
    );

    let panel_id = panel.get_id().untyped();
    let input_id = panel.input_id().untyped();

    popup_id.set(Some(panel_id));

    tuie::open_popup(
        Popup::new(panel)
            .dismissible(),
    );

    tuie::focus_widget(input_id);
}

fn editable_session_from_detail(
    row: &PacketRowEditContext,
    detail: &DetailEditState,
) -> Option<EditableFilterSession> {
    match detail.selection.primary_tab {
        DetailPrimaryTabSelection::Request => {
            let request = editable_request_from_detail(row, detail);
            Some(EditableFilterSession::Request {
                name: generated_edit_name(row, "request"),
                original: request.clone(),
                edited_text: request.to_edit_text(),
            })
        }
        DetailPrimaryTabSelection::Response => {
            let request_context = editable_request_from_detail(row, detail);
            let response = editable_response_from_detail(row, detail)?;
            Some(EditableFilterSession::Response {
                name: generated_edit_name(row, "response"),
                request_context,
                original: response.clone(),
                edited_text: response.to_edit_text(),
            })
        }
        DetailPrimaryTabSelection::SslTls | DetailPrimaryTabSelection::Info => None,
    }
}

fn editable_request_from_detail(
    row: &PacketRowEditContext,
    detail: &DetailEditState,
) -> EditableHttpMessage {
    let headers = parse_headers_from_meta(&detail.content.request_meta);
    let content_type = content_type_from_headers(&headers);
    let body_text = strip_body_size_header(&detail.content.request_body);

    EditableHttpMessage {
        kind: EditableHttpMessageKind::Request,
        method: Some(row.method.clone()),
        scheme: Some(row.protocol.clone()),
        host: row.host.clone(),
        path: row.uri.clone(),
        query: row.query_str.clone(),
        status: None,
        headers,
        body: editable_body_from_text(body_text, content_type),
    }
}

fn editable_response_from_detail(
    row: &PacketRowEditContext,
    detail: &DetailEditState,
) -> Option<EditableHttpMessage> {
    let headers = parse_headers_from_meta(&detail.content.response_meta);
    let content_type = content_type_from_headers(&headers);
    let body_text = strip_body_size_header(&detail.content.response_body);

    Some(EditableHttpMessage {
        kind: EditableHttpMessageKind::Response,
        method: None,
        scheme: Some(row.protocol.clone()),
        host: row.host.clone(),
        path: row.uri.clone(),
        query: row.query_str.clone(),
        status: row.status,
        headers,
        body: editable_body_from_text(body_text, content_type),
    })
}

fn editable_body_from_text(
    text: String,
    content_type: Option<String>,
) -> EditableHttpBody {
    let body = text.trim();

    if body.is_empty()
        || body.starts_with("<no path>")
        || body.starts_with("<read error:")
    {
        return EditableHttpBody::Empty;
    }

    if let Some(decoded_text) = decode_gzip_hexdump_to_text(body) {
        return EditableHttpBody::Text {
            text: decoded_text,
            content_type,
        };
    }

    if body.starts_with("<binary body detected") || looks_like_hexdump(body) {
        let bytes_len = extract_hexdump_bytes(body)
            .map(|bytes| bytes.len())
            .unwrap_or_else(|| text.len());

        return EditableHttpBody::Binary {
            bytes_len,
            content_type,
        };
    }

    EditableHttpBody::Text {
        text,
        content_type,
    }
}

fn decode_gzip_hexdump_to_text(text: &str) -> Option<String> {
    if !text.contains("magic number: gzip") {
        return None;
    }

    let bytes = extract_hexdump_bytes(text)?;
    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut out = String::new();

    decoder.read_to_string(&mut out).ok()?;
    if out.trim().is_empty() {
        return None;
    }

    Some(out)
}

fn extract_hexdump_bytes(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();

    for line in text.lines() {
        let mut parts = line.split('|');
        let left = parts.next().unwrap_or_default().trim_end();

        let mut iter = left.split_whitespace();
        let Some(offset) = iter.next() else {
            continue;
        };

        if offset.len() != 8 || !offset.chars().all(|ch| ch.is_ascii_hexdigit()) {
            continue;
        }

        for token in iter {
            if token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit())
                && let Ok(byte) = u8::from_str_radix(token, 16) {
                bytes.push(byte);
            }
        }
    }

    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

fn looks_like_hexdump(text: &str) -> bool {
    let mut total_lines = 0usize;
    let mut valid_lines = 0usize;

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }

        total_lines += 1;

        let mut parts = line.split('|');
        let left = parts.next().unwrap_or_default().trim_end();
        let mut iter = left.split_whitespace();

        let Some(offset) = iter.next() else {
            continue;
        };

        if offset.len() != 8 || !offset.chars().all(|ch| ch.is_ascii_hexdigit()) {
            continue;
        }

        let hex_tokens = iter
            .filter(|token| token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
            .count();

        if (1..=16).contains(&hex_tokens) {
            valid_lines += 1;
        }
    }

    total_lines > 0 && valid_lines > 0 && valid_lines * 100 / total_lines >= 80
}

fn parse_headers_from_meta(meta: &str) -> Vec<EditableHttpHeader> {
    let Some(headers_json) = extract_headers_json(meta) else {
        return Vec::new();
    };

    let Ok(value) = serde_json::from_str::<serde_json::Value>(&headers_json) else {
        return Vec::new();
    };

    let mut headers = match value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?.to_string();
                let value = item.get("value")?.as_str()?.to_string();

                Some(EditableHttpHeader { name, value })
            })
            .collect::<Vec<_>>(),
        serde_json::Value::Object(map) => map
            .into_iter()
            .map(|(name, value)| {
                let value = match value {
                    serde_json::Value::String(value) => value,
                    serde_json::Value::Null => String::new(),
                    other => other.to_string(),
                };

                EditableHttpHeader { name, value }
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    headers.sort_by(|left, right| left.name.cmp(&right.name));
    headers
}

fn extract_headers_json(meta: &str) -> Option<String> {
    let headers_line_idx = meta
        .lines()
        .scan(0usize, |offset, line| {
            let start = *offset;
            *offset += line.len() + 1;
            Some((start, line))
        })
        .find_map(|(start, line)| {
            let key = line
                .split_once(':')
                .map(|(key, _)| key.trim())
                .unwrap_or_else(|| line.trim());

            (key == "headers").then_some(start)
        })?;

    let after_headers = &meta[headers_line_idx..];
    let json_start_relative = after_headers
        .find(['[', '{'])?;
    let json_start = headers_line_idx + json_start_relative;
    let text = &meta[json_start..];

    let opening = text.chars().next()?;
    let closing = match opening {
        '[' => ']',
        '{' => '}',
        _ => return None,
    };

    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if in_string {
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            ch if ch == opening => depth += 1,
            ch if ch == closing => {
                depth = depth.saturating_sub(1);

                if depth == 0 {
                    return Some(text[..=idx].to_string());
                }
            }
            _ => {}
        }
    }

    None
}

fn content_type_from_headers(headers: &[EditableHttpHeader]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.clone())
}

fn strip_body_size_header(text: &str) -> String {
    if text.starts_with("body size :")
        && let Some((_, body)) = text.split_once("\n\n")
    {
        body.to_string()
    } else {
        text.to_string()
    }
}

fn generated_edit_name(row: &PacketRowEditContext, phase: &str) -> String {
    let path = row
        .uri
        .trim_matches('/')
        .replace('/', "-");

    if path.is_empty() {
        format!("edit {phase} {}", row.host)
    } else {
        format!("edit {phase} {} {path}", row.host)
    }
}

fn editable_text_from_detail(
    row: &PacketRowEditContext,
    detail: &DetailEditState,
) -> String {
    let selected_body = match detail.selection.primary_tab {
        DetailPrimaryTabSelection::Request => match detail.selection.message_part {
            DetailMessagePartSelection::Meta => &detail.content.request_meta,
            DetailMessagePartSelection::Body => &detail.content.request_body,
        },
        DetailPrimaryTabSelection::Response => match detail.selection.message_part {
            DetailMessagePartSelection::Meta => &detail.content.response_meta,
            DetailMessagePartSelection::Body => &detail.content.response_body,
        },
        DetailPrimaryTabSelection::SslTls | DetailPrimaryTabSelection::Info => "",
    };

    format!(
        "# {}\n# This selection could not be converted into an EditableFilterSession yet.\n\n{}",
        row.title(),
        selected_body,
    )
}

impl DelegateWidget for EditPanel {
    fn get_delegate(&self) -> &dyn Widget {
        self.root.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.root.as_mut()
    }

    fn override_is_focusable(&self) -> bool {
        true
    }

    // fn after_before_layout(&mut self) {
    //     if self.initial_scroll_synced {
    //         return;
    //     }
    //
    //     if let Some(pane) = self.root.get_widget_mut(self.input_scroll_id) {
    //         pane.set_scroll_progress(Axis2D::Y, 0.0);
    //     }
    //
    //     if let Some(pane) = self.root.get_widget_mut(self.preview_scroll_id) {
    //         pane.set_scroll_progress(Axis2D::Y, 0.0);
    //     }
    //
    //     self.initial_scroll_synced = true;
    // }

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.peek() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(Esc) => {
                queue.next();
                self.close();
                InputResult::Handled
            }
            chord!(S | Ctrl + s) => {
                queue.next();
                self.save_current();
                InputResult::Handled
            }
            chord!(Ctrl + j) => {
                queue.next();
                self.scroll_preview_by(4);
                InputResult::Handled
            }
            chord!(Ctrl + k) => {
                queue.next();
                self.scroll_preview_by(-4);
                InputResult::Handled
            }
            chord!(Ctrl + g) => {
                queue.next();
                self.scroll_preview_to(1.0);
                InputResult::Handled
            }
            _ => self.root.on_input(queue),
        }
    }

    fn after_on_event(&mut self, event: &mut WidgetEvent) {
        if let Some(change) = event.get_by::<ChangeEvent<String>>(self.input_id) {
            self.edited_text = change.0.clone();
            self.refresh_preview();
        }
    }
}