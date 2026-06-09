mod read_metadata;
pub mod global_chords;
mod search;
mod button;
mod focus_pane;
mod time;

use std::path::PathBuf;
use crate::{CapturePaths, PacketSummary};

use std::sync::Arc;
use std::time::Duration;
use chord_macro::chord;
use regex::Regex;
use tokio::sync::{
    mpsc::{
        self, UnboundedReceiver, UnboundedSender
    }, watch};
use tuie::prelude::*;
use read_metadata::DbState;
use crate::tui::search::{open_full_text_search_popup, open_search_popup, FullTextMatcher};
pub use crate::tui::time::{TimeDisplayConfig, TimeFormatter};

const MAX_ROWS: usize = 10_000;
const TRIM_ROWS: usize = 1_000;

const DETAIL_PLACEHOLDER_TEXT: &'static str = "Select row and press Enter";


#[derive(Clone, Debug, Default)]
struct PacketRow {
    id: String,
    flow_key: String,
    time: String,
    method: String,
    status: u16,
    host: String,
    uri: String,
    query_str: String,
    line: String,
}

impl PacketRow {
    fn url_text(&self) -> String {
        if self.query_str.is_empty() {
            format!("{}{}", self.host, self.uri)
        } else {
            format!("{}{}?{}", self.host, self.uri, self.query_str)
        }
    }
}

#[derive(Clone, Debug)]
enum SearchCondition {
    UrlContains(String),
    UrlRegex {
        pattern: String,
        regex: Regex,
    },
    Method(String),
    Status(u16),
    StatusClass(u16),
}

#[derive(Clone, Debug)]
struct SearchMatcher {
    conditions: Vec<SearchCondition>,
    label: String,
}

impl SearchMatcher {
    fn parse(query: &str) -> Result<Option<Self>, regex::Error> {
        let query = query.trim();

        if query.is_empty() {
            return Ok(None);
        }

        let mut conditions = Vec::new();

        for raw_part in query.split("&&") {
            let part = raw_part.trim();

            if part.is_empty() {
                continue;
            }

            conditions.push(SearchCondition::parse(part)?);
        }

        if conditions.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            conditions,
            label: query.to_string(),
        }))
    }

    fn matches(&self, row: &PacketRow) -> bool {
        self.conditions
            .iter()
            .all(|condition| condition.matches(row))
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

impl SearchCondition {
    fn parse(part: &str) -> Result<Self, regex::Error> {
        if let Some(value) = part
            .strip_prefix("method:")
            .or_else(|| part.strip_prefix("meth:"))
            .or_else(|| part.strip_prefix("m:"))
        {
            return Ok(Self::Method(value.trim().to_ascii_uppercase()));
        }

        if let Some(value) = part
            .strip_prefix("status:")
            .or_else(|| part.strip_prefix("stat:"))
            .or_else(|| part.strip_prefix("s:"))
        {
            let value = value.trim();

            if let Some(prefix) = value.strip_suffix("xx") {
                if let Ok(class) = prefix.parse::<u16>() {
                    return Ok(Self::StatusClass(class));
                }
            }

            if let Ok(status) = value.parse::<u16>() {
                return Ok(Self::Status(status));
            }

            return Ok(Self::UrlContains(part.to_ascii_lowercase()));
        }

        if let Some(pattern) = part.strip_prefix("re:") {
            let regex = Regex::new(pattern)?;
            return Ok(Self::UrlRegex {
                pattern: pattern.to_string(),
                regex,
            });
        }

        Ok(Self::UrlContains(part.to_ascii_lowercase()))
    }

    fn matches(&self, row: &PacketRow) -> bool {
        match self {
            Self::UrlContains(query) => row
                .url_text()
                .to_ascii_lowercase()
                .contains(query),
            Self::UrlRegex { regex, .. } => regex.is_match(&row.url_text()),
            Self::Method(method) => row.method.eq_ignore_ascii_case(method),
            Self::Status(status) => row.status == *status,
            Self::StatusClass(class) => row.status / 100 == *class,
        }
    }
}

#[derive(Debug)]
pub enum UiEvent {
    ShowDetail {
        text: String,
        highlight_query: Option<String>,
    },
}

#[derive(Clone, Copy, Debug)]
struct RowClicked(pub usize);

#[derive(Clone, Debug)]
struct PacketListContext {
    rows: Vec<PacketRow>,
    selected: usize,
    owner_id: WidgetId<PacketListDelegate>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketListMode {
    Main,
    Search,
}

pub struct PacketListDelegate {
    rows: Vec<PacketRow>,
    search_rows: Vec<PacketRow>,
    mode: PacketListMode,
    main_selected: usize,
    search_selected: usize,
    search_query: String,
    search_matcher: Option<SearchMatcher>,
    search_error: Option<String>,
    selected: usize,
    paused: bool,
    rx: mpsc::UnboundedReceiver<PacketSummary>,
    list: Box<Pane>,
    list_id: WidgetId<List>,
    list_title_id: WidgetId<Text>,
    task: TaskHandle,
    dbstate: Arc<DbState>,
    detail_tx: UnboundedSender<UiEvent>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
    search_requests: Arc<parking_lot::Mutex<Vec<String>>>,
    full_text_select_requests: Arc<parking_lot::Mutex<Vec<(String, String)>>>,
    capture_flows_dir: PathBuf,
    time_formatter: TimeFormatter,
}

impl PacketListDelegate {
    const TICK_INTERVAL: Duration = Duration::from_millis(50);
    const SELECTED_SCROLL_OFF: i32 = 2;
    const WAITING_ROW_TEXT: &'static str = "waiting for packets...";

    pub async fn new(
        rx: mpsc::UnboundedReceiver<PacketSummary>,
        detail_tx: UnboundedSender<UiEvent>,
        time_display: TimeDisplayConfig,
    ) -> Box<Self> {
        let rows = vec![PacketRow {
            id: String::new(),
            flow_key: String::new(),
            time: "".to_string(),
            method: "".to_string(),
            status: 0,
            host: "".to_string(),
            uri: "".to_string(),
            query_str: "".to_string(),
            line: Self::WAITING_ROW_TEXT.to_string(),
        }];

        let selected = 0;
        let row_clicks = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let search_requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let full_text_select_requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let capture_flows_dir = CapturePaths::new().flows_dir;
        let time_formatter = TimeFormatter::new(time_display);

        let mut list_id = WidgetId::EMPTY;
        let mut list_title_id = WidgetId::EMPTY;

        let mut list = List::new()
            .vertical()
            .flex(1)
            .min_height(5)
            .gap(0)
            .scroll(Scrollbar::AutoHide)
            .id(&mut list_id);

        let context = PacketListContext {
            rows: rows.clone(),
            selected,
            owner_id: WidgetId::EMPTY,
            row_clicks: row_clicks.clone(),
        };

        list.set_item_count(context.rows.len());
        list.set_renderer(
            context,
            |ctx: &mut PacketListContext, idx: usize| -> Option<Box<dyn Widget>> {
                let row = ctx.rows.get(idx)?;
                let prefix = if idx == ctx.selected { "> " } else { "  " };
                Some(
                    Text::new()
                        .content(format!("{prefix}{}", row.line))
                        .overflow(TextOverflow::TRUNCATE)
                        .flex(1) as Box<dyn Widget>
                )
            },
        );
        let list = Pane::new()
            .vertical()
            .flex(1)
            .gap(0)
            .children([
                Text::new()
                    .content("Packets".bold())
                    .id(&mut list_title_id) as Box<dyn Widget>,
                list,
            ]);

        let mut this = Box::new(Self {
            rows,
            search_rows: Vec::new(),
            mode: PacketListMode::Main,
            main_selected: selected,
            search_selected: 0,
            search_query: String::new(),
            search_matcher: None,
            search_error: None,
            selected,
            paused: false,
            rx,
            list,
            list_id,
            list_title_id,
            task: TaskHandle::EMPTY,
            dbstate: Arc::new(DbState::new().await.expect("dbstate")),
            detail_tx,
            row_clicks,
            search_requests,
            full_text_select_requests,
            capture_flows_dir,
            time_formatter,
        });

        this.task = tuie::schedule(this.get_id(), Self::TICK_INTERVAL, Self::tick);
        this
    }

    fn tick(&mut self) {
        self.poll_incoming();
        self.task = tuie::schedule(self.get_id(), Self::TICK_INTERVAL, Self::tick);
    }

    fn show_detail(&mut self) {
        let selected_id = self.selected_packet_id().map(str::to_owned);

        if let Some(id) = selected_id {
            self.on_select_packet(id);
        }
    }

    fn move_up(&mut self) {
        let selected = self.current_selected();

        if selected > 0 {
            self.set_current_selected(selected - 1);
            self.sync_list_and_reveal_selected();
        }
    }

    fn move_down(&mut self) {
        let len = self.visible_rows_len();
        let selected = self.current_selected();

        if selected + 1 < len {
            self.set_current_selected(selected + 1);
            self.sync_list_and_reveal_selected();
        }
    }

    fn page_up(&mut self) {
        let old = self.current_selected();
        let selected = old.saturating_sub(20);

        if selected != old {
            self.set_current_selected(selected);
            self.sync_list_and_reveal_selected();
        }
    }

    fn page_down(&mut self) {
        let len = self.visible_rows_len();

        if len == 0 {
            return;
        }

        let old = self.current_selected();
        let selected = (old + 20).min(len - 1);

        if selected != old {
            self.set_current_selected(selected);
            self.sync_list_and_reveal_selected();
        }
    }

    fn jump_to_bottom(&mut self) {
        let len = self.visible_rows_len();

        if len == 0 {
            return;
        }

        self.set_current_selected(len - 1);
        self.sync_list_and_reveal_selected();
    }

    fn poll_incoming(&mut self) {
        let mut changed = false;

        while let Ok(pkt) = self.rx.try_recv() {
            if self.paused {
                continue;
            }

            self.remove_waiting_row_if_needed();

            let display_time = self.time_formatter.format_packet_time(&pkt.time, pkt.epoch_ms);
            let line = format!(
                "{} {:<6} {:<4} {}{}{}",
                display_time,
                pkt.method,
                pkt.status,
                pkt.host,
                pkt.uri,
                if pkt.query_str.is_empty() {
                    String::new()
                } else {
                    format!("?{}", pkt.query_str)
                }
            );

            let row = PacketRow {
                id: pkt.id,
                flow_key: pkt.flow_key,
                time: display_time,
                method: pkt.method,
                status: pkt.status,
                host: pkt.host,
                uri: pkt.uri,
                query_str: pkt.query_str,
                line,
            };

            if self.mode == PacketListMode::Search
                && self
                .search_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.matches(&row))
            {
                self.search_rows.push(row.clone());
            }

            self.rows.push(row);

            changed = true;
        }

        if changed {
            self.trim_rows_if_needed();
            self.clamp_current_selected();
            self.sync_list();
        }
    }

    fn remove_waiting_row_if_needed(&mut self) {
        if self.rows.len() == 1
            && self.rows[0].id.is_empty()
            && self.rows[0].line == Self::WAITING_ROW_TEXT
        {
            self.rows.clear();
            self.search_rows.clear();
            self.main_selected = 0;
            self.search_selected = 0;
            self.selected = 0;
        }
    }

    fn sync_list(&mut self) {
        self.sync_list_title();

        let context = PacketListContext {
            rows: self.visible_rows().to_vec(),
            selected: self.current_selected(),
            owner_id: self.get_id(),
            row_clicks: self.row_clicks.clone(),
        };

        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            list.set_item_count(context.rows.len());
            list.set_renderer(
                context,
                |ctx: &mut PacketListContext, idx: usize| -> Option<Box<dyn Widget>> {
                    let row = ctx.rows.get(idx)?;
                    Some(
                        ClickablePacketRow::new(
                            ctx.owner_id,
                            ctx.row_clicks.clone(),
                            idx,
                            row.line.clone(),
                            idx == ctx.selected,
                        ) as Box<dyn Widget>
                    )
                },
            );
            list.invalidate_all();
        }
    }

    fn sync_list_and_reveal_selected(&mut self) {
        self.sync_list();

        let len = self.visible_rows_len();

        if len == 0 {
            return;
        }

        let selected = self.current_selected().min(len - 1);

        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            list.ensure_visible_scrolloff(selected, Self::SELECTED_SCROLL_OFF);
        }
    }

    fn sync_list_and_follow_tail(&mut self) {
        self.sync_list();

        let len = self.visible_rows_len();

        if len == 0 {
            return;
        }

        let last = len - 1;

        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            list.ensure_visible_scrolloff(last, 2);
        }
    }

    fn trim_rows_if_needed(&mut self) {
        if self.rows.len() <= MAX_ROWS {
            return;
        }

        let drain_count = TRIM_ROWS.min(self.rows.len());
        self.rows.drain(0..drain_count);

        self.main_selected = self.main_selected.saturating_sub(drain_count);

        if self.mode == PacketListMode::Search {
            if let Some(matcher) = self.search_matcher.as_ref() {
                self.search_rows = self
                    .rows
                    .iter()
                    .filter(|row| matcher.matches(row))
                    .cloned()
                    .collect();

                self.search_selected = self.search_selected.min(self.search_rows.len().saturating_sub(1));
            }
        }

        self.clamp_current_selected();
    }

    fn append_system_line(&mut self, line: impl Into<String>) {
        self.rows.push(PacketRow {
            id: String::new(),
            flow_key: String::new(),
            time: "test time".to_string(),
            method: "test method".to_string(),
            status: 0,
            host: "test host".to_string(),
            uri: "test url".to_string(),
            query_str: String::new(),
            line: line.into(),
        });

        self.trim_rows_if_needed();
        self.sync_list();
    }

    fn toggle_pause(&mut self) {
        self.paused = !self.paused;

        if self.paused {
            self.append_system_line("=== paused ===");
        } else {
            self.append_system_line("=== resumed ===");
        }
    }

    fn selected_packet_id(&self) -> Option<&str> {
        self.visible_rows()
            .get(self.current_selected())
            .and_then(|row| {
                if row.id.is_empty() {
                    None
                } else {
                    Some(row.id.as_str())
                }
            })
    }

    fn on_select_packet(&self, id: String) {
        self.on_select_packet_with_highlight(id, None);
    }

    fn on_select_packet_with_highlight(&self, id: String, highlight_query: Option<String>) {
        let db = self.dbstate.clone();
        let detail_tx = self.detail_tx.clone();
        let mut time_formatter = self.time_formatter.clone();

        tokio::spawn(async move {
            let req = db.select_request_by_id(id.clone()).await;
            let res = db.select_response_by_id(id.clone()).await;

            let text = match (req, res) {
                (Ok(mut req), Ok(res)) => {
                    if let Some(epoch_ms) = req.epoch_ms {
                        let raw_time = req.time.as_deref().unwrap_or_default();
                        req.time = Some(time_formatter.format_packet_time(raw_time, epoch_ms));
                    }

                    let req_body = read_body_file(req.request_body_path.as_deref()).await;
                    let res_body = read_body_file(res.response_body_path.as_deref()).await;
                    let dir = req.flow_dir.as_deref().unwrap();
                    format!(
                        "id  : {id}\ndir : {dir}\n\n[request meta]\n{req}\n\n[request body]\n{req_body}\n\n[response meta]\n{res}\n\n[response body]\n{res_body}"
                    )
                }
                (Ok(mut req), Err(e)) => {
                    if let Some(epoch_ms) = req.epoch_ms {
                        let raw_time = req.time.as_deref().unwrap_or_default();
                        req.time = Some(time_formatter.format_packet_time(raw_time, epoch_ms));
                    }

                    let req_body = read_body_file(req.request_body_path.as_deref()).await;
                    let dir = req.flow_dir.as_deref().unwrap();
                    format!(
                        "id  : {id}\ndir : {dir}\n\n[request meta]\n{req}\n\n[request body]\n{req_body}\n\nresponse error: {e}"
                    )
                }
                (Err(e1), Err(e2)) => {
                    format!("id: {id}\n\nrequest error: {e1}\nresponse error: {e2}")
                }
                (Err(e), _) => format!("id: {id}\n\nrequest error: {e}"),
                // (_, Err(e)) => format!("id: {id}\n\nresponse error: {e}"),
            };

            let _ = detail_tx.send(UiEvent::ShowDetail {
                text,
                highlight_query,
            });
        });
    }

    fn select_row(&mut self, idx: usize) {
        if idx < self.visible_rows_len() {
            self.set_current_selected(idx);
            self.sync_list_and_reveal_selected();

            if let Some(id) = self.selected_packet_id().map(str::to_owned) {
                self.on_select_packet(id);
            }
        }
    }

    fn poll_row_clicks(&mut self) {
        let clicked = {
            let mut row_clicks = self.row_clicks.lock();
            std::mem::take(&mut *row_clicks)
        };

        for idx in clicked {
            self.select_row(idx);
        }
    }

    fn visible_rows(&self) -> &[PacketRow] {
        match self.mode {
            PacketListMode::Main => &self.rows,
            PacketListMode::Search => &self.search_rows,
        }
    }

    fn visible_rows_len(&self) -> usize {
        self.visible_rows().len()
    }

    fn current_selected(&self) -> usize {
        match self.mode {
            PacketListMode::Main => self.main_selected,
            PacketListMode::Search => self.search_selected,
        }
    }

    fn set_current_selected(&mut self, selected: usize) {
        match self.mode {
            PacketListMode::Main => {
                self.main_selected = selected;
            }
            PacketListMode::Search => {
                self.search_selected = selected;
            }
        }

        self.selected = selected;
    }

    fn clamp_current_selected(&mut self) {
        let len = self.visible_rows_len();

        if len == 0 {
            self.set_current_selected(0);
            return;
        }

        let selected = self.current_selected().min(len - 1);
        self.set_current_selected(selected);
    }

    fn open_search(&mut self) {
        let search_requests = self.search_requests.clone();

        open_search_popup(move |query| {
            search_requests.lock().push(query);
        });
    }

    fn open_full_text_search(&mut self) {
        let select_requests = self.full_text_select_requests.clone();
        let search_path = self.capture_flows_dir.clone();

        open_full_text_search_popup(search_path, move |flow_key, query| {
            select_requests.lock().push((flow_key, query));
        });
    }

    fn poll_search_requests(&mut self) {
        let requests = {
            let mut search_requests = self.search_requests.lock();
            std::mem::take(&mut *search_requests)
        };

        for query in requests {
            self.search_url(query);
        }
    }

    fn poll_full_text_select_requests(&mut self) {
        let requests = {
            let mut full_text_select_requests = self.full_text_select_requests.lock();
            std::mem::take(&mut *full_text_select_requests)
        };

        for (flow_key, query) in requests {
            self.select_flow_key(&flow_key, Some(query));
        }
    }

    fn reset_detail(&self) {
        let _ = self
            .detail_tx
            .send(UiEvent::ShowDetail {
                text: DETAIL_PLACEHOLDER_TEXT.to_string(),
                highlight_query: None,
            });
    }

    fn search_url(&mut self, query: impl Into<String>) {
        let query = query.into();

        let matcher = match SearchMatcher::parse(&query) {
            Ok(Some(matcher)) => matcher,
            Ok(None) => {
                self.clear_search();
                return;
            }
            Err(err) => {
                self.search_error = Some(format!("invalid regex: {err}"));
                self.append_system_line(format!("=== invalid regex: {err} ==="));
                return;
            }
        };

        self.search_query = matcher.label();
        self.search_rows = self
            .rows
            .iter()
            .filter(|row| matcher.matches(row))
            .cloned()
            .collect();

        self.search_matcher = Some(matcher);
        self.search_error = None;
        self.mode = PacketListMode::Search;
        self.search_selected = 0;
        self.clamp_current_selected();
        self.sync_list_and_reveal_selected();
        self.reset_detail();
    }

    fn clear_search(&mut self) {
        self.mode = PacketListMode::Main;
        self.search_query.clear();
        self.search_matcher = None;
        self.search_error = None;
        self.search_rows.clear();
        self.clamp_current_selected();
        self.sync_list_and_reveal_selected();
        self.reset_detail();
    }

    fn list_title(&self) -> StyledString {
        match self.mode {
            PacketListMode::Main => {
                StyledString::new()
                    .span("Packets".bold())
                    .span(format!(" ({})", self.rows.len()).dim())
            }
            PacketListMode::Search => {
                StyledString::new()
                    .span("Packets".bold())
                    .span(" [filter: ".fg(Color::YELLOW))
                    .span(self.search_query.clone().fg(Color::YELLOW).bold())
                    .span("]".fg(Color::YELLOW))
                    .span(format!(" {}/{}", self.search_rows.len(), self.rows.len()).dim())
            }
        }
    }

    fn sync_list_title(&mut self) {
        let title = self.list_title();

        if let Some(text) = self.list.get_widget_mut(self.list_title_id) {
            text.set_content(title);
        }
    }

    fn select_flow_key(&mut self, flow_key: &str, highlight_query: Option<String>) {
        let Some(idx) = self
            .rows
            .iter()
            .position(|row| row.flow_key == flow_key)
        else {
            self.append_system_line(format!("=== search result not found in packet list: {flow_key} ==="));
            return;
        };

        self.mode = PacketListMode::Main;
        self.search_rows.clear();
        self.search_query.clear();
        self.search_matcher = None;
        self.search_error = None;

        self.main_selected = idx;
        self.selected = idx;
        self.sync_list_and_reveal_selected();

        if let Some(id) = self.selected_packet_id().map(str::to_owned) {
            self.on_select_packet_with_highlight(id, highlight_query);
        }
    }
}

async fn read_body_file(path: Option<&str>) -> String {
    let Some(path) = path else {
        return "<no path>".to_string();
    };

    match tokio::fs::read(path).await {
        Ok(bytes) => format_body_for_display(&bytes),
        Err(e) => format!("<read error: {e}>"),
    }
}

fn format_body_for_display(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    hexdump_with_ascii(bytes)
}

fn hexdump_with_ascii(bytes: &[u8]) -> String {
    const WIDTH: usize = 16;
    let mut out = String::new();

    for (line, chunk) in bytes.chunks(WIDTH).enumerate() {
        let offset = line * WIDTH;
        out.push_str(&format!("{offset:08x}  "));
        for i in 0..WIDTH {
            if i < chunk.len() {
                out.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                out.push_str("   ");
            }
            if i == 7 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for &b in chunk {
            let ch = match b {
                0x20..=0x7e => b as char, // printable ASCII
                _ => '.',
            };
            out.push(ch);
        }
        for _ in chunk.len()..WIDTH {
            out.push(' ');
        }
        out.push('|');
        if offset + chunk.len() < bytes.len() {
            out.push('\n');
        }
    }
    out
}

impl DelegateWidget for PacketListDelegate {
    fn get_delegate(&self) -> &dyn Widget {
        self.list.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.poll_incoming();
        self.poll_row_clicks();
        self.poll_search_requests();
        self.poll_full_text_select_requests();
        self.list.as_mut()
    }

    fn override_is_focusable(&self) -> bool {
        true
    }

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        self.poll_incoming();

        let Some(event) = queue.peek() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(LeftClick) => {
                tuie::focus_widget(self.get_id());
                return InputResult::Rejected
            }
            // search filter shortcut
            chord!(Char('s')) if queue.is_unhandled() => {
                queue.next();
                self.open_search();
                return InputResult::Handled;
            }
            // global search shortcut
            chord!(Char('g')) if queue.is_unhandled() => {
                queue.next();
                self.open_full_text_search();
                return InputResult::Handled;
            }
            chord!(Esc) if self.mode == PacketListMode::Search => {
                queue.next();
                self.clear_search();
                tuie::dirty_layout();
                return InputResult::Handled;
            }
            chord!(Enter|l) => {
                queue.next();
                self.show_detail();
                return InputResult::Handled;
            }
            chord!(Up|k) => {
                queue.next();
                self.move_up();
            }
            chord!(Down|j) => {
                queue.next();
                self.move_down();
            }
            chord!(Shift+Up|K) => {
                queue.next();
                self.page_up();
            }
            chord!(Shift+Down|J) => {
                queue.next();
                self.page_down();
            }
            chord!(G) => {
                queue.next();
                self.jump_to_bottom();
            }
            _ => return InputResult::Rejected,
        }
        self.show_detail();
        InputResult::Handled
    }

    fn after_on_input(&mut self, _result: InputResult) {
        self.poll_row_clicks();
    }
}

struct RootPane {
    split: Box<Pane>,
    detail_rx: UnboundedReceiver<UiEvent>,
    detail_text_id: WidgetId<Text>,
}

impl RootPane {
    fn new(
        split: Box<Pane>,
        detail_rx: UnboundedReceiver<UiEvent>,
        detail_text_id: WidgetId<Text>,
    ) -> Box<Self> {
        Box::new(Self {
            split,
            detail_rx,
            detail_text_id,
        })
    }

    fn poll_ui_events(&mut self) {
        while let Ok(event) = self.detail_rx.try_recv() {
            match event {
                UiEvent::ShowDetail {
                    text,
                    highlight_query,
                } => {
                    if let Some(detail) = self.split.get_widget_mut(self.detail_text_id) {
                        if let Some(query) = highlight_query {
                            detail.set_content(highlight_detail_text(&text, &query));
                        } else {
                            detail.set_content(text);
                        }
                    }
                }
            }
        }
    }
}

fn highlight_detail_text(text: &str, query: &str) -> StyledString {
    let Some(matcher) = FullTextMatcher::parse(query) else {
        return StyledString::new().span(text.dim());
    };

    let mut styled = StyledString::new();

    for line in text.split_inclusive('\n') {
        let line_without_newline = line.strip_suffix('\n').unwrap_or(line);
        let has_newline = line.ends_with('\n');

        let ranges = matcher.find_all_in_line(line_without_newline);

        if ranges.is_empty() {
            styled = styled.span(line_without_newline.dim());
        } else {
            let mut cursor = 0;

            for range in ranges {
                if cursor < range.start {
                    styled = styled.span(line_without_newline[cursor..range.start].dim());
                }

                styled = styled.span(
                    line_without_newline[range.start..range.end]
                        .to_string()
                        .fg(Color::BLACK)
                        .bg(Color::YELLOW)
                        .bold(),
                );

                cursor = range.end;
            }

            if cursor < line_without_newline.len() {
                styled = styled.span(line_without_newline[cursor..].dim());
            }
        }

        if has_newline {
            styled = styled.span("\n".dim());
        }
    }

    styled
}

impl DelegateWidget for RootPane {
    fn get_delegate(&self) -> &dyn Widget {
        self.split.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.poll_ui_events();
        self.split.as_mut()
    }

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        self.poll_ui_events();
        InputResult::Rejected
    }
}

struct ClickablePacketRow {
    layout: Layout,
    owner_id: WidgetId<PacketListDelegate>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
    idx: usize,
    text: String,
    selected: bool,
    pressed: std::cell::Cell<bool>,
}
impl ClickablePacketRow {
    fn new(
        owner_id: WidgetId<PacketListDelegate>,
        row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
        idx: usize,
        text: String,
        selected: bool,
    ) -> Box<Self> {
        Box::new(Self {
            layout: Layout::new(),
            owner_id,
            row_clicks,
            idx,
            text,
            selected,
            pressed: std::cell::Cell::new(false),
        })
    }

    fn hit(&self, pos: Vec2<i32>) -> bool {
        let size = self.get_rect_size();
        pos.x >= 0 && pos.y >= 0 && pos.x < size.x as i32 && pos.y < size.y as i32
    }
}

impl Widget for ClickablePacketRow {
    fn get_layout(&self) -> &Layout {
        &self.layout
    }

    fn get_layout_mut(&mut self) -> &mut Layout {
        &mut self.layout
    }

    fn get_name(&self) -> &'static str {
        "ClickablePacketRow"
    }

    fn render(&self, mut ctx: RenderContext) {
        ctx.clear();
        let prefix = if self.selected { "> " } else { "  " };
        write!(ctx, "{}{}", prefix, self.text);
    }

    fn measure_constraints(&mut self) -> Constraints {
        let margin = self.layout.get_margin_total();
        let h = 1 + margin.y;
        Constraints {
            min_size: Vec2::new(0, h),
            max_size: Vec2::new(u16::MAX, h),
            preferred_size: Vec2::new(16, h),
        }
    }

    fn on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.next() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(LeftClick) => {
                if self.hit(event.mouse_pos) {
                    tuie::focus_widget(self.owner_id);
                    self.row_clicks.lock().push(self.idx);
                    return InputResult::Handled;
                }
                InputResult::Rejected
            }
            chord!(LeftRelease) => {
                let was_pressed = self.pressed.get();
                self.pressed.set(false);
                if was_pressed && self.hit(event.mouse_pos) {
                    tuie::emit(self.owner_id, RowClicked(self.idx));
                    return InputResult::Handled;
                }
                InputResult::Rejected
            }
            _ => InputResult::Rejected,
        }
    }
}

pub async fn run_tui(
    rx: UnboundedReceiver<PacketSummary>,
    quit_tx: watch::Sender<bool>,
    time_display: TimeDisplayConfig,
) -> anyhow::Result<()> {
    let (detail_tx, detail_rx) = mpsc::unbounded_channel::<UiEvent>();

    let app: Box<dyn Widget> = PacketListDelegate::new(rx, detail_tx, time_display).await;

    let mut detail_text_id = WidgetId::EMPTY;
    let split = Pane::new()
        .vertical()
        .flex(1)
        .gap(0)
        .children([Split::new(
            SplitPane::horizontal()
                .children([
                    SplitPaneChild::from(Pane::new()
                        .preferred_width(60)
                        .preferred_height(1)
                        .vertical()
                        .flex(1)
                        .children([
                            app
                        ])).title("Inspect"),
                    SplitPaneChild::from(Pane::new()
                        .preferred_width(40)
                        .preferred_height(1)
                        .vertical()
                        .flex(1)
                        .children([
                            Text::new()
                                .content(DETAIL_PLACEHOLDER_TEXT.dim())
                                .overflow(TextOverflow::WRAP)
                                .id(&mut detail_text_id).flex(1),
                        ])
                        .y_scroll(Scrollbar::Visible),
                    ),
                ])
            ).flex(1)
            .border(Border::ROUND)
            .border_style(Style::new().fg(Color::grey256(8)))
        ]);

    let mut tx_opt = Some(quit_tx);
    let _quit_hook = tuie::on_quit(move |_| {
        if let Some(tx) = tx_opt.take() {
            let _ = tx.send(true);
        }
    });

    let root = RootPane::new(split, detail_rx, detail_text_id);
    let root = global_chords::GlobalChords::new(root);

    tuie::start_tui(root)?;

    Ok(())
}
