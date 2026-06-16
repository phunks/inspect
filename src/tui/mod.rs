mod read_metadata;
mod global_chords;
mod search;
mod button;
mod focus_pane;
pub mod time;
pub mod tab;
mod segmented_control;

use std::collections::HashMap;
use std::path::PathBuf;
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
use crate::tui::search::{open_full_text_search_popup, open_search_popup, FullTextMatcher, FullTextSearchResult};
use crate::tui::time::{TimeDisplayConfig, TimeFormatter};
use crate::mitm::proxy::{PacketCompleted, PacketEvent, PacketStarted};
use crate::mitm::capture::CapturePaths;
use crate::tui::read_metadata::PacketSummary;
use crate::tui::tab::{DetailContent, DetailMessagePartSelection, DetailMessageTypeSelection, DetailPane, DetailTabSelection};

const MAX_ROWS: usize = 10_000;
const TRIM_ROWS: usize = 1_000;
const DETAIL_PLACEHOLDER_TEXT: &str = "Select row and press Enter";
pub const TUI_EVENT_BUFFER: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuiMode {
    Capture,
    Viewer,
}

#[derive(Clone, Debug, Default)]
struct PacketRow {
    id: String,
    seq: u64,
    flow_key: String,
    time: String,
    method: String,
    status: Option<u16>,
    elapsed_ms: Option<i64>,
    protocol: String,
    host: String,
    uri: String,
    query_str: String,
    line: Arc<str>,
}

impl PacketRow {
    fn url_text(&self) -> String {
        let scheme = if self.protocol.is_empty() {
            String::new()
        } else {
            format!("{}://", self.protocol)
        };

        if self.query_str.is_empty() {
            format!("{}{}{}", scheme, self.host, self.uri)
        } else {
            format!("{}{}{}?{}", scheme, self.host, self.uri, self.query_str)
        }
    }

    fn refresh_line(&mut self) {
        let status = self
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "----".to_string());

        let elapsed = self
            .elapsed_ms
            .map(|ms| format!("{ms:>5}ms"))
            .unwrap_or_else(|| "       ".to_string());

        let query_suffix = if self.query_str.is_empty() {
            String::new()
        } else {
            format!("?{}", self.query_str)
        };

        self.line = format!(
            "#{:06} {} {:<6} {:<4} {} {}://{}{}{}",
            self.seq,
            self.time,
            self.method,
            status,
            elapsed,
            self.protocol,
            self.host,
            self.uri,
            query_suffix,
        )
            .into();
    }
}

#[derive(Clone, Debug)]
enum SearchCondition {
    Not(Box<SearchCondition>),
    Any(Vec<SearchCondition>),
    UrlContains(String),
    UrlRegex {
        _pattern: String,
        regex: Regex,
    },
    Method(String),
    MethodAny(Vec<String>),
    Status(u16),
    StatusClass(u16),
    NoStatus,
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

    fn label(&self) -> &str {
        &self.label
    }
}

impl SearchCondition {
    fn parse(part: &str) -> Result<Self, regex::Error> {
        let part = part.trim();

        if let Some(rest) = part.strip_prefix('!') {
            return Ok(Self::Not(Box::new(Self::parse(rest.trim())?)));
        }

        if let Some(value) = part
            .strip_prefix("method:")
            .or_else(|| part.strip_prefix("meth:"))
            .or_else(|| part.strip_prefix("m:"))
        {
            let methods = split_csv_values(value)
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect::<Vec<_>>();

            if methods.len() == 1 {
                return Ok(Self::Method(methods.into_iter().next().unwrap()));
            }

            return Ok(Self::MethodAny(methods));
        }

        if let Some(value) = part
            .strip_prefix("status:")
            .or_else(|| part.strip_prefix("stat:"))
            .or_else(|| part.strip_prefix("s:"))
        {
            let values = split_csv_values(value);

            if values.len() == 1 {
                return Ok(Self::parse_status_value(&values[0], part));
            }

            return Ok(Self::Any(
                values
                    .into_iter()
                    .map(|value| Self::parse_status_value(&value, part))
                    .collect(),
            ));
        }

        if let Some(pattern) = part.strip_prefix("re:") {
            let regex = Regex::new(pattern)?;
            return Ok(Self::UrlRegex {
                _pattern: pattern.to_string(),
                regex,
            });
        }

        Ok(Self::UrlContains(part.to_ascii_lowercase()))
    }

    fn parse_status_value(value: &str, original_part: &str) -> Self {
        let value = value.trim();

        if value == "-" || value == "----" || value.eq_ignore_ascii_case("none") {
            return Self::NoStatus;
        }

        if let Some(prefix) = value.strip_suffix("xx")
            && let Ok(class) = prefix.parse::<u16>() {
            return Self::StatusClass(class);
        };

        if let Ok(status) = value.parse::<u16>() {
            return Self::Status(status);
        }

        Self::UrlContains(original_part.to_ascii_lowercase())
    }

    fn matches(&self, row: &PacketRow) -> bool {
        match self {
            Self::Not(condition) => !condition.matches(row),
            Self::Any(conditions) => conditions
                .iter()
                .any(|condition| condition.matches(row)),
            Self::UrlContains(query) => row
                .url_text()
                .to_ascii_lowercase()
                .contains(query),
            Self::UrlRegex { regex, .. } => regex.is_match(&row.url_text()),
            Self::Method(method) => row.method.eq_ignore_ascii_case(method),
            Self::MethodAny(methods) => methods
                .iter()
                .any(|method| row.method.eq_ignore_ascii_case(method)),
            Self::Status(status) => row.status == Some(*status),
            Self::StatusClass(class) => row
                .status
                .is_some_and(|status| status / 100 == *class),
            Self::NoStatus => row.status.is_none(),
        }
    }
}

fn split_csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Debug)]
pub enum UiEvent {
    ShowDetail {
        detail: DetailContent,
        highlight_query: Option<String>,
        tab_selection: Option<DetailTabSelection>,
    },
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct RowClicked(usize);

#[derive(Clone, Debug)]
struct PacketListItem {
    _row_index: usize,
    line: Arc<str>,
}

#[derive(Clone, Debug)]
struct PacketListContext {
    items: Arc<[PacketListItem]>,
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
    search_indices: Vec<usize>,
    mode: PacketListMode,
    _tui_mode: TuiMode,
    main_selected: usize,
    search_selected: usize,
    search_query: String,
    search_matcher: Option<SearchMatcher>,
    search_error: Option<String>,
    selected: usize,
    rx: mpsc::Receiver<PacketEvent>,
    list: Box<Pane>,
    list_id: WidgetId<List>,
    list_title_id: WidgetId<Text>,
    task: TaskHandle,
    dbstate: Arc<DbState>,
    detail_tx: UnboundedSender<UiEvent>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
    search_requests: Arc<parking_lot::Mutex<Vec<String>>>,
    full_text_select_requests: Arc<parking_lot::Mutex<Vec<FullTextSelectRequest>>>,
    search_history: Arc<parking_lot::Mutex<Vec<String>>>,
    full_text_search_history: Arc<parking_lot::Mutex<Vec<String>>>,
    retained_full_text_results: Vec<FullTextSearchResult>,
    retained_full_text_selected: Option<usize>,
    retained_full_text_query: Option<String>,
    capture_flows_dir: PathBuf,
    time_formatter: TimeFormatter,
    id_to_row_index: HashMap<String, usize>,
}

#[derive(Clone, Debug)]
struct FullTextSelectRequest {
    results: Vec<FullTextSearchResult>,
    selected: usize,
    query: String,
}

fn detail_tab_selection_from_search_path(path: &str) -> Option<DetailTabSelection> {
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);

    let message_type = if file_name.starts_with("request.") {
        DetailMessageTypeSelection::Request
    } else if file_name.starts_with("response.") {
        DetailMessageTypeSelection::Response
    } else {
        return None;
    };

    let message_part = if file_name.ends_with(".body") {
        DetailMessagePartSelection::Body
    } else {
        DetailMessagePartSelection::Meta
    };

    Some(DetailTabSelection {
        message_type,
        message_part,
    })
}

impl PacketListDelegate {
    const TICK_INTERVAL: Duration = Duration::from_millis(50);
    const SELECTED_SCROLL_OFF: u16 = 2;
    const WAITING_ROW_TEXT: &'static str = "waiting for packets...";

    pub async fn new(
        rx: mpsc::Receiver<PacketEvent>,
        detail_tx: UnboundedSender<UiEvent>,
        time_display: TimeDisplayConfig,
        tui_mode: TuiMode,
    ) -> Box<Self> {
        let row_clicks = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let search_requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let full_text_select_requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let search_history = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let full_text_search_history = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let capture_flows_dir = CapturePaths::new().flows_dir;
        let mut time_formatter = TimeFormatter::new(time_display);
        let dbstate = Arc::new(DbState::new().await.expect("dbstate"));

        let rows = match dbstate.select_packet_summaries().await {
            Ok(summaries) if !summaries.is_empty() => summaries
                .into_iter()
                .map(|summary| Self::row_from_summary(summary, &mut time_formatter))
                .collect(),
            Ok(_) | Err(_) => vec![PacketRow {
                id: String::new(),
                seq: 0,
                flow_key: String::new(),
                time: String::new(),
                method: String::new(),
                status: None,
                elapsed_ms: None,
                protocol: String::new(),
                host: String::new(),
                uri: String::new(),
                query_str: String::new(),
                line: Arc::<str>::from(Self::WAITING_ROW_TEXT),
            }],
        };

        let selected = match tui_mode {
            TuiMode::Capture => rows.len().saturating_sub(1),
            TuiMode::Viewer => 0,
        };
        let id_to_row_index = rows
            .iter()
            .enumerate()
            .filter_map(|(idx, row)| {
                if row.id.is_empty() {
                    None
                } else {
                    Some((row.id.clone(), idx))
                }
            })
            .collect();

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
            items: rows
                .iter()
                .enumerate()
                .map(|(row_index, row)| PacketListItem {
                    _row_index: row_index,
                    line: row.line.clone(),
                })
                .collect::<Vec<_>>()
                .into(),
            selected,
            owner_id: WidgetId::EMPTY,
            row_clicks: row_clicks.clone(),
        };

        list.set_item_count(context.items.len());
        list.set_renderer(
            context,
            |ctx: &mut PacketListContext, idx: usize| -> Option<Box<dyn Widget>> {
                let item = ctx.items.get(idx)?;
                Some(
                    ClickablePacketRow::new(
                        ctx.owner_id,
                        ctx.row_clicks.clone(),
                        idx,
                        item.line.clone(),
                        idx == ctx.selected,
                    ) as Box<dyn Widget>
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
            search_indices: Vec::new(),
            mode: PacketListMode::Main,
            _tui_mode: tui_mode,
            main_selected: selected,
            search_selected: 0,
            search_query: String::new(),
            search_matcher: None,
            search_error: None,
            selected,
            rx,
            list,
            list_id,
            list_title_id,
            task: TaskHandle::EMPTY,
            dbstate,
            detail_tx,
            row_clicks,
            search_requests,
            full_text_select_requests,
            search_history,
            full_text_search_history,
            retained_full_text_results: Vec::new(),
            retained_full_text_selected: None,
            retained_full_text_query: None,
            capture_flows_dir,
            time_formatter,
            id_to_row_index,
        });

        this.sync_list_and_reveal_selected();
        this.task = tuie::schedule(this.get_id(), Self::TICK_INTERVAL, Self::tick);
        this
    }

    fn row_from_summary(summary: PacketSummary, time_formatter: &mut TimeFormatter) -> PacketRow {
        let raw_time = summary.time.as_deref().unwrap_or_default();
        let display_time = if let Some(epoch_ms) = summary.epoch_ms {
            time_formatter.format_packet_time(raw_time, epoch_ms)
        } else {
            raw_time.to_string()
        };

        let mut row = PacketRow {
            id: summary.id,
            seq: summary.seq.max(0) as u64,
            flow_key: summary.flow_key,
            time: display_time,
            method: summary.method.unwrap_or_default(),
            status: summary.status.map(|status| status as u16),
            elapsed_ms: summary.elapsed,
            protocol: summary.protocol.unwrap_or_default(),
            host: summary.host.unwrap_or_default(),
            uri: summary.uri.unwrap_or_default(),
            query_str: summary.query_str.unwrap_or_default(),
            line: Arc::<str>::from(""),
        };

        row.refresh_line();
        row
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

    fn is_list_at_bottom(&self) -> bool {
        // if self.selected == 0 && self.list
        //     .get_widget(self.list_id)
        //     .map(|list| {
        //         list.get_scroll_ratio(Axis2D::Y) == 1.0})
        //     .unwrap_or(true) {
        //     return true;
        // }
        // let visible = self.list
        //     .get_widget(self.list_id).map(|list|list.get_scroll_ratio(Axis2D::Y));
        //
        // debug!("is_list_at_bottom: {:?}", visible);

        self.list
            .get_widget(self.list_id)
            .map(|list| {
                list.get_scroll_ratio(Axis2D::Y) >= 1.0
                    || list.get_scroll_progress(Axis2D::Y) >= 0.999
            })
            .unwrap_or(true)
    }

    fn follow_list_bottom(&mut self) {
        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            list.set_scroll_progress(Axis2D::Y, 1.0);
        }
    }

    fn poll_incoming(&mut self) {
        let mut changed = false;
        let was_at_bottom = self.is_list_at_bottom();

        while let Ok(event) = self.rx.try_recv() {
            self.remove_waiting_row_if_needed();

            match event {
                PacketEvent::Started(pkt) => {
                    self.on_packet_started(pkt);
                }
                PacketEvent::Completed(pkt) => {
                    self.on_packet_completed(pkt);
                }
            }

            changed = true;
        }

        if changed {
            self.trim_rows_if_needed();
            self.clamp_current_selected();
            self.sync_list();

            if was_at_bottom {
                self.follow_list_bottom();
            }
        }
    }

    fn on_packet_started(&mut self, pkt: PacketStarted) {
        let display_time = self.time_formatter.format_packet_time(&pkt.time, pkt.epoch_ms);

        let mut row = PacketRow {
            id: pkt.id,
            seq: pkt.seq,
            flow_key: pkt.flow_key,
            time: display_time,
            method: pkt.method,
            status: None,
            elapsed_ms: None,
            protocol: pkt.protocol,
            host: pkt.host,
            uri: pkt.uri,
            query_str: pkt.query_str,
            line: Arc::<str>::from(""),
        };
        row.refresh_line();

        let idx = self.rows.len();
        self.id_to_row_index.insert(row.id.clone(), idx);

        if self.mode == PacketListMode::Search
            && self
            .search_matcher
            .as_ref()
            .is_some_and(|matcher| matcher.matches(&row))
        {
            self.search_indices.push(idx);
        }

        self.rows.push(row);
    }

    fn on_packet_completed(&mut self, pkt: PacketCompleted) {
        let Some(&idx) = self.id_to_row_index.get(&pkt.id) else {
            return;
        };

        let Some(row) = self.rows.get_mut(idx) else {
            return;
        };

        row.status = Some(pkt.status);
        row.elapsed_ms = Some(pkt.elapsed_ms);
        row.refresh_line();

        self.rebuild_search_rows_if_needed();
    }

    fn rebuild_search_rows_if_needed(&mut self) {
        if self.mode != PacketListMode::Search {
            return;
        }

        if let Some(matcher) = self.search_matcher.as_ref() {
            self.search_indices = self
                .rows
                .iter()
                .enumerate()
                .filter_map(|(idx, row)| matcher.matches(row).then_some(idx))
                .collect();

            self.search_selected = self
                .search_selected
                .min(self.search_indices.len().saturating_sub(1));
        }
    }

    fn remove_waiting_row_if_needed(&mut self) {
        if self.rows.len() == 1
            && self.rows[0].id.is_empty()
            && self.rows[0].line.as_ref() == Self::WAITING_ROW_TEXT
        {
            self.rows.clear();
            self.search_indices.clear();
            self.main_selected = 0;
            self.search_selected = 0;
            self.selected = 0;
        }
    }

    fn sync_list(&mut self) {
        self.sync_list_title();

        let items: Arc<[PacketListItem]> = match self.mode {
            PacketListMode::Main => self
                .rows
                .iter()
                .enumerate()
                .map(|(row_index, row)| PacketListItem {
                    _row_index: row_index,
                    line: row.line.clone(),
                })
                .collect::<Vec<_>>()
                .into(),
            PacketListMode::Search => self
                .search_indices
                .iter()
                .filter_map(|&row_index| {
                    self.rows.get(row_index).map(|row| PacketListItem {
                        _row_index: row_index,
                        line: row.line.clone(),
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        };

        let context = PacketListContext {
            selected: self.current_selected(),
            owner_id: self.get_id(),
            row_clicks: self.row_clicks.clone(),
            items,
        };

        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            list.set_item_count(context.items.len());
            list.set_renderer(
                context,
                |ctx: &mut PacketListContext, idx: usize| -> Option<Box<dyn Widget>> {
                    let item = ctx.items.get(idx)?;
                    Some(
                        ClickablePacketRow::new(
                            ctx.owner_id,
                            ctx.row_clicks.clone(),
                            idx,
                            item.line.clone(),
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

    fn trim_rows_if_needed(&mut self) {
        if self.rows.len() <= MAX_ROWS {
            return;
        }

        let drain_count = TRIM_ROWS.min(self.rows.len());
        self.rows.drain(0..drain_count);

        self.id_to_row_index.clear();
        for (idx, row) in self.rows.iter().enumerate() {
            if !row.id.is_empty() {
                self.id_to_row_index.insert(row.id.clone(), idx);
            }
        }

        self.main_selected = self.main_selected.saturating_sub(drain_count);

        if self.mode == PacketListMode::Search
            && let Some(matcher) = self.search_matcher.as_ref() {
            self.search_indices = self
                .rows
                .iter()
                .enumerate()
                .filter_map(|(idx, row)| matcher.matches(row).then_some(idx))
                .collect();

            self.search_selected = self
                .search_selected
                .min(self.search_indices.len().saturating_sub(1));
        };

        self.clamp_current_selected();
    }

    fn append_system_line(&mut self, line: impl Into<String>) {
        self.rows.push(PacketRow {
            id: String::new(),
            seq: 0,
            flow_key: String::new(),
            time: "test time".to_string(),
            method: "test method".to_string(),
            status: None,
            elapsed_ms: None,
            protocol: "test protocol".to_string(),
            host: "test host".to_string(),
            uri: "test url".to_string(),
            query_str: String::new(),
            line: Arc::<str>::from(line.into()),
        });

        self.trim_rows_if_needed();
        self.sync_list();
    }

    fn selected_packet_id(&self) -> Option<&str> {
        self.current_row()
            .and_then(|row| {
                if row.id.is_empty() {
                    None
                } else {
                    Some(row.id.as_str())
                }
            })
    }

    fn on_select_packet(&self, id: String) {
        self.on_select_packet_with_highlight(id, None, None);
    }

    fn on_select_packet_with_highlight(
        &self,
        id: String,
        highlight_query: Option<String>,
        tab_selection: Option<DetailTabSelection>,
    ) {
        let db = self.dbstate.clone();
        let detail_tx = self.detail_tx.clone();
        let time_formatter = self.time_formatter.clone();

        tokio::spawn(async move {
            let req = db.select_request_by_id(id.clone()).await;
            let res = db.select_response_by_id(id.clone()).await;

            let detail = match (req, res) {
                (Ok(mut req), Ok(res)) => {
                    if let Some(epoch_ms) = req.epoch_ms {
                        let raw_time = req.time.as_deref().unwrap_or_default();
                        req.time = Some(time_formatter.format_packet_time_rfc3339(raw_time, epoch_ms));
                    }

                    let req_body = read_body_file(
                        req.request_body_path.as_deref()
                    ).await;
                    let res_body = read_body_file(
                        res.response_body_path.as_deref()
                    ).await;
                    let req_body = format_body_with_size(req.body_size_line(), req_body);
                    let res_body = format_body_with_size(res.body_size_line(), res_body);
                    let dir = req.flow_dir.as_deref().unwrap_or_default().to_string();

                    DetailContent {
                        request_meta: req.to_string(),
                        request_body: req_body,
                        response_meta: res.to_string(),
                        response_body: res_body,
                        id,
                        dir,
                    }
                }
                (Ok(mut req), Err(e)) => {
                    if let Some(epoch_ms) = req.epoch_ms {
                        let raw_time = req.time.as_deref().unwrap_or_default();
                        req.time = Some(time_formatter.format_packet_time_rfc3339(raw_time, epoch_ms));
                    }

                    let req_body = read_body_file(
                        req.request_body_path.as_deref()
                    ).await;
                    let req_body = format_body_with_size(req.body_size_line(), req_body);
                    let dir = req.flow_dir.as_deref().unwrap_or_default().to_string();

                    DetailContent {
                        request_meta: req.to_string(),
                        request_body: req_body,
                        response_meta: format!("response error: {e:#}"),
                        response_body: String::new(),
                        id,
                        dir,
                    }
                }
                (Err(e1), Err(e2)) => {
                    DetailContent {
                        request_meta: format!("request error: {e1:#}"),
                        request_body: String::new(),
                        response_meta: format!("response error: {e2:#}"),
                        response_body: String::new(),
                        id,
                        dir: String::new(),
                    }
                }
                (Err(e), _) => {
                    DetailContent {
                        request_meta: format!("request error: {e:#}"),
                        request_body: String::new(),
                        response_meta: String::new(),
                        response_body: String::new(),
                        id,
                        dir: String::new(),
                    }
                }
            };

            let _ = detail_tx.send(UiEvent::ShowDetail {
                detail,
                highlight_query,
                tab_selection,
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

    // fn visible_rows(&self) -> &[PacketRow] {
    //     match self.mode {
    //         PacketListMode::Main => &self.rows,
    //         PacketListMode::Search => &self.search_rows,
    //     }
    // }

    fn visible_rows_len(&self) -> usize {
        match self.mode {
            PacketListMode::Main => self.rows.len(),
            PacketListMode::Search => self.search_indices.len(),
        }
    }

    fn current_row_index(&self) -> Option<usize> {
        match self.mode {
            PacketListMode::Main => {
                let idx = self.main_selected;
                (idx < self.rows.len()).then_some(idx)
            }
            PacketListMode::Search => self
                .search_indices
                .get(self.search_selected)
                .copied(),
        }
    }

    fn current_row(&self) -> Option<&PacketRow> {
        self.current_row_index()
            .and_then(|idx| self.rows.get(idx))
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
        let search_history = self.search_history.clone();

        open_search_popup(search_history, move |query| {
            search_requests.lock().push(query);
        });
    }

    fn open_full_text_search(&mut self) {
        let select_requests = self.full_text_select_requests.clone();
        let search_path = self.capture_flows_dir.clone();
        let full_text_search_history = self.full_text_search_history.clone();

        open_full_text_search_popup(search_path, full_text_search_history, move |results, selected, query| {
            select_requests.lock().push(FullTextSelectRequest {
                results,
                selected,
                query,
            });
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

        for request in requests {
            self.retained_full_text_selected = Some(request.selected);
            self.retained_full_text_query = Some(request.query);
            self.retained_full_text_results = request.results;

            self.select_retained_full_text_result(request.selected);
        }
    }

    fn move_retained_full_text_next(&mut self) {
        let len = self.retained_full_text_results.len();

        if len == 0 {
            self.append_system_line("=== no retained full text search results ===");
            return;
        }

        let current = self.retained_full_text_selected.unwrap_or(0);
        let next = if current + 1 < len { current + 1 } else { 0 };

        self.select_retained_full_text_result(next);
    }

    fn move_retained_full_text_previous(&mut self) {
        let len = self.retained_full_text_results.len();

        if len == 0 {
            self.append_system_line("=== no retained full text search results ===");
            return;
        }

        let current = self.retained_full_text_selected.unwrap_or(0);
        let previous = if current == 0 { len - 1 } else { current - 1 };

        self.select_retained_full_text_result(previous);
    }

    fn select_retained_full_text_result(&mut self, idx: usize) {
        let Some(result) = self.retained_full_text_results.get(idx) else {
            return;
        };

        self.retained_full_text_selected = Some(idx);

        let flow_key = result.flow_key.clone();
        let query = self.retained_full_text_query.clone();
        let tab_selection = detail_tab_selection_from_search_path(&result.path);

        self.select_flow_key(&flow_key, query, tab_selection);
    }

    fn reset_detail(&self) {
        let _ = self
            .detail_tx
            .send(UiEvent::ShowDetail {
                detail: DetailContent {
                    request_meta: DETAIL_PLACEHOLDER_TEXT.to_string(),
                    ..Default::default()
                },
                highlight_query: None,
                tab_selection: None,
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

        self.search_query = matcher.label().to_owned();
        self.search_indices = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(idx, row)| matcher.matches(row).then_some(idx))
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
        self.search_indices.clear();
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
                    .span(self.search_query.as_str().fg(Color::YELLOW).bold())
                    .span("]".fg(Color::YELLOW))
                    .span(format!(" {}/{}", self.search_indices.len(), self.rows.len()).dim())
            }
        }
    }

    fn sync_list_title(&mut self) {
        let title = self.list_title();

        if let Some(text) = self.list.get_widget_mut(self.list_title_id) {
            text.set_content(title);
        }
    }

    fn select_flow_key(
        &mut self,
        flow_key: &str,
        highlight_query: Option<String>,
        tab_selection: Option<DetailTabSelection>,
    ) {
        let Some(idx) = self
            .rows
            .iter()
            .position(|row| row.flow_key == flow_key)
        else {
            self.append_system_line(format!("=== search result not found in packet list: {flow_key} ==="));
            return;
        };

        self.mode = PacketListMode::Main;
        self.search_indices.clear();
        self.search_query.clear();
        self.search_matcher = None;
        self.search_error = None;

        self.main_selected = idx;
        self.selected = idx;
        self.sync_list_and_reveal_selected();

        if let Some(id) = self.selected_packet_id().map(str::to_owned) {
            self.on_select_packet_with_highlight(id, highlight_query, tab_selection);
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

fn format_body_with_size(body_size: String, body: String) -> String {
    format!("body size : {body_size}\n\n{body}")
}

pub fn format_body_for_display(bytes: &[u8]) -> String {
    if let Some(kind) = binary_magic_kind(bytes) {
        return format!("<binary body detected by magic number: {kind}>\n\n{}", hexdump_with_ascii(bytes));
    }

    if let Ok(text) = std::str::from_utf8(bytes)
        && looks_like_text(text) {
        return text.to_string();
    }

    hexdump_with_ascii(bytes)
}

fn binary_magic_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some("png");
    }

    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("jpeg");
    }

    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("gif");
    }

    if bytes.starts_with(b"%PDF-") {
        return Some("pdf");
    }

    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08") {
        return Some("zip");
    }

    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some("gzip");
    }

    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("zstd");
    }

    if bytes.starts_with(b"\x00asm") {
        return Some("wasm");
    }

    if bytes.starts_with(b"\x7fELF") {
        return Some("elf");
    }

    if bytes.starts_with(b"BM") {
        return Some("bmp");
    }

    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        return Some("webp");
    }

    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE") {
        return Some("wav");
    }

    if bytes.starts_with(b"OggS") {
        return Some("ogg");
    }

    if bytes.len() >= 12 && bytes.get(4..12) == Some(b"ftypavif") {
        return Some("avif");
    }

    if bytes.len() >= 12 && bytes.get(4..8) == Some(b"ftyp") {
        return Some("mp4");
    }

    None
}

fn looks_like_text(text: &str) -> bool {
    let mut total = 0usize;
    let mut control = 0usize;

    for ch in text.chars() {
        total += 1;

        if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
            control += 1;
        }
    }

    total == 0 || control * 100 / total <= 5
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
            // filter shortcut
            chord!(Char('f')) if queue.is_unhandled() => {
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
            chord!(Char('n')) if queue.is_unhandled() => {
                queue.next();
                self.move_retained_full_text_next();
                return InputResult::Handled;
            }
            chord!(Char('p')) if queue.is_unhandled() => {
                queue.next();
                self.move_retained_full_text_previous();
                return InputResult::Handled;
            }
            chord!(Esc) if self.mode == PacketListMode::Search => {
                queue.next();
                self.clear_search();
                tuie::dirty_layout();
                return InputResult::Handled;
            }
            chord!(Esc) => {
                queue.next();
                self.show_detail();
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
    detail_pane_id: WidgetId<DetailPane>,
}

impl RootPane {
    fn new(
        split: Box<Pane>,
        detail_rx: UnboundedReceiver<UiEvent>,
        detail_pane_id: WidgetId<DetailPane>,
    ) -> Box<Self> {
        Box::new(Self {
            split,
            detail_rx,
            detail_pane_id,
        })
    }

    fn poll_ui_events(&mut self) {
        while let Ok(event) = self.detail_rx.try_recv() {
            match event {
                UiEvent::ShowDetail {
                    detail,
                    highlight_query,
                    tab_selection,
                } => {
                    if let Some(detail_pane) = self.split.get_widget_mut(self.detail_pane_id) {
                        detail_pane.set_content(detail, highlight_query, tab_selection);
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

    fn override_on_input(&mut self, _queue: &mut InputQueue) -> InputResult {
        self.poll_ui_events();
        InputResult::Rejected
    }
}

struct ClickablePacketRow {
    layout: Layout,
    owner_id: WidgetId<PacketListDelegate>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
    visible_idx: usize,
    text: Arc<str>,
    selected: bool,
    pressed: std::cell::Cell<bool>,
}

impl ClickablePacketRow {
    fn new(
        owner_id: WidgetId<PacketListDelegate>,
        row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
        visible_idx: usize,
        text: Arc<str>,
        selected: bool,
    ) -> Box<Self> {
        Box::new(Self {
            layout: Layout::new(),
            owner_id,
            row_clicks,
            visible_idx,
            text,
            selected,
            pressed: std::cell::Cell::new(false),
        })
    }

    fn hit(&self, pos: Vec2<f32>) -> bool {
        let size = self.get_rect_size();
        pos.x >= 0. && pos.y >= 0. && pos.x < size.x as f32 && pos.y < size.y as f32
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
                if self.hit(event.pos) {
                    tuie::focus_widget(self.owner_id);
                    self.row_clicks.lock().push(self.visible_idx);
                    return InputResult::Handled;
                }
                InputResult::Rejected
            }
            chord!(LeftRelease) => {
                let was_pressed = self.pressed.get();
                self.pressed.set(false);
                if was_pressed && self.hit(event.pos) {
                    tuie::emit(self.owner_id, RowClicked(self.visible_idx));
                    return InputResult::Handled;
                }
                InputResult::Rejected
            }
            _ => InputResult::Rejected,
        }
    }
}

pub async fn run_tui(
    rx: mpsc::Receiver<PacketEvent>,
    quit_tx: watch::Sender<bool>,
    time_display: TimeDisplayConfig,
    tui_mode: TuiMode,
) -> anyhow::Result<()> {
    let (detail_tx, detail_rx) = mpsc::unbounded_channel::<UiEvent>();

    let app: Box<dyn Widget> = PacketListDelegate::new(
        rx,
        detail_tx,
        time_display,
        tui_mode,
    ).await;

    let title = match tui_mode {
        TuiMode::Capture => "Inspect",
        TuiMode::Viewer => "Inspect (Viewer Mode)",
    };

    let mut detail_pane_id = WidgetId::EMPTY;
    let detail_pane = DetailPane::new()
        .id(&mut detail_pane_id);

    let split = Pane::new()
        .vertical()
        .flex(1)
        .gap(0)
        .children([Split::new(
            SplitPane::new()
                .children([
                    SplitPaneChild::from(Pane::new()
                        .preferred_width(60)
                        .preferred_height(1)
                        .vertical()
                        .flex(1)
                        .children([
                            app
                        ])).title(title),
                    SplitPaneChild::from(Pane::new()
                        .preferred_width(40)
                        .preferred_height(1)
                        .vertical()
                        .flex(1)
                        .children([
                            detail_pane,
                        ]),
                        // .y_scroll(Scrollbar::Visible),
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

    let root = RootPane::new(split, detail_rx, detail_pane_id);
    let root = global_chords::GlobalChords::new(root);

    tuie::start_tui(root)?;

    Ok(())
}
