use std::cell::{Cell, RefCell};
use std::rc::Rc;
use chord_macro::chord;
use tuie::prelude::*;
use grep_regex::RegexMatcher;
use grep_searcher::{Searcher, Sink, SinkMatch};
use ignore::WalkBuilder;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use crate::tui::button::Button;
use crate::tui::focus_pane::FocusPane;

const MAX_FULL_TEXT_RESULTS_DISPLAYED: usize = 500;
const MAX_FULL_TEXT_RESULT_LINE_CHARS: usize = 96;
const MIN_FULL_TEXT_PREVIEW_CHARS: usize = 32;
const MAX_SEARCH_HISTORY: usize = 100;

struct PopupHost {
    root: Box<Pane>,
    input_id: WidgetId<Input>,
    search_button_id: WidgetId<Button>,
    cancel_button_id: WidgetId<Button>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
    history: Arc<parking_lot::Mutex<Vec<String>>>,
    history_selected: Option<usize>,
    on_search: Box<dyn Fn(String)>,
}

impl PopupHost {
    fn new(
        root: Box<Pane>,
        input_id: WidgetId<Input>,
        search_button_id: WidgetId<Button>,
        cancel_button_id: WidgetId<Button>,
        popup_id: Rc<Cell<Option<WidgetId>>>,
        history: Arc<parking_lot::Mutex<Vec<String>>>,
        on_search: impl Fn(String) + 'static,
    ) -> Box<Self> {
        Box::new(Self {
            root,
            input_id,
            search_button_id,
            cancel_button_id,
            popup_id,
            history,
            history_selected: None,
            on_search: Box::new(on_search),
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn search(&self) {
        let query = self.query();

        remember_search_query(&self.history, &query);

        (self.on_search)(query);
        self.close();
    }

    fn query(&self) -> String {
        self.root
            .get_widget(self.input_id)
            .map(|input| input.get_string())
            .unwrap_or_default()
    }

    fn set_query(&mut self, query: impl Into<String>) {
        if let Some(input) = self.root.get_widget_mut(self.input_id) {
            input.set_content(query.into());
        }
        tuie::dirty_layout();
    }

    fn move_history_up(&mut self) {
        let len = history_len(&self.history);

        if len == 0 {
            return;
        }

        let next = match self.history_selected {
            Some(idx) => idx.saturating_sub(1),
            None => len - 1,
        };

        self.history_selected = Some(next);

        if let Some(query) = history_item(&self.history, next) {
            self.set_query(query);
        }
    }

    fn move_history_down(&mut self) {
        let len = history_len(&self.history);

        if len == 0 {
            return;
        }

        let Some(idx) = self.history_selected else {
            return;
        };

        if idx + 1 < len {
            let next = idx + 1;
            self.history_selected = Some(next);

            if let Some(query) = history_item(&self.history, next) {
                self.set_query(query);
            }
        } else {
            self.history_selected = None;
            self.set_query("");
        }
    }
}

impl DelegateWidget for PopupHost {
    tuie::delegate_widget!(root);

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
            chord!(Up) => {
                queue.next();
                self.move_history_up();
                InputResult::Handled
            }
            chord!(Down) => {
                queue.next();
                self.move_history_down();
                InputResult::Handled
            }
            chord!(Enter) => {
                queue.next();
                self.search();
                InputResult::Handled
            }
            _ => InputResult::Rejected,
        }
    }

    fn after_on_event(&mut self, event: &mut WidgetEvent) {
        if event.of_by::<ClickEvent>(self.search_button_id) {
            self.search();
        } else if event.of_by::<ClickEvent>(self.cancel_button_id) {
            self.close();
        }
    }
}

pub fn open_search_popup(
    history: Arc<parking_lot::Mutex<Vec<String>>>,
    on_search: impl Fn(String) + 'static,
) {
    let mut input_id = WidgetId::EMPTY;
    let mut search_button_id = WidgetId::EMPTY;
    let mut cancel_button_id = WidgetId::EMPTY;

    let sl_input = FocusPane::new().children([
        Pane::new()
            .horizontal()
            .max_height(3)
            .children([
                Input::new()
                    .word_wrap()
                    .flex(1)
                    .id(&mut input_id),
            ]),
    ]);

    let body = Pane::new()
        .style(Style::new().bg(Color::grey256(3)).blend(95))
        .width(60)
        .vertical()
        .padding(Spacing::balanced(2))
        .gap(1)
        .children([
            Text::new()
                .content("Filter".fg(Color::Foreground).bold()) as Box<dyn Widget>,
            sl_input,
            Pane::new()
                .horizontal()
                .x_place(Place::End)
                .gap(1)
                .children([
                    Button::new()
                        .children([Text::new().content(" Cancel ")])
                        .id(&mut cancel_button_id) as Box<dyn Widget>,
                    Button::new()
                        .children([Text::new().content(" Apply ")])
                        .id(&mut search_button_id),
                ]),
        ]);

    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));

    let host = PopupHost::new(
        body,
        input_id,
        search_button_id,
        cancel_button_id,
        popup_id.clone(),
        history,
        on_search,
    );

    popup_id.set(Some(host.get_id().untyped()));

    tuie::open_popup(
        Popup::new(host)
            .dismissible(),
    );
}

#[derive(Clone, Debug)]
pub(crate) struct FullTextSearchResult {
    pub flow_key: String,
    pub path: String,
    pub line_number: u64,
    #[allow(dead_code)]
    pub preview: String,
    pub display_line: String,
}

fn flow_key_from_path(path: &Path) -> Option<String> {
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .map(str::to_string)
}

fn sequence_from_flow_key(flow_key: &str) -> u64 {
    flow_key
        .split_once('-')
        .map(|(seq, _)| seq)
        .unwrap_or(flow_key)
        .parse::<u64>()
        .unwrap_or(u64::MAX)
}

fn trim_preview(line: &str, max_chars: usize) -> String {
    let line = line.trim();

    if line.chars().count() <= max_chars {
        return line.to_string();
    }

    let half = max_chars / 2;
    let head: String = line.chars().take(half).collect();
    let tail: String = line
        .chars()
        .rev()
        .take(half)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    format!("{head} ... {tail}")
}

fn compact_result_path(path: &std::path::Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("?");

    let parent_name = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("?");

    format!("{parent_name}/{file_name}")
}

pub fn search_capture_files(
    search_path: impl AsRef<std::path::Path>,
    query: &str,
) -> anyhow::Result<Vec<FullTextSearchResult>> {
    struct CollectSink {
        path: PathBuf,
        matcher: FullTextMatcher,
        results: Vec<FullTextSearchResult>,
    }

    impl Sink for CollectSink {
        type Error = io::Error;

        fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
            let Some(flow_key) = flow_key_from_path(&self.path) else {
                return Ok(true);
            };

            let line = std::str::from_utf8(mat.bytes()).unwrap_or("").trim();

            let result_path = compact_result_path(&self.path);
            let line_number = mat.line_number().unwrap_or(0);
            let prefix = format!("{result_path}:{line_number} ");

            let preview_max_chars = MAX_FULL_TEXT_RESULT_LINE_CHARS
                .saturating_sub(prefix.chars().count())
                .max(MIN_FULL_TEXT_PREVIEW_CHARS);

            let preview = if let Some(range) = self.matcher.find_in_line(line) {
                trim_preview_around_match(
                    line,
                    range.start,
                    range.end,
                    preview_max_chars,
                )
            } else {
                trim_preview(line, preview_max_chars)
            };

            let display_line = format!("{prefix}{preview}");

            self.results.push(FullTextSearchResult {
                flow_key,
                path: self.path.display().to_string(),
                line_number,
                preview,
                display_line,
            });

            Ok(true)
        }
    }

    let Some(matcher_config) = FullTextMatcher::parse(query) else {
        return Ok(Vec::new());
    };

    let matcher = RegexMatcher::new(matcher_config.grep_pattern())?;
    let mut results = Vec::new();

    for entry in WalkBuilder::new(search_path).build() {
        let Ok(entry) = entry else {
            continue;
        };

        if !entry.file_type().is_some_and(|ft| ft.is_file())  {
            continue;
        }

        let path = entry.path();

        let mut sink = CollectSink {
            path: path.to_path_buf(),
            matcher: matcher_config.clone(),
            results: Vec::new(),
        };

        let mut searcher = Searcher::new();
        let _ = searcher.search_path(&matcher, path, &mut sink);

        results.extend(sink.results);
    }

    results.sort_by_key(|result| {
        (
            sequence_from_flow_key(&result.flow_key),
            result.line_number,
            result.path.clone(),
        )
    });

    Ok(results)
}

fn remember_search_query(history: &Arc<parking_lot::Mutex<Vec<String>>>, query: &str) {
    let query = query.trim();

    if query.is_empty() {
        return;
    }

    let mut history = history.lock();

    if let Some(idx) = history.iter().position(|item| item == query) {
        history.remove(idx);
    }

    history.push(query.to_string());

    if history.len() > MAX_SEARCH_HISTORY {
        let overflow = history.len() - MAX_SEARCH_HISTORY;
        history.drain(0..overflow);
    }
}

fn history_item(history: &Arc<parking_lot::Mutex<Vec<String>>>, idx: usize) -> Option<String> {
    history.lock().get(idx).cloned()
}

fn history_len(history: &Arc<parking_lot::Mutex<Vec<String>>>) -> usize {
    history.lock().len()
}

#[derive(Clone, Debug)]
pub(crate) enum FullTextMatcher {
    Plain {
        query: String,
        escaped_pattern: String,
    },
    Regex {
        pattern: String,
    },
}

impl FullTextMatcher {
    pub(crate) fn parse(query: &str) -> Option<Self> {
        let query = query.trim();

        if query.is_empty() {
            return None;
        }

        if let Some(pattern) = query.strip_prefix("re:") {
            return Some(Self::Regex {
                pattern: pattern.to_string(),
            });
        }

        Some(Self::Plain {
            query: query.to_string(),
            // escaped_pattern: format!("(?i){}", regex::escape(query)),
            escaped_pattern: regex::escape(query),
        })
    }

    pub(crate) fn grep_pattern(&self) -> &str {
        match self {
            Self::Plain { escaped_pattern, .. } => escaped_pattern,
            Self::Regex { pattern } => pattern,
        }
    }

    pub(crate) fn find_in_line(&self, line: &str) -> Option<std::ops::Range<usize>> {
        match self {
            Self::Plain { query, .. } => line.find(query).map(|start| {
                let end = start + query.len();
                start..end
            }),
            Self::Regex { pattern } => regex::Regex::new(pattern)
                .ok()
                .and_then(|regex| regex.find(line).map(|m| m.start()..m.end())),
        }
    }

    pub(crate) fn find_all_in_line(&self, line: &str) -> Vec<std::ops::Range<usize>> {
        match self {
            Self::Plain { query, .. } => {
                if query.is_empty() {
                    return Vec::new();
                }

                let mut ranges = Vec::new();
                let mut offset = 0;

                while let Some(pos) = line[offset..].find(query) {
                    let start = offset + pos;
                    let end = start + query.len();
                    ranges.push(start..end);
                    offset = end;
                }

                ranges
            }
            Self::Regex { pattern } => regex::Regex::new(pattern)
                .ok()
                .map(|regex| {
                    regex
                        .find_iter(line)
                        .filter(|m| m.start() < m.end())
                        .map(|m| m.start()..m.end())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug)]
struct FullTextResultListContext {
    results: Vec<FullTextSearchResult>,
    result_clicks: Rc<RefCell<Vec<usize>>>,
}

struct ClickableFullTextSearchResult {
    layout: Layout,
    result_idx: usize,
    text: String,
    result_clicks: Rc<RefCell<Vec<usize>>>,
}

impl ClickableFullTextSearchResult {
    fn new(
        result_idx: usize,
        result: FullTextSearchResult,
        result_clicks: Rc<RefCell<Vec<usize>>>,
    ) -> Box<Self> {
        Box::new(Self {
            layout: Layout::new(),
            result_idx,
            text: result.display_line,
            result_clicks,
        })
    }

    fn hit(&self, pos: Vec2<f32>) -> bool {
        let size = self.get_rect_size();
        pos.x >= 0. && pos.y >= 0. && pos.x < size.x as f32 && pos.y < size.y as f32
    }
}

impl Widget for ClickableFullTextSearchResult {
    fn get_layout(&self) -> &Layout {
        &self.layout
    }

    fn get_layout_mut(&mut self) -> &mut Layout {
        &mut self.layout
    }

    fn get_name(&self) -> &'static str {
        "ClickableFullTextSearchResult"
    }

    fn render(&self, mut ctx: RenderContext) {
        ctx.clear();
        write!(ctx, "{}", self.text);
    }

    fn measure_constraints(&mut self) -> Constraints {
        let margin = self.layout.get_margin_total();
        let h = 1 + margin.y;

        Constraints {
            min_size: Vec2::new(0, h),
            max_size: Vec2::new(u16::MAX, h),
            preferred_size: Vec2::new(40, h),
        }
    }

    fn on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.next() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(LeftClick) => {
                if self.hit(event.pos) {
                    self.result_clicks.borrow_mut().push(self.result_idx);
                    return InputResult::Handled;
                }

                InputResult::Rejected
            }
            _ => InputResult::Rejected,
        }
    }
}

struct FullTextSearchPopupHost {
    root: Box<Pane>,
    input_id: WidgetId<Input>,
    search_button_id: WidgetId<Button>,
    cancel_button_id: WidgetId<Button>,
    status_text_id: WidgetId<Text>,
    results_list_id: WidgetId<List>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
    result_clicks: Rc<RefCell<Vec<usize>>>,
    current_results: Vec<FullTextSearchResult>,
    search_path: PathBuf,
    history: Arc<parking_lot::Mutex<Vec<String>>>,
    history_selected: Option<usize>,
    on_select: Box<dyn Fn(Vec<FullTextSearchResult>, usize, String)>,
}

#[allow(clippy::too_many_arguments)]
impl FullTextSearchPopupHost {
    fn new(
        root: Box<Pane>,
        input_id: WidgetId<Input>,
        search_button_id: WidgetId<Button>,
        cancel_button_id: WidgetId<Button>,
        status_text_id: WidgetId<Text>,
        results_list_id: WidgetId<List>,
        popup_id: Rc<Cell<Option<WidgetId>>>,
        result_clicks: Rc<RefCell<Vec<usize>>>,
        search_path: PathBuf,
        history: Arc<parking_lot::Mutex<Vec<String>>>,
        on_select: impl Fn(Vec<FullTextSearchResult>, usize, String) + 'static,
    ) -> Box<Self> {
        Box::new(Self {
            root,
            input_id,
            search_button_id,
            cancel_button_id,
            status_text_id,
            results_list_id,
            popup_id,
            result_clicks,
            current_results: Vec::new(),
            search_path,
            history,
            history_selected: None,
            on_select: Box::new(on_select),
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn query(&self) -> String {
        self.root
            .get_widget(self.input_id)
            .map(|input| input.get_string())
            .unwrap_or_default()
    }

    fn set_query(&mut self, query: impl Into<String>) {
        if let Some(input) = self.root.get_widget_mut(self.input_id) {
            input.set_content(query.into());
        }
        tuie::dirty_layout();
    }

    fn move_history_up(&mut self) {
        let len = history_len(&self.history);

        if len == 0 {
            return;
        }

        let next = match self.history_selected {
            Some(idx) => idx.saturating_sub(1),
            None => len - 1,
        };

        self.history_selected = Some(next);

        if let Some(query) = history_item(&self.history, next) {
            self.set_query(query);
        }
    }

    fn move_history_down(&mut self) {
        let len = history_len(&self.history);

        if len == 0 {
            return;
        }

        let Some(idx) = self.history_selected else {
            return;
        };

        if idx + 1 < len {
            let next = idx + 1;
            self.history_selected = Some(next);

            if let Some(query) = history_item(&self.history, next) {
                self.set_query(query);
            }
        } else {
            self.history_selected = None;
            self.set_query("");
        }
    }

    fn set_status(&mut self, text: impl Into<String>) {
        if let Some(status) = self.root.get_widget_mut(self.status_text_id) {
            status.set_content(text.into());
        }
        tuie::dirty_layout();
    }

    fn set_results(&mut self, mut results: Vec<FullTextSearchResult>) {
        if results.len() > MAX_FULL_TEXT_RESULTS_DISPLAYED {
            results.truncate(MAX_FULL_TEXT_RESULTS_DISPLAYED);
        }

        self.current_results = results.clone();

        let context = FullTextResultListContext {
            results,
            result_clicks: self.result_clicks.clone(),
        };

        if let Some(list) = self.root.get_widget_mut(self.results_list_id) {
            list.set_item_count(context.results.len());
            list.set_renderer(
                context,
                |ctx: &mut FullTextResultListContext, idx: usize| -> Option<Box<dyn Widget>> {
                    let result = ctx.results.get(idx)?.clone();

                    Some(
                        ClickableFullTextSearchResult::new(
                            idx,
                            result,
                            ctx.result_clicks.clone(),
                        ) as Box<dyn Widget>
                    )
                },
            );
            list.invalidate_all();
        }
        tuie::dirty_layout();
    }

    fn run_search(&mut self) {
        let query = self.query();

        if query.trim().is_empty() {
            self.set_results(Vec::new());
            self.set_status("Enter text or regex to search.");
            return;
        }

        remember_search_query(&self.history, &query);

        self.set_status("Searching...");

        match search_capture_files(&self.search_path, &query) {
            Ok(results) => {
                let total_count = results.len();
                let shown_count = total_count.min(MAX_FULL_TEXT_RESULTS_DISPLAYED);

                self.set_results(results);

                if shown_count < total_count {
                    self.set_status(format!(
                        "{total_count} matches, showing first {shown_count}"
                    ));
                } else {
                    self.set_status(format!("{total_count} matches"));
                }
            }
            Err(err) => {
                self.set_results(Vec::new());
                self.set_status(format!("Search error: {err}"));
            }
        }
    }

    fn poll_result_clicks(&mut self) {
        let clicked = {
            let mut result_clicks = self.result_clicks.borrow_mut();
            std::mem::take(&mut *result_clicks)
        };

        for result_idx in clicked {
            if result_idx < self.current_results.len() {
                (self.on_select)(
                    self.current_results.clone(),
                    result_idx,
                    self.query(),
                );
                self.close();
            }
        }
    }
}

impl DelegateWidget for FullTextSearchPopupHost {
    fn get_delegate(&self) -> &dyn Widget {
        self.root.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.poll_result_clicks();
        self.root.as_mut()
    }

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
            chord!(Up) => {
                queue.next();
                self.move_history_up();
                InputResult::Handled
            }
            chord!(Down) => {
                queue.next();
                self.move_history_down();
                InputResult::Handled
            }
            chord!(Enter) => {
                queue.next();
                self.run_search();
                InputResult::Handled
            }
            _ => InputResult::Rejected,
        }
    }

    fn after_on_event(&mut self, event: &mut WidgetEvent) {
        if event.of_by::<ClickEvent>(self.search_button_id) {
            self.run_search();
        } else if event.of_by::<ClickEvent>(self.cancel_button_id) {
            self.close();
        }
    }
}

pub fn open_full_text_search_popup(
    search_path: PathBuf,
    history: Arc<parking_lot::Mutex<Vec<String>>>,
    on_select: impl Fn(Vec<FullTextSearchResult>, usize, String) + 'static,
) {
    let mut input_id = WidgetId::EMPTY;
    let mut search_button_id = WidgetId::EMPTY;
    let mut cancel_button_id = WidgetId::EMPTY;
    let mut status_text_id = WidgetId::EMPTY;
    let mut results_list_id = WidgetId::EMPTY;

    let result_clicks: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));

    let search_input = FocusPane::new().children([
        Pane::new()
            .horizontal()
            .max_height(3)
            .children([
                Input::new()
                    .word_wrap()
                    .flex(1)
                    .id(&mut input_id),
            ]),
    ]);

    let mut results_list = List::new()
        .vertical()
        .flex(1)
        .min_height(8)
        .gap(0)
        .scroll(Scrollbar::AutoHide)
        .id(&mut results_list_id);

    let context = FullTextResultListContext {
        results: Vec::new(),
        result_clicks: result_clicks.clone(),
    };

    results_list.set_item_count(0);
    results_list.set_renderer(
        context,
        |ctx: &mut FullTextResultListContext, idx: usize| -> Option<Box<dyn Widget>> {
            let result = ctx.results.get(idx)?.clone();

            Some(
                ClickableFullTextSearchResult::new(
                    idx,
                    result,
                    ctx.result_clicks.clone(),
                ) as Box<dyn Widget>
            )
        },
    );

    let body = Pane::new()
        .style(Style::new().bg(Color::grey256(3)).blend(95))
        .width(86)
        .max_height(28)
        .vertical()
        .padding(Spacing::balanced(2))
        .gap(1)
        .children([
            Text::new()
                .content("Full Text Search".fg(Color::Foreground).bold()) as Box<dyn Widget>,
            search_input,
            Pane::new()
                .horizontal()
                .x_place(Place::End)
                .gap(1)
                .children([
                    Button::new()
                        .children([Text::new().content(" Cancel ")])
                        .id(&mut cancel_button_id) as Box<dyn Widget>,
                    Button::new()
                        .children([Text::new().content(" Search ")])
                        .id(&mut search_button_id),
                ]),
            Text::new()
                .content("Enter text or regex to search.".dim())
                .id(&mut status_text_id),
            Pane::new()
                .vertical()
                .flex(1)
                .bordered()
                .border_style(Style::new().fg(Color::grey256(8)))
                .children([
                    results_list,
                ]),
        ]);

    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));

    let host = FullTextSearchPopupHost::new(
        body,
        input_id,
        search_button_id,
        cancel_button_id,
        status_text_id,
        results_list_id,
        popup_id.clone(),
        result_clicks,
        search_path,
        history,
        on_select,
    );

    popup_id.set(Some(host.get_id().untyped()));

    tuie::open_popup(
        Popup::new(host)
            .dismissible(),
    );
}

fn trim_preview_around_match(
    line: &str,
    match_start: usize,
    match_end: usize,
    max_chars: usize,
) -> String {
    let line = line.trim();

    if line.chars().count() <= max_chars {
        return line.to_string();
    }

    let match_start = match_start.min(line.len());
    let match_end = match_end.min(line.len());

    let mut char_positions: Vec<usize> = line.char_indices().map(|(idx, _)| idx).collect();
    char_positions.push(line.len());

    let match_start_char = char_positions
        .partition_point(|idx| *idx <= match_start)
        .saturating_sub(1);

    let match_end_char = char_positions
        .partition_point(|idx| *idx < match_end)
        .min(char_positions.len().saturating_sub(1));

    let before_chars = max_chars / 3;
    let mut start_char = match_start_char.saturating_sub(before_chars);
    let mut end_char = (start_char + max_chars).min(char_positions.len().saturating_sub(1));

    if match_end_char >= end_char {
        end_char = match_end_char.min(char_positions.len().saturating_sub(1));
        start_char = end_char.saturating_sub(max_chars);
    }

    let start_byte = char_positions[start_char];
    let end_byte = char_positions[end_char];

    line[start_byte..end_byte].to_string()
}