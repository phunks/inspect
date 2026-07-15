use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use chord_macro::chord;
use chrono::{DateTime, Local};
use tokio::sync::mpsc;
use tuie::prelude::*;

use crate::tui::read_metadata::{
    DbState,
    FilterExecStatsRow,
    FilterStatusRow,
    FilterStatsSnapshot,
};
use crate::tui::theme;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilterStatsTab {
    Execution,
    Status,
}

pub struct FilterStatsPopup {
    root: Box<Pane>,
    text_id: WidgetId<Text>,
    scroll_id: WidgetId<Pane>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
    dbstate: Arc<DbState>,
    refresh_tx: mpsc::UnboundedSender<anyhow::Result<FilterStatsSnapshot>>,
    refresh_rx: mpsc::UnboundedReceiver<anyhow::Result<FilterStatsSnapshot>>,
    snapshot: FilterStatsSnapshot,
    tab: FilterStatsTab,
    refreshing: bool,
}

impl FilterStatsPopup {
    fn new(
        dbstate: Arc<DbState>,
        snapshot: FilterStatsSnapshot,
        popup_id: Rc<Cell<Option<WidgetId>>>,
    ) -> Box<Self> {
        let mut text_id = WidgetId::EMPTY;
        let mut scroll_id = WidgetId::EMPTY;
        let (refresh_tx, refresh_rx) = mpsc::unbounded_channel();

        let root = Pane::new()
            .vertical()
            .width(120)
            .height(32)
            .padding(Spacing::balanced(1))
            .gap(1)
            .style(Style::new().bg(theme::panel_outer_bg()))
            .bordered()
            .border_style(Style::new().fg(theme::accent_fg()))
            .children([
                Text::new()
                    .content("Filter stats    ←/→: switch  r: refresh  j/k: scroll  q/Esc: close".bold())
                    as Box<dyn Widget>,
                Pane::new()
                    .vertical()
                    .flex(1)
                    .style(Style::new().bg(theme::panel_inner_bg()))
                    .id(&mut scroll_id)
                    .y_scroll(Scrollbar::AutoHide)
                    .children([
                        Text::new()
                            .content("")
                            .overflow(TextOverflow::WRAP)
                            .style(Style::new().bg(theme::panel_inner_bg()))
                            .id(&mut text_id) as Box<dyn Widget>,
                    ]) as Box<dyn Widget>,
            ]);

        let mut this = Box::new(Self {
            root,
            text_id,
            scroll_id,
            popup_id,
            dbstate,
            refresh_tx,
            refresh_rx,
            snapshot,
            tab: FilterStatsTab::Execution,
            refreshing: false,
        });

        this.refresh();
        this
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn switch_left(&mut self) {
        self.tab = match self.tab {
            FilterStatsTab::Execution => FilterStatsTab::Status,
            FilterStatsTab::Status => FilterStatsTab::Execution,
        };
        self.refresh();
    }

    fn switch_right(&mut self) {
        self.switch_left();
    }

    fn scroll_by(&mut self, delta: i32) {
        if let Some(pane) = self.root.get_widget_mut(self.scroll_id) {
            pane.scroll_by(delta);
        }
        tuie::dirty_layout();
    }

    fn refresh(&mut self) {
        let text = match self.tab {
            FilterStatsTab::Execution => format_execution_stats(&self.snapshot.exec_stats),
            FilterStatsTab::Status => format_filter_statuses(&self.snapshot.statuses),
        };

        if let Some(widget) = self.root.get_widget_mut(self.text_id) {
            widget.set_content(text);
        }

        if let Some(pane) = self.root.get_widget_mut(self.scroll_id) {
            pane.set_scroll_progress(Axis2D::Y, 0.0);
        }

        tuie::dirty_layout();
    }

    fn request_refresh(&mut self) {
        if self.refreshing {
            return;
        }

        self.refreshing = true;
        self.set_footer_message("refreshing filter stats...");

        let dbstate = self.dbstate.clone();
        let refresh_tx = self.refresh_tx.clone();

        tokio::spawn(async move {
            let result = dbstate.select_filter_stats().await;
            let _ = refresh_tx.send(result);
            tuie::dirty_layout();
        });
        tuie::dirty_layout();
    }

    fn poll_refresh_results(&mut self) {
        while let Ok(result) = self.refresh_rx.try_recv() {
            self.refreshing = false;

            match result {
                Ok(snapshot) => {
                    self.snapshot = snapshot;
                    self.refresh();
                }
                Err(err) => {
                    self.set_footer_message(format!("refresh failed: {err:#}"));
                }
            }
        }
    }

    fn set_footer_message(&mut self, message: impl Into<String>) {
        let body = match self.tab {
            FilterStatsTab::Execution => format_execution_stats(&self.snapshot.exec_stats),
            FilterStatsTab::Status => format_filter_statuses(&self.snapshot.statuses),
        };

        let mut text = body;
        text.push_str("\n\n");
        text.push_str(&message.into());

        if let Some(widget) = self.root.get_widget_mut(self.text_id) {
            widget.set_content(text);
        }

        tuie::dirty_layout();
    }
}

impl DelegateWidget for FilterStatsPopup {
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
            chord!(Esc | q) => {
                queue.next();
                self.close();
                InputResult::Handled
            }
            chord!(r) => {
                queue.next();
                self.request_refresh();
                InputResult::Handled
            }
            chord!(Left | h) => {
                queue.next();
                self.switch_left();
                InputResult::Handled
            }
            chord!(Right | l) => {
                queue.next();
                self.switch_right();
                InputResult::Handled
            }
            chord!(Down | j) => {
                queue.next();
                self.scroll_by(1);
                InputResult::Handled
            }
            chord!(Up | k) => {
                queue.next();
                self.scroll_by(-1);
                InputResult::Handled
            }
            chord!(Shift + Down | J | PageDown) => {
                queue.next();
                self.scroll_by(10);
                InputResult::Handled
            }
            chord!(Shift + Up | K | PageUp) => {
                queue.next();
                self.scroll_by(-10);
                InputResult::Handled
            }
            _ => InputResult::Rejected,
        }
    }

    fn after_before_layout(&mut self) {
        self.poll_refresh_results();
    }
}

pub fn open_filter_stats_popup(
    dbstate: Arc<DbState>,
    snapshot: FilterStatsSnapshot,
) {
    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));
    let popup = FilterStatsPopup::new(dbstate, snapshot, popup_id.clone());
    let id = popup.get_id().untyped();

    popup_id.set(Some(id));

    tuie::open_popup(Popup::new(popup).dismissible());
}

fn format_execution_stats(rows: &[FilterExecStatsRow]) -> String {
    let mut out = String::new();

    out.push_str("[execution stats]\n\n");
    out.push_str(&format!(
        "{:<24} {:<8} {:>8} {:>10} {:>10} {:>10}  {}\n",
        "filter", "phase", "runs", "min_us", "avg_us", "max_us", "filter_id",
    ));
    out.push_str(&format!("{}\n", "-".repeat(100)));

    if rows.is_empty() {
        out.push_str("no filter execution stats yet\n");
        return out;
    }

    for row in rows {
        out.push_str(&format!(
            "{:<24} {:<8} {:>8} {:>10} {:>10.1} {:>10}  {}\n",
            truncate(&row.filter_name, 24),
            row.phase,
            row.runs,
            row.min_us.unwrap_or_default(),
            row.avg_us.unwrap_or_default(),
            row.max_us.unwrap_or_default(),
            row.filter_id.as_deref().unwrap_or("-"),
        ));
    }

    out
}

fn format_filter_statuses(rows: &[FilterStatusRow]) -> String {
    let mut out = String::new();

    out.push_str("[filter status]\n\n");
    out.push_str(&format!(
        "{:<10} {:<7} {:<4} {:>4} {:<18} {:<26} {:<9} {:<12}\n",
        "src",
        "state",
        "on",
        "prio",
        "name",
        "file",
        "program",
        "loaded",
    ));
    out.push_str(&format!("{}\n", "-".repeat(104)));

    if rows.is_empty() {
        out.push_str("no loaded filter statuses yet\n");
        return out;
    }

    for row in rows {
        out.push_str(&format!(
            "{:<10} {:<7} {:<4} {:>4} {:<18} {:<26} {:<9} {:<12}\n",
            &row.source_kind,
            bool_valid(row.valid),
            bool_short(row.enabled),
            row.priority
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate(&row.name, 18),
            truncate(&row.file_name, 26),
            truncate(row.program_kind.as_deref().unwrap_or("-"), 9),
            rfc3999_to_local(&row.loaded_at),
        ));

        if let Some(last_error) = row
            .last_error
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            out.push_str("      error: ");
            out.push_str(last_error);
            out.push('\n');
        }
    }

    out
}

fn rfc3999_to_local(rfc3339_str: &str) -> String {
    let parsed_time = DateTime::parse_from_rfc3339(rfc3339_str)
        .unwrap_or(rfc3339_str.to_string().parse().unwrap());

    let local_time: DateTime<Local> = parsed_time.with_timezone(&Local);
    local_time.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn bool_short(value: i64) -> &'static str {
    if value == 0 {
        "no"
    } else {
        "yes"
    }
}

fn bool_valid(value: i64) -> &'static str {
    if value == 0 {
        "invalid"
    } else {
        "valid"
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let mut out = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    out.push('…');
    out
}