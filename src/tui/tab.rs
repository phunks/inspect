use std::sync::Arc;
use parking_lot::Mutex;
use tuie::prelude::*;
use tuie::prelude::Scrollbar::AutoHide;
use crate::tui::{highlight_detail_text, DETAIL_PLACEHOLDER_TEXT};
use crate::tui::segmented_control::SegmentedControl;

pub type SharedDetailEditState = Arc<Mutex<DetailEditState>>;
pub type SharedOpenEditRequests = Arc<Mutex<Vec<()>>>;
pub type SharedExternalDiffRequests = Arc<Mutex<Vec<DetailTabSelection>>>;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailPrimaryTab {
    Request,
    Response,
    SslTls,
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailMessagePart {
    Meta,
    Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetailTabSelection {
    pub primary_tab: DetailPrimaryTabSelection,
    pub message_part: DetailMessagePartSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailPrimaryTabSelection {
    Request,
    Response,
    SslTls,
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailMessagePartSelection {
    Meta,
    Body,
}

impl From<DetailPrimaryTabSelection> for DetailPrimaryTab {
    fn from(value: DetailPrimaryTabSelection) -> Self {
        match value {
            DetailPrimaryTabSelection::Request => Self::Request,
            DetailPrimaryTabSelection::Response => Self::Response,
            DetailPrimaryTabSelection::SslTls => Self::SslTls,
            DetailPrimaryTabSelection::Info => Self::Info,
        }
    }
}

impl From<DetailMessagePartSelection> for DetailMessagePart {
    fn from(value: DetailMessagePartSelection) -> Self {
        match value {
            DetailMessagePartSelection::Meta => Self::Meta,
            DetailMessagePartSelection::Body => Self::Body,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DetailContent {
    pub request_meta: String,
    pub request_body: String,
    pub response_meta: String,
    pub response_body: String,
    pub ssl_tls_info: String,
    pub tunnel_info: Option<String>,
    pub id: String,
    pub dir: String,
}

// #[derive(Debug)]
// pub enum UiEvent {
//     ShowDetail {
//         detail: DetailContent,
//         highlight_query: Option<String>,
//         tab_selection: Option<DetailTabSelection>,
//     },
// }

#[derive(Clone, Debug)]
pub struct DetailEditState {
    pub selection: DetailTabSelection,
    pub content: DetailContent,
}

impl Default for DetailEditState {
    fn default() -> Self {
        Self {
            selection: DetailTabSelection {
                primary_tab: DetailPrimaryTabSelection::Request,
                message_part: DetailMessagePartSelection::Meta,
            },
            content: DetailContent::default(),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct DetailActionBus {
    edit_state: SharedDetailEditState,
    open_edit_requests: SharedOpenEditRequests,
    external_diff_requests: SharedExternalDiffRequests,
}

impl DetailActionBus {
    pub fn set_edit_state(&self, state: DetailEditState) {
        *self.edit_state.lock() = state;
    }

    pub fn edit_state(&self) -> DetailEditState {
        self.edit_state.lock().clone()
    }

    pub fn request_open_edit(&self) {
        self.open_edit_requests.lock().push(());
    }

    pub fn request_open_edit_if_supported(&self) -> bool {
        let selection = self.edit_state().selection;

        match selection.primary_tab {
            DetailPrimaryTabSelection::Request | DetailPrimaryTabSelection::Response => {
                self.request_open_edit();
                true
            }
            DetailPrimaryTabSelection::SslTls | DetailPrimaryTabSelection::Info => false,
        }
    }

    pub fn take_open_edit_requests(&self) -> usize {
        let mut requests = self.open_edit_requests.lock();
        let count = requests.len();
        requests.clear();
        count
    }

    pub fn request_external_diff_if_supported(&self) -> bool {
        let selection = self.edit_state().selection;

        match selection.primary_tab {
            DetailPrimaryTabSelection::Request
            | DetailPrimaryTabSelection::Response
            | DetailPrimaryTabSelection::SslTls => {
                self.external_diff_requests.lock().push(selection);
                true
            }
            DetailPrimaryTabSelection::Info => false,
        }
    }

    pub fn take_external_diff_requests(&self) -> Vec<DetailTabSelection> {
        std::mem::take(&mut *self.external_diff_requests.lock())
    }
}

pub struct DetailPane {
    root: Box<Pane>,
    primary_tab_id: WidgetId<SegmentedControl>,
    message_part_row_id: WidgetId<Pane>,
    message_part_id: WidgetId<SegmentedControl>,
    text_scroll_id: WidgetId<Pane>,
    #[allow(unused)]
    separator_id: WidgetId<Text>,
    text_id: WidgetId<Text>,
    content: DetailContent,
    primary_tab: DetailPrimaryTab,
    message_part: DetailMessagePart,
    highlight_query: Option<String>,
    bus: DetailActionBus,
}

impl DetailPane {
    pub(crate) fn new(
        bus: DetailActionBus,
    ) -> Box<Self> {
        let mut primary_tab_id = WidgetId::EMPTY;
        let mut message_part_row_id = WidgetId::EMPTY;
        let mut message_part_id = WidgetId::EMPTY;
        let mut text_scroll_id = WidgetId::EMPTY;
        let separator_id = WidgetId::EMPTY;
        let mut text_id = WidgetId::EMPTY;

        let row = |label: &str, ctrl: Box<dyn Widget>| -> Box<Pane> {
            Pane::new()
                .horizontal()
                .gap(0)
                .children([
                    Pane::new()
                        .horizontal()
                        .width(0)
                        .children([
                            Text::new().content(label.fg(Color::grey256(11))) as Box<dyn Widget>,
                        ]) as Box<dyn Widget>,
                    ctrl,
                ])
        };

        let primary_controls = Pane::new()
            .horizontal()
            .gap(0)
            .children([
                row(
                    "",
                    SegmentedControl::new(&["request", "response", "ssl/tls", "info"])
                        .selected(0)
                        .id(&mut primary_tab_id),
                ) as Box<dyn Widget>,
            ]);

        let part_controls = Pane::new()
            .horizontal()
            .gap(0)
            .id(&mut message_part_row_id)
            .children([
                row(
                    "",
                    SegmentedControl::new(&["meta", "body"])
                        .selected(0)
                        .id(&mut message_part_id),
                ) as Box<dyn Widget>,
            ]);

        let root = Pane::new()
            .vertical()
            .flex(1)
            .gap(0)
            .children([
                row("", primary_controls as Box<dyn Widget>),
                part_controls as Box<dyn Widget>,
                Pane::new()
                    .vertical()
                    .gap(0)
                    .id(&mut text_scroll_id)
                    .children([Text::new()
                        .content(DETAIL_PLACEHOLDER_TEXT.dim())
                        .overflow(TextOverflow::WRAP)
                        .id(&mut text_id)
                        .flex(1)])
                    .flex(1)
                    .y_scroll(AutoHide) as Box<dyn Widget>,
            ]);

        let mut this = Box::new(Self {
            root,
            primary_tab_id,
            message_part_row_id,
            message_part_id,
            text_scroll_id,
            separator_id,
            text_id,
            content: DetailContent::default(),
            primary_tab: DetailPrimaryTab::Request,
            message_part: DetailMessagePart::Meta,
            highlight_query: None,
            bus,
        });

        this.sync_message_part_visibility();
        this.sync_edit_state();
        this
    }

    pub(crate) fn set_content(
        &mut self,
        content: DetailContent,
        highlight_query: Option<String>,
        tab_selection: Option<DetailTabSelection>,
    ) {
        let was_tunnel_failure = self.is_tunnel_failure();

        self.content = content;
        self.highlight_query = highlight_query;
        self.sync_primary_tab_labels();

        if self.is_tunnel_failure() {
            if !matches!(self.primary_tab, DetailPrimaryTab::SslTls | DetailPrimaryTab::Info) {
                self.primary_tab = DetailPrimaryTab::SslTls;
            }

            self.message_part = DetailMessagePart::Meta;

            let primary_tab_index = self.primary_tab_index();

            if let Some(ctrl) = self.root.get_widget_mut(self.primary_tab_id) {
                ctrl.set_selected(primary_tab_index);
            }
        } else {
            if let Some(tab_selection) = tab_selection {
                self.select_tab(tab_selection);
            } else if was_tunnel_failure {
                let primary_tab_index = self.primary_tab_index();

                if let Some(ctrl) = self.root.get_widget_mut(self.primary_tab_id) {
                    ctrl.set_selected(primary_tab_index);
                }
            }
        }

        self.sync_message_part_visibility();
        self.refresh_text();
        self.sync_edit_state();
    }

    fn current_selection(&self) -> DetailTabSelection {
        DetailTabSelection {
            primary_tab: match self.primary_tab {
                DetailPrimaryTab::Request => DetailPrimaryTabSelection::Request,
                DetailPrimaryTab::Response => DetailPrimaryTabSelection::Response,
                DetailPrimaryTab::SslTls => DetailPrimaryTabSelection::SslTls,
                DetailPrimaryTab::Info => DetailPrimaryTabSelection::Info,
            },
            message_part: match self.message_part {
                DetailMessagePart::Meta => DetailMessagePartSelection::Meta,
                DetailMessagePart::Body => DetailMessagePartSelection::Body,
            },
        }
    }

    fn sync_edit_state(&self) {
        self.bus.set_edit_state(DetailEditState {
            selection: self.current_selection(),
            content: self.content.clone(),
        });
    }

    fn is_tunnel_failure(&self) -> bool {
        self.content.tunnel_info.is_some()
    }

    fn sync_primary_tab_labels(&mut self) {
        let tunnel_failure = self.is_tunnel_failure();

        if let Some(ctrl) = self.root.get_widget_mut(self.primary_tab_id) {
            if tunnel_failure {
                ctrl.set_labels(&["ssl/tls", "info"]);
            } else {
                ctrl.set_labels(&["request", "response", "ssl/tls", "info"]);
            }
        }
    }

    fn primary_tab_index(&self) -> usize {
        if self.is_tunnel_failure() {
            match self.primary_tab {
                DetailPrimaryTab::Info => 1,
                _ => 0,
            }
        } else {
            match self.primary_tab {
                DetailPrimaryTab::Request => 0,
                DetailPrimaryTab::Response => 1,
                DetailPrimaryTab::SslTls => 2,
                DetailPrimaryTab::Info => 3,
            }
        }
    }

    fn select_tab(&mut self, tab_selection: DetailTabSelection) {
        self.primary_tab = tab_selection.primary_tab.into();
        self.message_part = tab_selection.message_part.into();

        let primary_tab_index = self.primary_tab_index();

        if let Some(ctrl) = self.root.get_widget_mut(self.primary_tab_id) {
            ctrl.set_selected(primary_tab_index);
        }

        if let Some(ctrl) = self.root.get_widget_mut(self.message_part_id) {
            ctrl.set_selected(match self.message_part {
                DetailMessagePart::Meta => 0,
                DetailMessagePart::Body => 1,
            });
        }
    }

    fn selected_text(&self) -> String {
        match self.primary_tab {
            DetailPrimaryTab::Request => {
                match self.message_part {
                    DetailMessagePart::Meta => self.content.request_meta.clone(),
                    DetailMessagePart::Body => self.content.request_body.clone(),
                }
            }
            DetailPrimaryTab::Response => {
                match self.message_part {
                    DetailMessagePart::Meta => self.content.response_meta.clone(),
                    DetailMessagePart::Body => self.content.response_body.clone(),
                }
            }
            DetailPrimaryTab::SslTls => {
                self.content.ssl_tls_info.clone()
            }
            DetailPrimaryTab::Info => {
                format!(
                    "id  : {}\ndir : {}",
                    self.content.id,
                    self.content.dir,
                )
            }
        }
    }

    fn refresh_text(&mut self) {
        let text = self.selected_text();

        if let Some(detail) = self.root.get_widget_mut(self.text_id) {
            if let Some(query) = self.highlight_query.as_deref() {
                detail.set_content(highlight_detail_text(&text, query));
            } else {
                detail.set_content(text);
            }
        }
    }

    fn scroll_text_by(&mut self, delta: i32) {
        if let Some(pane) = self.root.get_widget_mut(self.text_scroll_id) {
            pane.scroll_by(delta);
        }
    }

    fn sync_from_controls(&mut self) {
        if let Some(ctrl) = self.root.get_widget(self.primary_tab_id) {
            self.primary_tab = if self.is_tunnel_failure() {
                match ctrl.get_selected() {
                    1 => DetailPrimaryTab::Info,
                    _ => DetailPrimaryTab::SslTls,
                }
            } else {
                match ctrl.get_selected() {
                    1 => DetailPrimaryTab::Response,
                    2 => DetailPrimaryTab::SslTls,
                    3 => DetailPrimaryTab::Info,
                    _ => DetailPrimaryTab::Request,
                }
            };
        }

        if let Some(ctrl) = self.root.get_widget(self.message_part_id) {
            self.message_part = match ctrl.get_selected() {
                1 => DetailMessagePart::Body,
                _ => DetailMessagePart::Meta,
            };
        }

        self.sync_message_part_visibility();
        self.refresh_text();
        self.sync_edit_state();
    }

    fn sync_message_part_visibility(&mut self) {
        let show_message_part = matches!(
                self.primary_tab,
                DetailPrimaryTab::Request | DetailPrimaryTab::Response
            );

        if let Some(row) = self.root.get_widget_mut(self.message_part_row_id) {
            if show_message_part {
                row.set_height(Some(1));
            } else {
                row.set_height(Some(0));
            }
        }

        if let Some(ctrl) = self.root.get_widget_mut(self.message_part_id) {
            ctrl.set_control_disabled(!show_message_part);

            if show_message_part {
                ctrl.set_selected(match self.message_part {
                    DetailMessagePart::Meta => 0,
                    DetailMessagePart::Body => 1,
                });
            } else {
                ctrl.clear_selected();
            }
        }

        tuie::dirty_layout();
    }
}

impl DelegateWidget for DetailPane {
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
            chord!(D) if queue.is_unhandled() => {
                queue.next();
                let _ = self.bus.request_external_diff_if_supported();
                InputResult::Handled
            }
            chord!(E) if queue.is_unhandled() => {
                queue.next();
                let _ = self.bus.request_open_edit_if_supported();
                InputResult::Handled
            }
            chord!(Up | k) => {
                queue.next();
                self.scroll_text_by(-1);
                InputResult::Handled
            }
            chord!(Down | j) => {
                queue.next();
                self.scroll_text_by(1);
                InputResult::Handled
            }
            chord!(Shift + Up | K) => {
                queue.next();
                self.scroll_text_by(-10);
                InputResult::Handled
            }
            chord!(Shift + Down | J) => {
                queue.next();
                self.scroll_text_by(10);
                InputResult::Handled
            }
            _ => self.root.on_input(queue),
        }
    }

    fn after_on_event(&mut self, event: &mut WidgetEvent) {
        if event.get_by::<ChangeEvent<usize>>(self.primary_tab_id).is_some()
            || event.get_by::<ChangeEvent<usize>>(self.message_part_id).is_some()
        {
            self.sync_from_controls();
        }
    }
}