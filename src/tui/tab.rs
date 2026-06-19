use tuie::prelude::*;
use tuie::prelude::Scrollbar::AutoHide;
use crate::tui::{highlight_detail_text, DETAIL_PLACEHOLDER_TEXT};
use crate::tui::segmented_control::SegmentedControl;

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
    pub id: String,
    pub dir: String,
}

#[derive(Debug)]
pub enum UiEvent {
    ShowDetail {
        detail: DetailContent,
        highlight_query: Option<String>,
        tab_selection: Option<DetailTabSelection>,
    },
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
}

impl DetailPane {
    pub(crate) fn new() -> Box<Self> {
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
        });

        this.sync_message_part_visibility();
        this
    }

    pub(crate) fn set_content(
        &mut self,
        content: DetailContent,
        highlight_query: Option<String>,
        tab_selection: Option<DetailTabSelection>,
    ) {
        self.content = content;
        self.highlight_query = highlight_query;

        if let Some(tab_selection) = tab_selection {
            self.select_tab(tab_selection);
        }

        self.sync_message_part_visibility();
        self.refresh_text();
    }

    fn select_tab(&mut self, tab_selection: DetailTabSelection) {
        self.primary_tab = tab_selection.primary_tab.into();
        self.message_part = tab_selection.message_part.into();

        if let Some(ctrl) = self.root.get_widget_mut(self.primary_tab_id) {
            ctrl.set_selected(match self.primary_tab {
                DetailPrimaryTab::Request => 0,
                DetailPrimaryTab::Response => 1,
                DetailPrimaryTab::SslTls => 2,
                DetailPrimaryTab::Info => 3,
            });
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
            self.primary_tab = match ctrl.get_selected() {
                1 => DetailPrimaryTab::Response,
                2 => DetailPrimaryTab::SslTls,
                3 => DetailPrimaryTab::Info,
                _ => DetailPrimaryTab::Request,
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