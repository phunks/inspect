use tuie::prelude::*;
use tuie::prelude::Scrollbar::AutoHide;
use crate::tui::{highlight_detail_text, DETAIL_PLACEHOLDER_TEXT};
use crate::tui::segmented_control::SegmentedControl;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailMessageType {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailMessagePart {
    Meta,
    Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailMessageInfo {
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetailTabSelection {
    pub message_type: DetailMessageTypeSelection,
    pub message_part: DetailMessagePartSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailMessageTypeSelection {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailMessagePartSelection {
    Meta,
    Body,
}

impl From<DetailMessageTypeSelection> for DetailMessageType {
    fn from(value: DetailMessageTypeSelection) -> Self {
        match value {
            DetailMessageTypeSelection::Request => Self::Request,
            DetailMessageTypeSelection::Response => Self::Response,
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
    message_type_id: WidgetId<SegmentedControl>,
    message_part_id: WidgetId<SegmentedControl>,
    message_info_id: WidgetId<SegmentedControl>,
    text_id: WidgetId<Text>,
    content: DetailContent,
    message_type: DetailMessageType,
    message_part: DetailMessagePart,
    message_info: Option<DetailMessageInfo>,
    highlight_query: Option<String>,
}

impl DetailPane {
    pub(crate) fn new() -> Box<Self> {
        let mut message_type_id = WidgetId::EMPTY;
        let mut message_part_id = WidgetId::EMPTY;
        let mut message_info_id = WidgetId::EMPTY;
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

        let controls = Pane::new()
            .horizontal()
            .gap(0)
            .children([
                row(
                    "",
                    SegmentedControl::new(&["request", "response"])
                        .selected(0)
                        .id(&mut message_type_id),
                ) as Box<dyn Widget>,
                Text::new().content("|"),
                row(
                    "",
                    SegmentedControl::new(&["meta", "body"])
                        .selected(0)
                        .id(&mut message_part_id),
                ),
                Text::new().content("|"),
                row(
                    "",
                    SegmentedControl::new(&["info"])
                        .selected(0)
                        .id(&mut message_info_id),
                ),
            ]);

        let root = Pane::new()
            .vertical()
            .flex(1)
            .gap(0)
            .children([
                row("",controls as Box<dyn Widget>),
                Pane::new()
                    .horizontal()
                    .gap(0)
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
            message_type_id,
            message_part_id,
            message_info_id,
            text_id,
            content: DetailContent::default(),
            message_type: DetailMessageType::Request,
            message_part: DetailMessagePart::Meta,
            message_info: None,
            highlight_query: None,
        });

        if let Some(ctrl) = this.root.get_widget_mut(this.message_info_id) {
            ctrl.clear_selected();
        }

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

        self.refresh_text();
    }

    fn select_tab(&mut self, tab_selection: DetailTabSelection) {
        self.message_type = tab_selection.message_type.into();
        self.message_part = tab_selection.message_part.into();
        self.message_info = None;

        if let Some(ctrl) = self.root.get_widget_mut(self.message_type_id) {
            ctrl.set_selected(match self.message_type {
                DetailMessageType::Request => 0,
                DetailMessageType::Response => 1,
            });
        }

        if let Some(ctrl) = self.root.get_widget_mut(self.message_part_id) {
            ctrl.set_selected(match self.message_part {
                DetailMessagePart::Meta => 0,
                DetailMessagePart::Body => 1,
            });
        }

        if let Some(ctrl) = self.root.get_widget_mut(self.message_info_id) {
            ctrl.clear_selected();
        }
    }

    fn selected_text(&self) -> String {
        if matches!(self.message_info, Some(DetailMessageInfo::Info)) {
            return format!(
                "id  : {}\ndir : {}",
                self.content.id,
                self.content.dir,
            );
        }

        match (self.message_type, self.message_part) {
            (DetailMessageType::Request, DetailMessagePart::Meta) => {
                self.content.request_meta.clone()
            }
            (DetailMessageType::Request, DetailMessagePart::Body) => {
                self.content.request_body.clone()
            }
            (DetailMessageType::Response, DetailMessagePart::Meta) => {
                self.content.response_meta.clone()
            }
            (DetailMessageType::Response, DetailMessagePart::Body) => {
                self.content.response_body.clone()
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

    fn sync_from_controls(&mut self) {
        if let Some(ctrl) = self.root.get_widget(self.message_type_id) {
            self.message_type = match ctrl.get_selected() {
                1 => DetailMessageType::Response,
                _ => DetailMessageType::Request,
            };
        }

        if let Some(ctrl) = self.root.get_widget(self.message_part_id) {
            self.message_part = match ctrl.get_selected() {
                1 => DetailMessagePart::Body,
                _ => DetailMessagePart::Meta,
            };
        }

        self.message_info = None;

        if let Some(ctrl) = self.root.get_widget_mut(self.message_info_id) {
            ctrl.clear_selected();
        }

        self.refresh_text();
    }

    fn sync_info_from_control(&mut self) {
        self.message_info = Some(DetailMessageInfo::Info);

        if let Some(ctrl) = self.root.get_widget_mut(self.message_info_id) {
            ctrl.set_selected(0);
        }

        self.refresh_text();
    }
}

impl DelegateWidget for DetailPane {
    fn get_delegate(&self) -> &dyn Widget {
        self.root.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.root.as_mut()
    }

    fn after_on_event(&mut self, event: &mut WidgetEvent) {
        if event.get_by::<ChangeEvent<usize>>(self.message_info_id).is_some() {
            self.sync_info_from_control();
        } else if event.get_by::<ChangeEvent<usize>>(self.message_type_id).is_some()
            || event.get_by::<ChangeEvent<usize>>(self.message_part_id).is_some()
        {
            self.sync_from_controls();
        }
    }
}