//! App-wide key chord handler.

use chord_macro::chord;
use tuie::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use crate::tui::tab::DetailActionBus;
use crate::tui::{theme, PacketListDelegate};

const HELP_TEXT: &str = r#"Key bindings

  q / Ctrl+C        quit
  ?                 show this help

Navigation
  j / Down          move down
  k / Up            move up
  h / Left          move left
  l / Right         move right
  Tab               move to next focus
  Shift+Tab         move to previous focus
  J / Shift+Down    page down
  K / Shift+Up      page up
  G                 jump to bottom
  Esc               close popup

Packet list
  Enter             open details
  a                 mark selected connection as [A]
                    (diff left)
  b                 mark selected connection as [B]
                    (diff right)
  x                 clear both A/B marks
  S                 export HAR
  i                 show filter stats

Detail pane
  D                 open external diff for A/B
                    Uses the selected request/response
                    meta/body tab.
                    Available for request and response
                    tabs only.
  W                 open selected request/response
                    meta/body or ssl/tls in external
                    viewer/editor
  E                 open the selected request/response
                    in the editor

Search
  f                 filter packets
  g                 full-text search
  n                 next full-text search result
  p                 previous full-text search result

Filter query examples
  example.com
  method:GET
  status:2xx
  re:/api/.*
  method:POST && status:4xx
"#;

struct HelpPopup {
    root: Box<Pane>,
    scroll_id: WidgetId<Pane>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
}

impl HelpPopup {
    fn new(
        root: Box<Pane>,
        scroll_id: WidgetId<Pane>,
        popup_id: Rc<Cell<Option<WidgetId>>>,
    ) -> Box<Self> {
        Box::new(Self {
            root,
            scroll_id,
            popup_id,
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn scroll_by(&mut self, delta: i32) {
        if let Some(pane) = self.root.get_widget_mut(self.scroll_id) {
            pane.scroll_by(delta);
        }
        tuie::dirty_layout();
    }

    fn scroll_to(&mut self, progress: f32) {
        if let Some(pane) = self.root.get_widget_mut(self.scroll_id) {
            pane.set_scroll_progress(Axis2D::Y, progress);
        }
        tuie::dirty_layout();
    }
}

impl DelegateWidget for HelpPopup {
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
            chord!(Esc|q) => {
                queue.next();
                self.close();
                InputResult::Handled
            }
            chord!(Down|j) => {
                queue.next();
                self.scroll_by(1);
                InputResult::Handled
            }
            chord!(Up|k) => {
                queue.next();
                self.scroll_by(-1);
                InputResult::Handled
            }
            chord!(Shift+Down|J|PageDown) => {
                queue.next();
                self.scroll_by(8);
                InputResult::Handled
            }
            chord!(Shift+Up|K|PageUp) => {
                queue.next();
                self.scroll_by(-8);
                InputResult::Handled
            }
            chord!(G) => {
                queue.next();
                self.scroll_to(1.0);
                InputResult::Handled
            }
            _ => InputResult::Rejected,
        }
    }
}


fn open_help_popup() {
    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));
    let mut scroll_id = WidgetId::EMPTY;

    let body = Pane::new()
        .style(Style::new().bg(theme::panel_inner_bg()))
        .width(64)
        .height(24)
        .vertical()
        .padding(Spacing::balanced(2))
        .gap(1)
        .children([
            Text::new()
                .content("Help".fg(Color::Foreground).bold()) as Box<dyn Widget>,
            Pane::new()
                .vertical()
                .flex(1)
                .id(&mut scroll_id)
                .y_scroll(Scrollbar::AutoHide)
                .children([
                    Text::new()
                        .content(HELP_TEXT.fg(Color::Foreground))
                        .overflow(TextOverflow::WRAP) as Box<dyn Widget>,
                ]),
            Text::new()
                .content("Esc/q: close  j/k: scroll  J/K: page"
                    .fg(Color::BRIGHT_BLACK))
                .align(Align::End),
        ]);

    let host = HelpPopup::new(body, scroll_id, popup_id.clone());

    popup_id.set(Some(host.get_id().untyped()));

    tuie::open_popup(
        Popup::new(host)
            .dismissible(),
    );
}

/// Root widget wrapper that intercepts app-wide key chords.
pub struct GlobalChords {
    inner: Box<dyn Widget>,
    packet_list_id: WidgetId<PacketListDelegate>,
    detail_bus: DetailActionBus,
}

impl DelegateWidget for GlobalChords {
    tuie::delegate_widget!(inner);

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.peek() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(Char('f')) if queue.is_unhandled() => {
                queue.next();
                if let Some(packet_list) = self.inner.get_widget_mut(self.packet_list_id) {
                    packet_list.open_search();
                }
            }
            chord!(Char('g')) if queue.is_unhandled() => {
                queue.next();
                if let Some(packet_list) = self.inner.get_widget_mut(self.packet_list_id) {
                    packet_list.open_full_text_search();
                }
            }
            chord!(Char('S')) if queue.is_unhandled() => {
                queue.next();
                if let Some(packet_list) = self.inner.get_widget_mut(self.packet_list_id) {
                    packet_list.open_har_export_dialog();
                }
            }
            chord!(Char('i')) if queue.is_unhandled() => {
                queue.next();
                if let Some(packet_list) = self.inner.get_widget_mut(self.packet_list_id) {
                    packet_list.open_filter_stats();
                }
            }
            chord!(Char('n')) if queue.is_unhandled() => {
                queue.next();
                if let Some(packet_list) = self.inner.get_widget_mut(self.packet_list_id) {
                    packet_list.move_retained_full_text_next();
                }
            }
            chord!(Char('p')) if queue.is_unhandled() => {
                queue.next();
                if let Some(packet_list) = self.inner.get_widget_mut(self.packet_list_id) {
                    packet_list.move_retained_full_text_previous();
                }
            }
            chord!(D) if queue.is_unhandled() => {
                queue.next();
                let _ = self.detail_bus.request_external_diff_if_supported();
            }
            chord!(W) if queue.is_unhandled() => {
                queue.next();
                let _ = self.detail_bus.request_external_view_if_supported();
            }
            chord!(E) if queue.is_unhandled() => {
                queue.next();
                let _ = self.detail_bus.request_open_edit_if_supported();
            }
            chord!(Tab) if queue.is_unhandled() => {
                queue.next();
                tuie::focus_next_tab_order(Sign::Positive);
            }
            chord!(Shift + Tab) if queue.is_unhandled() => {
                queue.next();
                tuie::focus_next_tab_order(Sign::Negative);
            }
            chord!(Ctrl + z) => {
                queue.next();
                tuie::suspend();
            }
            chord!('?') if queue.is_unhandled() => {
                queue.next();
                open_help_popup();
            }
            chord!(Ctrl + c | q) => {
                queue.next();
                tuie::quit(0);
            }
            _ => return InputResult::Rejected,
        }

        InputResult::Handled
    }
}

impl GlobalChords {
    /// Wraps `inner` in a [`GlobalChords`] handler.
    pub fn new(
        inner: Box<dyn Widget>,
        packet_list_id: WidgetId<PacketListDelegate>,
        detail_bus: DetailActionBus,
    ) -> Box<Self> {
        Box::new(Self {
            inner,
            packet_list_id,
            detail_bus,
        })
    }
}