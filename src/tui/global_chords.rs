//! App-wide key chord handler.

use chord_macro::chord;
use tuie::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

const HELP_TEXT: &str = "\
Key bindings

  q / Ctrl+C        quit
  ?                 show / close this help

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

Packet
  Enter             open details
  S                 export HAR

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
";

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
        .style(Style::new().bg(Color::grey256(3)).blend(95))
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
}

impl DelegateWidget for GlobalChords {
    tuie::delegate_widget!(inner);

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.peek() else {
            return InputResult::Rejected;
        };

        // let _ = std::fs::OpenOptions::new()
        //     .create(true)
        //     .append(true)
        //     .open("/tmp/mitm_proxy_tuie_keys.log")
        //     .and_then(|mut f| {
        //         use std::io::Write;
        //         writeln!(f, "queue={}", queue.to_string())?;
        //         writeln!(f, "peek={:?}", event.chord)
        //     });

        match &event.chord {
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
            chord!(Ctrl + c|q) => {
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
    pub fn new(inner: Box<dyn Widget>) -> Box<Self> {
        Box::new(Self { inner })
    }
}
