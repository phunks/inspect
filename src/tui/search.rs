//! App-wide key chord handler.

use std::cell::Cell;
use std::rc::Rc;
use chord_macro::chord;
use tuie::prelude::*;
use crate::tui::button::Button;
use crate::tui::focus_pane::FocusPane;

struct PopupHost {
    root: Box<Pane>,
    input_id: WidgetId<Input>,
    search_button_id: WidgetId<Button>,
    cancel_button_id: WidgetId<Button>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
    on_search: Box<dyn Fn(String)>,
}

impl PopupHost {
    fn new(
        root: Box<Pane>,
        input_id: WidgetId<Input>,
        search_button_id: WidgetId<Button>,
        cancel_button_id: WidgetId<Button>,
        popup_id: Rc<Cell<Option<WidgetId>>>,
        on_search: impl Fn(String) + 'static,
    ) -> Box<Self> {
        Box::new(Self {
            root,
            input_id,
            search_button_id,
            cancel_button_id,
            popup_id,
            on_search: Box::new(on_search),
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn search(&self) {
        let query = self
            .root
            .get_widget(self.input_id)
            .map(|input| input.get_string())
            .unwrap_or_default();

        (self.on_search)(query);
        self.close();
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

pub fn open_search_popup(on_search: impl Fn(String) + 'static) {
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
            ])
            .x_scroll(Scrollbar::AutoHide)
            .y_scroll(Scrollbar::AutoHide),
    ]);

    let body = Pane::new()
        .style(Style::new().bg(Color::grey256(3)).blend(95))
        .width(60)
        .vertical()
        .padding(Spacing::balanced(2))
        .gap(1)
        .children([
            Text::new()
                .content("Search URL".fg(Color::Foreground).bold()) as Box<dyn Widget>,
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
                        .children([Text::new().content(" Search ")])
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
        on_search,
    );

    popup_id.set(Some(host.get_id().untyped()));

    tuie::open_popup(
        Popup::new(host)
            .dismissible(true),
    );
}
