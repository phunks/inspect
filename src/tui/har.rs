use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use tuie::prelude::*;
use tuie::widget::{WidgetId, WidgetMethods};
use crate::mitm::capture::CapturePaths;
use crate::mitm::har::export_current_capture_har;
use crate::tui::button::Button;
use crate::tui::theme;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarExportState {
    Ready,
    Exporting,
    Finished,
}

struct HarExportPopup {
    root: Box<Pane>,
    action_button_id: WidgetId<Button>,
    action_button_text_id: WidgetId<Text>,
    status_text_id: WidgetId<Text>,
    popup_id: Rc<Cell<Option<WidgetId>>>,
    state: HarExportState,
    export_rx: Option<tokio::sync::oneshot::Receiver<anyhow::Result<PathBuf>>>,
}

impl HarExportPopup {
    fn new(
        root: Box<Pane>,
        action_button_id: WidgetId<Button>,
        action_button_text_id: WidgetId<Text>,
        status_text_id: WidgetId<Text>,
        popup_id: Rc<Cell<Option<WidgetId>>>,
    ) -> Box<Self> {
        Box::new(Self {
            root,
            action_button_id,
            action_button_text_id,
            status_text_id,
            popup_id,
            state: HarExportState::Ready,
            export_rx: None,
        })
    }

    fn close(&self) {
        if let Some(id) = self.popup_id.get() {
            tuie::close_popup(id);
        }
    }

    fn set_status(&mut self, text: impl Into<String>) {
        if let Some(status) = self.root.get_widget_mut(self.status_text_id) {
            status.set_content(text.into());
        }
        tuie::dirty_layout();
    }

    fn set_action_label(&mut self, text: impl Into<String>) {
        if let Some(label) = self.root.get_widget_mut(self.action_button_text_id) {
            label.set_content(text.into());
        }
        tuie::dirty_layout();
    }

    fn activate(&mut self) {
        match self.state {
            HarExportState::Ready => self.start_export(),
            HarExportState::Exporting => {}
            HarExportState::Finished => self.close(),
        }
    }

    fn start_export(&mut self) {
        self.state = HarExportState::Exporting;
        self.set_status("Exporting HAR...");
        self.set_action_label(" ... ");

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.export_rx = Some(rx);

        tokio::spawn(async move {
            let result = export_current_capture_har().await;
            let _ = tx.send(result);
        });
    }

    fn finish_export(&mut self, message: String) {
        self.export_rx = None;
        self.state = HarExportState::Finished;
        self.set_status(message);
        self.set_action_label(" Done ");
    }

    fn poll_export_result(&mut self) {
        let Some(rx) = self.export_rx.as_mut() else {
            return;
        };

        match rx.try_recv() {
            Ok(Ok(path)) => {
                self.finish_export(format!("Exported: {}", path.display()));
            }
            Ok(Err(err)) => {
                self.finish_export(format!("Export failed: {err:#}"));
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                self.finish_export("Export failed: worker dropped".to_string());
            }
        }
    }
}

impl DelegateWidget for HarExportPopup {
    fn get_delegate(&self) -> &dyn Widget {
        self.root.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.poll_export_result();
        self.root.as_mut()
    }

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        let Some(event) = queue.peek() else {
            return InputResult::Rejected;
        };

        match &event.chord {
            chord!(Esc) if self.state != HarExportState::Exporting => {
                queue.next();
                self.close();
                InputResult::Handled
            }
            chord!(Enter) => {
                queue.next();
                self.activate();
                InputResult::Handled
            }
            _ => InputResult::Rejected,
        }
    }

    fn after_on_event(&mut self, event: &mut WidgetEvent) {
        if event.of_by::<ClickEvent>(self.action_button_id) {
            self.activate();
        }
    }
}

pub fn open_har_export_popup() {
    let paths = CapturePaths::new();
    let output_path = paths.root.join("inspect.har");

    let mut action_button_id = WidgetId::EMPTY;
    let mut action_button_text_id = WidgetId::EMPTY;
    let mut status_text_id = WidgetId::EMPTY;

    let body = Pane::new()
        .style(Style::new().bg(theme::panel_inner_bg()))
        .width(72)
        .vertical()
        .padding(Spacing::balanced(2))
        .gap(1)
        .children([
            Text::new()
                .content("Export HAR".fg(Color::Foreground).bold()) as Box<dyn Widget>,
            Text::new()
                .content(format!(
                    "Output:\n{}\n\nThis exports headers, timings, and complete bodies when captured with --body-save-unlimited.\nTruncated bodies are omitted and noted in HAR comments.",
                    output_path.display(),
                ).fg(Color::Foreground))
                .overflow(TextOverflow::WRAP) as Box<dyn Widget>,
            Text::new()
                .content("Ok/Enter: export  Esc: close".dim())
                .id(&mut status_text_id),
            Pane::new()
                .horizontal()
                .x_place(Place::End)
                .gap(1)
                .children([
                    Button::new()
                        .children([
                            Text::new()
                                .content(" Ok ")
                                .id(&mut action_button_text_id),
                        ])
                        .id(&mut action_button_id) as Box<dyn Widget>,
                ]),
        ]);

    let popup_id: Rc<Cell<Option<WidgetId>>> = Rc::new(Cell::new(None));

    let host = HarExportPopup::new(
        body,
        action_button_id,
        action_button_text_id,
        status_text_id,
        popup_id.clone(),
    );

    popup_id.set(Some(host.get_id().untyped()));

    tuie::open_popup(
        Popup::new(host)
            .dismissible(),
    );
}
