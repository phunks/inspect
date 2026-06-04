mod read_metadata;
pub mod global_chords;

use std::sync::Arc;
use crate::PacketSummary;
use std::time::Duration;
use chord_macro::chord;
use tokio::sync::{
    mpsc::{
        self, UnboundedReceiver, UnboundedSender
    }, watch};
use tuie::prelude::*;
use read_metadata::DbState;


const MAX_ROWS: usize = 10_000;
const TRIM_ROWS: usize = 1_000;

#[derive(Clone, Debug, Default)]
struct PacketRow {
    id: String,
    time: String,
    method: String,
    status: u16,
    host: String,
    uri: String,
    line: String,
}

#[derive(Debug)]
pub enum UiEvent {
    ShowDetail(String),
}

#[derive(Clone, Copy, Debug)]
struct RowClicked(pub usize);

#[derive(Clone, Debug)]
struct PacketListContext {
    rows: Vec<PacketRow>,
    selected: usize,
    owner_id: WidgetId<PacketListDelegate>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
}

pub struct PacketListDelegate {
    rows: Vec<PacketRow>,
    selected: usize,
    paused: bool,
    follow_tail: bool,
    rx: mpsc::UnboundedReceiver<PacketSummary>,
    list: Box<Pane>,
    list_id: WidgetId<List>,
    task: TaskHandle,
    dbstate: Arc<DbState>,
    detail_tx: UnboundedSender<UiEvent>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
}

impl PacketListDelegate {
    const TICK_INTERVAL: Duration = Duration::from_millis(50);

    pub async fn new(
        rx: mpsc::UnboundedReceiver<PacketSummary>,
        detail_tx: UnboundedSender<UiEvent>,
    ) -> Box<Self> {
        let rows = vec![PacketRow {
            id: String::new(),
            time: "".to_string(),
            method: "".to_string(),
            status: 0,
            host: "".to_string(),
            uri: "".to_string(),
            line: "waiting for packets...".to_string(),
        }];

        let selected = 0;
        let row_clicks = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let mut list_id = WidgetId::EMPTY;

        let mut list = List::new()
            .vertical()
            .flex(1)
            .min_height(5)
            .gap(0)
            .scroll(Scrollbar::AutoHide)
            .bordered()
            .border_style(Style::new().fg(Color::grey256(8)))
            .title("Packets")
            .id(&mut list_id);

        let context = PacketListContext {
            rows: rows.clone(),
            selected,
            owner_id: WidgetId::EMPTY,
            row_clicks: row_clicks.clone(),
        };

        list.set_item_count(context.rows.len());
        list.set_renderer(
            context,
            |ctx: &mut PacketListContext, idx: usize| -> Option<Box<dyn Widget>> {
                let row = ctx.rows.get(idx)?;
                let prefix = if idx == ctx.selected { "> " } else { "  " };
                Some(
                    Text::new()
                        .content(format!("{prefix}{}", row.line))
                        .overflow(TextOverflow::TRUNCATE)
                        .flex(1) as Box<dyn Widget>
                )
            },
        );
        let list = Pane::new()
            .vertical()
            .flex(1)
            .gap(0)
            .children([list]);

        let mut this = Box::new(Self {
            rows,
            selected,
            paused: false,
            follow_tail: true,
            rx,
            list,
            list_id,
            task: TaskHandle::EMPTY,
            dbstate: Arc::new(DbState::new().await.expect("dbstate")),
            detail_tx,
            row_clicks,
        });

        this.task = tuie::schedule(this.get_id(), Self::TICK_INTERVAL, Self::tick);
        this
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
        if self.selected > 0 {
            self.selected -= 1;
            self.follow_tail = false;
            self.sync_list();
        }
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.rows.len() {
            self.selected += 1;

            if self.selected + 1 == self.rows.len() {
                self.follow_tail = true;
            }

            self.sync_list();
        }
    }

    fn page_up(&mut self) {
        let old = self.selected;
        self.selected = self.selected.saturating_sub(20);
        self.follow_tail = false;

        if self.selected != old {
            self.sync_list();
        }
    }

    fn page_down(&mut self) {
        if self.rows.is_empty() {
            return;
        }

        let old = self.selected;
        self.selected = (self.selected + 20).min(self.rows.len() - 1);

        if self.selected + 1 == self.rows.len() {
            self.follow_tail = true;
        }

        if self.selected != old {
            self.sync_list();
        }
    }

    fn jump_to_bottom(&mut self) {
        if self.rows.is_empty() {
            return;
        }

        self.selected = self.rows.len() - 1;
        self.follow_tail = true;
        self.sync_list();
    }

    fn poll_incoming(&mut self) {
        let mut changed = false;

        while let Ok(pkt) = self.rx.try_recv() {
            if self.paused {
                continue;
            }

            let line = format!(
                "{} {:<6} {:<4} {}{}{}",
                pkt.time,
                pkt.method,
                pkt.status,
                pkt.host,
                pkt.uri,
                if pkt.query_str.is_empty() {
                    String::new()
                } else {
                    format!("?{}", pkt.query_str)
                }
            );

            self.rows.push(PacketRow {
                id: pkt.id,
                time: "test time".to_string(),
                method: "test method".to_string(),
                status: 0,
                host: "test host".to_string(),
                uri: "test url".to_string(),
                line,
            });

            changed = true;
        }

        if changed {
            self.trim_rows_if_needed();

            if self.follow_tail && !self.rows.is_empty() {
                self.selected = self.rows.len() - 1;
            }

            self.sync_list();
        }
    }

    fn sync_list(&mut self) {
        let context = PacketListContext {
            rows: self.rows.clone(),
            selected: self.selected,
            owner_id: self.get_id(),
            row_clicks: self.row_clicks.clone(),
        };

        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            list.set_item_count(context.rows.len());
            list.set_renderer(
                context,
                |ctx: &mut PacketListContext, idx: usize| -> Option<Box<dyn Widget>> {
                    let row = ctx.rows.get(idx)?;
                    Some(
                        ClickablePacketRow::new(
                            ctx.owner_id,
                            ctx.row_clicks.clone(),
                            idx,
                            row.line.clone(),
                            idx == ctx.selected,
                        ) as Box<dyn Widget>
                    )
                },
            );
            list.invalidate_all();
        }
    }

    fn sync_list_and_follow_tail(&mut self) {
        self.sync_list();

        if let Some(list) = self.list.get_widget_mut(self.list_id) {
            if !self.rows.is_empty() {
                let last = self.rows.len() - 1;
                list.ensure_visible_scrolloff(last, 2);
            }
        }
    }

    fn trim_rows_if_needed(&mut self) {
        if self.rows.len() <= MAX_ROWS {
            return;
        }

        let drain_count = TRIM_ROWS.min(self.rows.len());
        self.rows.drain(0..drain_count);

        self.selected = self.selected.saturating_sub(drain_count);

        if self.rows.is_empty() {
            self.selected = 0;
            self.follow_tail = true;
        } else if self.selected >= self.rows.len() {
            self.selected = self.rows.len() - 1;
            self.follow_tail = true;
        }
    }

    fn append_system_line(&mut self, line: impl Into<String>) {
        self.rows.push(PacketRow {
            id: String::new(),
            time: "test time".to_string(),
            method: "test method".to_string(),
            status: 0,
            host: "test host".to_string(),
            uri: "test url".to_string(),
            line: line.into(),
        });

        self.trim_rows_if_needed();

        if !self.rows.is_empty() {
            self.selected = self.rows.len() - 1;
        }

        self.follow_tail = true;
        self.sync_list();
    }

    fn toggle_pause(&mut self) {
        self.paused = !self.paused;

        if self.paused {
            self.append_system_line("=== paused ===");
        } else {
            self.append_system_line("=== resumed ===");
        }
    }

    fn selected_packet_id(&self) -> Option<&str> {
        self.rows
            .get(self.selected)
            .and_then(|row| {
                if row.id.is_empty() {
                    None
                } else {
                    Some(row.id.as_str())
                }
            })
    }

    fn on_select_packet(&self, id: String) {
        let db = self.dbstate.clone();
        let detail_tx = self.detail_tx.clone();

        tokio::spawn(async move {
            let req = db.select_request_by_id(id.clone()).await;
            let res = db.select_response_by_id(id.clone()).await;

            let text = match (req, res) {
                (Ok(req), Ok(res)) => {
                    let req_body = read_body_file(req.request_body_path.as_deref()).await;
                    let res_body = read_body_file(res.response_body_path.as_deref()).await;

                    format!(
                        "id: {id}\n\n[request meta]\n{req}\n\n[request body]\n{req_body}\n\n[response meta]\n{res}\n\n[response body]\n{res_body}"
                    )
                }
                (Ok(req), Err(e)) => {
                    let req_body = read_body_file(req.request_body_path.as_deref()).await;
                    format!(
                        "id: {id}\n\n[request meta]\n{req}\n\n[request body]\n{req_body}\n\nresponse error: {e}"
                    )
                }
                (Err(e1), Err(e2)) => {
                    format!("id: {id}\n\nrequest error: {e1}\nresponse error: {e2}")
                }
                (Err(e), _) => format!("id: {id}\n\nrequest error: {e}"),
                (_, Err(e)) => format!("id: {id}\n\nresponse error: {e}"),
            };

            let _ = detail_tx.send(UiEvent::ShowDetail(text));
        });
    }

    fn select_row(&mut self, idx: usize) {
        if idx < self.rows.len() {
            self.selected = idx;
            self.follow_tail = self.selected + 1 == self.rows.len();
            self.sync_list();

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

fn format_body_for_display(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    hexdump_with_ascii(bytes)
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
            chord!(Enter|l) => {
                queue.next();
                self.show_detail();
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
    detail_text_id: WidgetId<Text>,
}

impl RootPane {
    fn new(
        split: Box<Pane>,
        detail_rx: UnboundedReceiver<UiEvent>,
        detail_text_id: WidgetId<Text>,
    ) -> Box<Self> {
        Box::new(Self {
            split,
            detail_rx,
            detail_text_id,
        })
    }

    fn poll_ui_events(&mut self) {
        while let Ok(event) = self.detail_rx.try_recv() {
            match event {
                UiEvent::ShowDetail(text) => {
                    if let Some(detail) = self.split.get_widget_mut(self.detail_text_id) {
                        detail.set_content(text);
                    }
                }
            }
        }
    }
}

impl DelegateWidget for RootPane {
    fn get_delegate(&self) -> &dyn Widget {
        self.split.as_ref()
    }

    fn get_delegate_mut(&mut self) -> &mut dyn Widget {
        self.poll_ui_events();
        self.split.as_mut()
    }

    fn override_on_input(&mut self, queue: &mut InputQueue) -> InputResult {
        self.poll_ui_events();
        InputResult::Rejected
    }
}

struct ClickablePacketRow {
    layout: Layout,
    owner_id: WidgetId<PacketListDelegate>,
    row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
    idx: usize,
    text: String,
    selected: bool,
    pressed: std::cell::Cell<bool>,
}
impl ClickablePacketRow {
    fn new(
        owner_id: WidgetId<PacketListDelegate>,
        row_clicks: Arc<parking_lot::Mutex<Vec<usize>>>,
        idx: usize,
        text: String,
        selected: bool,
    ) -> Box<Self> {
        Box::new(Self {
            layout: Layout::new(),
            owner_id,
            row_clicks,
            idx,
            text,
            selected,
            pressed: std::cell::Cell::new(false),
        })
    }

    fn hit(&self, pos: Vec2<i32>) -> bool {
        let size = self.get_rect_size();
        pos.x >= 0 && pos.y >= 0 && pos.x < size.x as i32 && pos.y < size.y as i32
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
                if self.hit(event.mouse_pos) {
                    tuie::focus_widget(self.owner_id);
                    self.row_clicks.lock().push(self.idx);
                    return InputResult::Handled;
                }
                InputResult::Rejected
            }
            chord!(LeftRelease) => {
                let was_pressed = self.pressed.get();
                self.pressed.set(false);
                if was_pressed && self.hit(event.mouse_pos) {
                    tuie::emit(self.owner_id, RowClicked(self.idx));
                    return InputResult::Handled;
                }
                InputResult::Rejected
            }
            _ => InputResult::Rejected,
        }
    }
}


pub async fn run_tui(rx: mpsc::UnboundedReceiver<PacketSummary>) -> anyhow::Result<()> {
    let (detail_tx, detail_rx) = mpsc::unbounded_channel::<UiEvent>();

    let app: Box<dyn Widget> = PacketListDelegate::new(rx, detail_tx).await;

    let mut detail_text_id = WidgetId::EMPTY;
    let split = Pane::new()
        .vertical()
        .flex(1)
        .gap(0)
        .children([Split::new(
        SplitPane::horizontal()
            .children([
                SplitPaneChild::from(Pane::new()
                    .preferred_width(60)
                    .preferred_height(1)
                    .vertical()
                    .flex(1)
                    .children([
                        app
                    ])),
                SplitPaneChild::from(Pane::new()
                    .preferred_width(40)
                    .preferred_height(1)
                    .vertical()
                    .flex(1)
                    .title("Details")
                    .bordered()
                    .border_style(Style::new().fg(Color::grey256(8)))
                    .children([
                        Text::new()
                            .content("Select row and press Enter".dim())
                            .overflow(TextOverflow::WRAP)
                            .id(&mut detail_text_id).flex(1),
                    ])
                    .y_scroll(Scrollbar::Visible),
                ),
            ])
        ).flex(1)]
    );

    let root = RootPane::new(split, detail_rx, detail_text_id);
    let root = global_chords::GlobalChords::new(root);

    tuie::start_tui(root)?;
    Ok(())
}
