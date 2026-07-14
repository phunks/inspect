// src/mitm/flow/sse_capture.rs

use std::path::PathBuf;

use bytes::Bytes;
use tokio::sync::mpsc;

const SSE_CAPTURE_MARKER_FILE: &str = "response.body.sse";
const SSE_CAPTURE_PARTIAL_FILE: &str = "response.body.partial";

enum SseCaptureMessage {
    Event {
        sequence: usize,
        bytes: Bytes,
    },
    Partial(Bytes),
}

pub struct SseCapture {
    tx: mpsc::UnboundedSender<SseCaptureMessage>,
    buffer: Vec<u8>,
    max_events: usize,
    max_event_bytes: usize,
    saved_events: usize,
    discarding_oversized_event: bool,
    finished: bool,
}

impl SseCapture {
    pub fn start(
        flow_dir: PathBuf,
        max_events: usize,
        max_event_bytes: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            if let Err(err) = tokio::fs::write(
                flow_dir.join(SSE_CAPTURE_MARKER_FILE),
                b"<SSE stream; events are stored in response.body.NNN>\n",
            )
                .await
            {
                tracing::error!(
                    path = %flow_dir.display(),
                    error = ?err,
                    "failed to write SSE capture marker"
                );
                return;
            }

            while let Some(message) = rx.recv().await {
                let (path, bytes) = match message {
                    SseCaptureMessage::Event { sequence, bytes } => (
                        flow_dir.join(format!("response.body.{sequence:03}")),
                        bytes,
                    ),
                    SseCaptureMessage::Partial(bytes) => {
                        (flow_dir.join(SSE_CAPTURE_PARTIAL_FILE), bytes)
                    }
                };

                if let Err(err) = tokio::fs::write(&path, bytes).await {
                    tracing::error!(
                        path = %path.display(),
                        error = ?err,
                        "failed to write SSE capture event"
                    );
                }
            }
        });

        Self {
            tx,
            buffer: Vec::new(),
            max_events,
            max_event_bytes,
            saved_events: 0,
            discarding_oversized_event: false,
            finished: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.finished || self.capture_limit_reached() {
            return;
        }

        self.buffer.extend_from_slice(bytes);

        loop {
            let Some(event_end) = find_sse_event_end(&self.buffer) else {
                self.handle_oversized_incomplete_event();
                return;
            };

            let event = self.buffer.drain(..event_end).collect::<Vec<_>>();

            if self.discarding_oversized_event {
                self.discarding_oversized_event = false;
                continue;
            }

            self.save_event(event);
            if self.capture_limit_reached() {
                self.buffer.clear();
                return;
            }
        }
    }

    pub fn finish(&mut self) {
        if self.finished {
            return;
        }

        self.finished = true;

        if self.buffer.is_empty()
            || self.discarding_oversized_event
            || self.capture_limit_reached()
        {
            return;
        }

        let bytes = truncate_event(
            std::mem::take(&mut self.buffer),
            self.max_event_bytes,
        );
        let _ = self.tx.send(SseCaptureMessage::Partial(Bytes::from(bytes)));
    }

    fn capture_limit_reached(&self) -> bool {
        self.max_events == 0
            || self.max_event_bytes == 0
            || self.saved_events >= self.max_events
    }

    fn handle_oversized_incomplete_event(&mut self) {
        if self.discarding_oversized_event || self.max_event_bytes == 0 {
            return;
        }

        if self.buffer.len() <= self.max_event_bytes {
            return;
        }

        let event = self.buffer[..self.max_event_bytes].to_vec();
        self.save_event_with_truncation(event);
        self.discarding_oversized_event = true;

        // Preserve enough trailing bytes to recognize an SSE terminator split
        // across subsequent HTTP body frames.
        let keep_from = self.buffer.len().saturating_sub(3);
        self.buffer.drain(..keep_from);
    }

    fn save_event(&mut self, event: Vec<u8>) {
        if event.len() > self.max_event_bytes {
            self.save_event_with_truncation(event);
            return;
        }

        self.saved_events += 1;
        let _ = self.tx.send(SseCaptureMessage::Event {
            sequence: self.saved_events,
            bytes: Bytes::from(event),
        });
    }

    fn save_event_with_truncation(&mut self, event: Vec<u8>) {
        let event = truncate_event(event, self.max_event_bytes);
        self.saved_events += 1;

        let _ = self.tx.send(SseCaptureMessage::Event {
            sequence: self.saved_events,
            bytes: Bytes::from(event),
        });
    }
}

impl Drop for SseCapture {
    fn drop(&mut self) {
        self.finish();
    }
}

fn truncate_event(mut event: Vec<u8>, max_event_bytes: usize) -> Vec<u8> {
    event.truncate(max_event_bytes);
    event.extend_from_slice(
        format!(
            "\n<< inspect SSE event capture truncated: max_event_bytes={max_event_bytes} >>\n"
        )
            .as_bytes(),
    );
    event
}

fn find_sse_event_end(bytes: &[u8]) -> Option<usize> {
    let mut index = 0;

    while index < bytes.len() {
        let remaining = &bytes[index..];

        if remaining.starts_with(b"\r\n\r\n") {
            return Some(index + 4);
        }

        if remaining.starts_with(b"\r\n\n") {
            return Some(index + 3);
        }

        if remaining.starts_with(b"\n\n") || remaining.starts_with(b"\r\r") {
            return Some(index + 2);
        }

        index += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use uuid::Uuid;

    use super::{SseCapture, find_sse_event_end};

    async fn wait_for_file(path: &Path) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if tokio::fs::try_exists(path).await.unwrap_or(false) {
                    return;
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
            .await
            .expect("SSE capture file should be written");
    }

    fn temporary_flow_dir(test_name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "inspect-sse-capture-{test_name}-{}",
            Uuid::new_v4()
        ))
    }

    #[test]
    fn finds_lf_event_end() {
        assert_eq!(find_sse_event_end(b"data: hello\n\n"), Some(13));
    }

    #[test]
    fn finds_crlf_event_end() {
        assert_eq!(find_sse_event_end(b"data: hello\r\n\r\n"), Some(15));
    }

    #[test]
    fn finds_crlf_then_lf_event_end() {
        assert_eq!(find_sse_event_end(b"data: hello\r\n\n"), Some(14));
    }

    #[test]
    fn finds_cr_event_end() {
        assert_eq!(find_sse_event_end(b"data: hello\r\r"), Some(13));
    }

    #[test]
    fn does_not_accept_a_single_line_end() {
        assert_eq!(find_sse_event_end(b"data: hello\n"), None);
    }

    #[tokio::test]
    async fn captures_an_event_when_crlf_delimiter_spans_frames() {
        let flow_dir = temporary_flow_dir("split-crlf");
        tokio::fs::create_dir_all(&flow_dir).await.unwrap();

        {
            let mut capture = SseCapture::start(flow_dir.clone(), 100, 1024);

            capture.push(b"event: message\r\ndata: hello\r\n\r");
            capture.push(b"\n");
        }

        let event_path = flow_dir.join("response.body.001");
        wait_for_file(&event_path).await;

        let event = tokio::fs::read(&event_path).await.unwrap();
        assert_eq!(event, b"event: message\r\ndata: hello\r\n\r\n");

        let _ = tokio::fs::remove_dir_all(flow_dir).await;
    }

    #[tokio::test]
    async fn captures_an_event_when_crlf_then_lf_delimiter_spans_frames() {
        let flow_dir = temporary_flow_dir("split-crlf-lf");
        tokio::fs::create_dir_all(&flow_dir).await.unwrap();

        {
            let mut capture = SseCapture::start(flow_dir.clone(), 100, 1024);

            capture.push(b"data: hello\r\n");
            capture.push(b"\n");
        }

        let event_path = flow_dir.join("response.body.001");
        wait_for_file(&event_path).await;

        let event = tokio::fs::read(&event_path).await.unwrap();
        assert_eq!(event, b"data: hello\r\n\n");

        let _ = tokio::fs::remove_dir_all(flow_dir).await;
    }

    #[tokio::test]
    async fn saves_only_the_configured_number_of_events() {
        let flow_dir = temporary_flow_dir("event-limit");
        tokio::fs::create_dir_all(&flow_dir).await.unwrap();

        {
            let mut capture = SseCapture::start(flow_dir.clone(), 2, 1024);

            capture.push(
                b"data: first\n\n\
                  data: second\n\n\
                  data: third\n\n",
            );
        }

        let first_path = flow_dir.join("response.body.001");
        let second_path = flow_dir.join("response.body.002");
        let third_path = flow_dir.join("response.body.003");

        wait_for_file(&first_path).await;
        wait_for_file(&second_path).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            tokio::fs::read(&first_path).await.unwrap(),
            b"data: first\n\n"
        );
        assert_eq!(
            tokio::fs::read(&second_path).await.unwrap(),
            b"data: second\n\n"
        );
        assert!(!tokio::fs::try_exists(&third_path).await.unwrap());

        let _ = tokio::fs::remove_dir_all(flow_dir).await;
    }

    #[tokio::test]
    async fn truncates_an_oversized_event_without_stopping_capture() {
        let flow_dir = temporary_flow_dir("event-size-limit");
        tokio::fs::create_dir_all(&flow_dir).await.unwrap();

        {
            let mut capture = SseCapture::start(flow_dir.clone(), 100, 8);

            capture.push(b"data: this event is deliberately too large\n\n");
        }

        let event_path = flow_dir.join("response.body.001");
        wait_for_file(&event_path).await;

        let event = String::from_utf8(tokio::fs::read(&event_path).await.unwrap())
            .expect("SSE test payload should remain UTF-8");

        assert!(event.starts_with("data: th"));
        assert!(event.contains("inspect SSE event capture truncated"));

        let _ = tokio::fs::remove_dir_all(flow_dir).await;
    }
}