use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use anyhow::Context;
use crate::tui::body::{format_body_for_display, format_body_for_display_with_headers};
use crate::tui::read_metadata::DbState;
use crate::tui::tab::{
    DetailMessagePartSelection,
    DetailPrimaryTabSelection,
    DetailTabSelection
};

#[derive(Clone, Debug)]
pub(crate) struct ExternalDiffPaths {
    pub(crate) left: PathBuf,
    pub(crate) right: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct ExternalViewPath {
    pub(crate) path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
enum ExternalDiffBodyKind {
    Request,
    Response,
}

#[derive(Clone, Debug)]
struct ExternalDiffBodySource {
    flow_key: String,
    flow_dir: PathBuf,
    path: PathBuf,
    headers: serde_json::Value,
    size_line: String,
    kind: ExternalDiffBodyKind,
}

pub(crate) async fn external_diff_paths(
    db: Arc<DbState>,
    selection: DetailTabSelection,
    left_id: String,
    right_id: String,
) -> anyhow::Result<ExternalDiffPaths> {
    match (selection.primary_tab, selection.message_part) {
        (DetailPrimaryTabSelection::Request, DetailMessagePartSelection::Meta) => {
            let left = db.select_request_by_id(left_id).await?;
            let right = db.select_request_by_id(right_id).await?;

            Ok(ExternalDiffPaths {
                left: existing_external_diff_path(left.request_head_path, "left request head")?,
                right: existing_external_diff_path(right.request_head_path, "right request head")?,
            })
        }
        (DetailPrimaryTabSelection::Response, DetailMessagePartSelection::Meta) => {
            let left = db.select_response_by_id(left_id).await?;
            let right = db.select_response_by_id(right_id).await?;

            Ok(ExternalDiffPaths {
                left: existing_external_diff_path(left.response_head_path, "left response head")?,
                right: existing_external_diff_path(right.response_head_path, "right response head")?,
            })
        }
        (DetailPrimaryTabSelection::SslTls, _) => {
            let left = db.select_request_by_id(left_id).await?;
            let right = db.select_request_by_id(right_id).await?;

            Ok(ExternalDiffPaths {
                left: existing_external_diff_path(
                    ssl_tls_path_from_flow_dir(left.flow_dir.as_deref())?,
                    "left ssl_tls.json",
                )?,
                right: existing_external_diff_path(
                    ssl_tls_path_from_flow_dir(right.flow_dir.as_deref())?,
                    "right ssl_tls.json",
                )?,
            })
        }
        (DetailPrimaryTabSelection::Request, DetailMessagePartSelection::Body) => {
            let left = request_external_diff_body_source(db.clone(), left_id).await?;
            let right = request_external_diff_body_source(db, right_id).await?;

            external_diff_body_paths(left, right).await
        }
        (DetailPrimaryTabSelection::Response, DetailMessagePartSelection::Body) => {
            let left = response_external_diff_body_source(db.clone(), left_id).await?;
            let right = response_external_diff_body_source(db, right_id).await?;

            external_diff_body_paths(left, right).await
        }
        (DetailPrimaryTabSelection::Info, _) => {
            anyhow::bail!("external diff requests do not support info");
        }
    }
}

pub(crate) async fn external_view_path(
    db: Arc<DbState>,
    selection: DetailTabSelection,
    id: String,
) -> anyhow::Result<ExternalViewPath> {
    match (selection.primary_tab, selection.message_part) {
        (DetailPrimaryTabSelection::Request, DetailMessagePartSelection::Meta) => {
            let req = db.select_request_by_id(id).await?;

            Ok(ExternalViewPath {
                path: existing_external_diff_path(req.request_head_path, "request head")?,
            })
        }
        (DetailPrimaryTabSelection::Response, DetailMessagePartSelection::Meta) => {
            let res = db.select_response_by_id(id).await?;

            Ok(ExternalViewPath {
                path: existing_external_diff_path(res.response_head_path, "response head")?,
            })
        }
        (DetailPrimaryTabSelection::SslTls, _) => {
            let req = db.select_request_by_id(id).await?;

            Ok(ExternalViewPath {
                path: existing_external_diff_path(
                    ssl_tls_path_from_flow_dir(req.flow_dir.as_deref())?,
                    "ssl_tls.json",
                )?,
            })
        }
        (DetailPrimaryTabSelection::Request, DetailMessagePartSelection::Body) => {
            let source = request_external_diff_body_source(db, id).await?;

            Ok(ExternalViewPath {
                path: external_view_body_path(source).await?,
            })
        }
        (DetailPrimaryTabSelection::Response, DetailMessagePartSelection::Body) => {
            let source = response_external_diff_body_source(db, id).await?;

            Ok(ExternalViewPath {
                path: external_view_body_path(source).await?,
            })
        }
        (DetailPrimaryTabSelection::Info, _) => {
            anyhow::bail!("external view requests do not support info");
        }
    }
}

async fn request_external_diff_body_source(
    db: Arc<DbState>,
    id: String,
) -> anyhow::Result<ExternalDiffBodySource> {
    let req = db.select_request_by_id(id).await?;
    let size_line = req.body_size_line();
    let flow_key = req.flow_key
        .ok_or_else(|| anyhow::anyhow!("request flow_key is missing"))?;
    let flow_dir = PathBuf::from(
        req.flow_dir
            .ok_or_else(|| anyhow::anyhow!("request flow_dir is missing for {flow_key}"))?,
    );
    let path = PathBuf::from(
        req.request_body_path
            .ok_or_else(|| anyhow::anyhow!("request body path is missing for {flow_key}"))?,
    );
    Ok(ExternalDiffBodySource {
        flow_key,
        flow_dir,
        path,
        headers: req.headers,
        size_line,
        kind: ExternalDiffBodyKind::Request,
    })
}

async fn response_external_diff_body_source(
    db: Arc<DbState>,
    id: String,
) -> anyhow::Result<ExternalDiffBodySource> {
    let res = db.select_response_by_id(id).await?;
    let size_line = res.body_size_line();
    let flow_key = res.flow_key
        .ok_or_else(|| anyhow::anyhow!("response flow_key is missing"))?;
    let flow_dir = PathBuf::from(
        res.flow_dir
            .ok_or_else(|| anyhow::anyhow!("response flow_dir is missing for {flow_key}"))?,
    );
    let path = PathBuf::from(
        res.response_body_path
            .ok_or_else(|| anyhow::anyhow!("response body path is missing for {flow_key}"))?,
    );

    Ok(ExternalDiffBodySource {
        flow_key,
        flow_dir,
        path,
        headers: res.headers,
        size_line,
        kind: ExternalDiffBodyKind::Response,
    })
}

async fn external_diff_body_paths(
    left: ExternalDiffBodySource,
    right: ExternalDiffBodySource,
) -> anyhow::Result<ExternalDiffPaths> {
    let left_needs_view = external_diff_body_needs_view(&left).await;
    let right_needs_view = external_diff_body_needs_view(&right).await;

    if left_needs_view || right_needs_view {
        Ok(ExternalDiffPaths {
            left: prepare_external_diff_body_view(&left).await?,
            right: prepare_external_diff_body_view(&right).await?,
        })
    } else {
        Ok(ExternalDiffPaths {
            left: existing_external_diff_path(Some(left.path.to_string_lossy().to_string()), "left body")?,
            right: existing_external_diff_path(Some(right.path.to_string_lossy().to_string()), "right body")?,
        })
    }
}

async fn external_view_body_path(
    source: ExternalDiffBodySource,
) -> anyhow::Result<PathBuf> {
    if external_diff_body_needs_view(&source).await {
        prepare_external_diff_body_view(&source).await
    } else {
        existing_external_diff_path(
            Some(source.path.to_string_lossy().to_string()),
            "body",
        )
    }
}

async fn external_diff_body_needs_view(source: &ExternalDiffBodySource) -> bool {
    is_compressed_body_path(&source.path)
        || is_sse_body_path(&source.path).await.unwrap_or(false)
}

fn is_compressed_body_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.ends_with(".gz")
                || name.ends_with(".br")
                || name.ends_with(".zst")
                || name.ends_with(".zstd")
                || name.ends_with(".deflate")
        })
}

async fn is_sse_body_path(path: &Path) -> std::io::Result<bool> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };

    if !file_name.starts_with("response.body") {
        return Ok(false);
    }

    let Some(flow_dir) = path.parent() else {
        return Ok(false);
    };

    tokio::fs::try_exists(flow_dir.join("response.body.sse")).await
}

async fn prepare_external_diff_body_view(
    source: &ExternalDiffBodySource,
) -> anyhow::Result<PathBuf> {
    let external_diff_dir = external_diff_dir_for_flow(&source.flow_dir)?;
    tokio::fs::create_dir_all(&external_diff_dir).await.with_context(|| {
        format!(
            "failed to create external diff dir {}",
            external_diff_dir.display(),
        )
    })?;

    let part = match source.kind {
        ExternalDiffBodyKind::Request => "request.body",
        ExternalDiffBodyKind::Response => "response.body",
    };
    let output_path = external_diff_dir.join(format!("{}.{}.txt", source.flow_key, part));

    let body = read_body_file(
        Some(source.path.to_string_lossy().as_ref()),
        &source.headers,
    ).await;
    let body = format_body_with_size(source.size_line.clone(), body);

    tokio::fs::write(&output_path, body).await.with_context(|| {
        format!(
            "failed to write external diff body view {}",
            output_path.display(),
        )
    })?;

    Ok(output_path)
}

fn external_diff_dir_for_flow(flow_dir: &Path) -> anyhow::Result<PathBuf> {
    let capture_root = flow_dir
        .parent()
        .and_then(|flows_dir| flows_dir.parent())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "failed to resolve capture root from flow dir {}",
                flow_dir.display(),
            )
        })?;

    Ok(capture_root.join(".external-diff"))
}

fn ssl_tls_path_from_flow_dir(flow_dir: Option<&str>) -> anyhow::Result<Option<String>> {
    let flow_dir = flow_dir
        .ok_or_else(|| anyhow::anyhow!("flow_dir is missing for ssl_tls.json"))?;

    Ok(Some(
        Path::new(flow_dir)
            .join("ssl_tls.json")
            .to_string_lossy()
            .to_string(),
    ))
}

fn existing_external_diff_path(path: Option<String>, label: &str) -> anyhow::Result<PathBuf> {
    let path = path
        .ok_or_else(|| anyhow::anyhow!("{label} path is missing"))?;

    let path = PathBuf::from(path);

    if !path.is_file() {
        anyhow::bail!("{label} file does not exist: {}", path.display());
    }

    Ok(path)
}

pub(crate) fn spawn_external_diff(command: &[String], left: &Path, right: &Path) -> anyhow::Result<()> {
    let Some(program) = command.first().filter(|program| !program.is_empty()) else {
        anyhow::bail!("external_diff_command must start with a program name");
    };

    let mut child = Command::new(program)
        .args(&command[1..])
        .arg(left)
        .arg(right)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdout) = child.stdout.take() {
        let program = program.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        tracing::debug!(
                            external_diff_program = %program,
                            stream = "stdout",
                            message = %line,
                            "external diff output"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            external_diff_program = %program,
                            stream = "stdout",
                            error = ?err,
                            "failed to read external diff stdout"
                        );
                        break;
                    }
                }
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let program = program.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        tracing::debug!(
                            external_diff_program = %program,
                            stream = "stderr",
                            message = %line,
                            "external diff output"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            external_diff_program = %program,
                            stream = "stderr",
                            error = ?err,
                            "failed to read external diff stderr"
                        );
                        break;
                    }
                }
            }
        });
    }

    std::thread::spawn(move || {
        match child.wait() {
            Ok(status) => {
                tracing::debug!(
                    status = %status,
                    "external diff process exited"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = ?err,
                    "failed to wait external diff process"
                );
            }
        }
    });

    Ok(())
}

pub(crate) fn spawn_external_view(command: &[String], path: &Path) -> anyhow::Result<()> {
    let Some(program) = command.first().filter(|program| !program.is_empty()) else {
        anyhow::bail!("external_view_command must start with a program name");
    };

    let mut child = Command::new(program)
        .args(&command[1..])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdout) = child.stdout.take() {
        let program = program.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        tracing::debug!(
                            external_view_program = %program,
                            stream = "stdout",
                            message = %line,
                            "external view output"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            external_view_program = %program,
                            stream = "stdout",
                            error = ?err,
                            "failed to read external view stdout"
                        );
                        break;
                    }
                }
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let program = program.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        tracing::debug!(
                            external_view_program = %program,
                            stream = "stderr",
                            message = %line,
                            "external view output"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            external_view_program = %program,
                            stream = "stderr",
                            error = ?err,
                            "failed to read external view stderr"
                        );
                        break;
                    }
                }
            }
        });
    }

    std::thread::spawn(move || {
        match child.wait() {
            Ok(status) => {
                tracing::debug!(
                    status = %status,
                    "external view process exited"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = ?err,
                    "failed to wait external view process"
                );
            }
        }
    });

    Ok(())
}

pub(crate) async fn read_body_file(path: Option<&str>, headers: &serde_json::Value) -> String {
    let Some(path) = path else {
        return "<no path>".to_string();
    };

    let path = Path::new(path);

    match read_sse_body_files(path).await {
        Ok(Some(body)) => return body,
        Ok(None) => {}
        Err(err) => return format!("<read SSE body error: {err}>"),
    }

    match tokio::fs::read(path).await {
        Ok(bytes) => format_body_for_display_with_headers(headers, &bytes),
        Err(e) => format!("<read error: {e}>"),
    }
}

async fn read_sse_body_files(path: &Path) -> std::io::Result<Option<String>> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };

    if !file_name.starts_with("response.body") {
        return Ok(None);
    }

    let Some(flow_dir) = path.parent() else {
        return Ok(None);
    };

    let marker_path = flow_dir.join("response.body.sse");
    if !tokio::fs::try_exists(&marker_path).await? {
        return Ok(None);
    }

    let mut entries = tokio::fs::read_dir(flow_dir).await?;
    let mut event_paths = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };

        let Some(sequence) = file_name
            .strip_prefix("response.body.")
            .and_then(|suffix| suffix.parse::<usize>().ok())
        else {
            continue;
        };

        event_paths.push((sequence, entry.path()));
    }

    event_paths.sort_unstable_by_key(|(sequence, _)| *sequence);

    let mut bytes = Vec::new();

    for (sequence, event_path) in event_paths {
        let event = tokio::fs::read(&event_path).await?;
        bytes.extend_from_slice(
            format!("\n<< SSE event {sequence:03} >>\n").as_bytes(),
        );
        bytes.extend_from_slice(&event);
    }

    let partial_path = flow_dir.join("response.body.partial");
    if tokio::fs::try_exists(&partial_path).await? {
        let partial = tokio::fs::read(&partial_path).await?;
        bytes.extend_from_slice(b"\n<< SSE partial event at stream end >>\n");
        bytes.extend_from_slice(&partial);
    }

    let saved_event_count = bytes
        .windows(b"<< SSE event ".len())
        .filter(|window| *window == b"<< SSE event ")
        .count();

    let header = format!(
        "<< Server-Sent Events capture: {saved_event_count} saved event(s) >>\n"
    );

    if bytes.is_empty() {
        return Ok(Some(format!(
            "{header}\n<no complete SSE event has been captured yet>"
        )));
    }

    Ok(Some(format!("{header}\n{}", format_body_for_display(&bytes))))
}

pub(crate) fn format_body_with_size(body_size: String, body: String) -> String {
    format!("body size : {body_size}\n\n{body}")
}

pub(crate) fn format_ssl_tls_info(tls_sni: Option<&str>, tls_upstream: Option<&str>) -> String {
    let upstream_tls = tls_upstream
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .unwrap_or(serde_json::Value::Null);

    let value = serde_json::json!({
        "request": {
            "tls_sni": tls_sni,
        },
        "response": {
            "upstream_tls": upstream_tls,
        }
    });

    serde_json::to_string_pretty(&value)
        .unwrap_or_else(|_| value.to_string())
}
