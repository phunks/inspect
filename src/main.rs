use std::sync::Arc;
use clap::Parser;
use rama::crypto::dep::x509_parser::nom::combinator::opt;
use tokio::sync::{mpsc, watch};

use inspect::mitm::dynamic_ca::generate_default_ca_files;
use inspect::mitm_proxy_main;
use inspect::tui::run_tui;
use inspect::{AnyError, CapturePaths, PacketSummary};
use inspect::option::{Opt, Logger};

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let opt = Opt::init()?;
    let _logger = Logger::build(opt.verbosity);
    let service_port = format!("{}:{}", opt.ip, opt.port);

    let _ = CapturePaths::initialize_for_process()?;

    let (tx, rx) = mpsc::unbounded_channel();
    let callback = Arc::new(move |p: PacketSummary| {
        let _ = tx.send(p);
    });

    let upstream_proxy = opt.upstream_proxy.clone();
    let (quit_tx, quit_rx) = watch::channel(false);

    let proxy_task = tokio::spawn(async move {
        if let Err(e) = mitm_proxy_main(upstream_proxy, service_port, Some(callback), quit_rx).await {
            eprintln!("proxy error: {e}");
        }
    });

    if let Err(e) = run_tui(rx, quit_tx.clone()).await {
        eprintln!("tui error: {e}");
    }

    // proxy_task.abort();
    let _ = quit_tx.send(true);

    let _ = proxy_task.await;
    Ok(())
}