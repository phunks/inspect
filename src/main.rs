use std::sync::Arc;
use clap::{ArgAction, Parser};
use tokio::sync::mpsc;

use inspect::mitm::dynamic_ca::generate_default_ca_files;
use inspect::mitm_proxy_main;
use inspect::tui::run_tui;
use inspect::{AnyError, CapturePaths, PacketSummary};

#[derive(Parser, Debug)]
#[command(version)]
pub struct Opt {
    #[arg(short, long, default_value_t = 62019)]
    /// Set port to listen on
    port: u16,

    #[arg(short, long, default_value = "127.0.0.1")]
    /// Set ip to listen on
    ip: String,

    /// Log verbosity level. -vv for more verbosity.
    /// Environmental variable `RUST_LOG` overrides this flag!
    #[arg(short, group = "log", action = ArgAction::Count)]
    verbosity: u8,

    /// Do not output any logs (even errors!). Overrides `RUST_LOG`
    #[arg(short, group = "log")]
    quiet: bool,

    #[arg(long)]
    upstream_proxy: Option<String>,

    #[arg(long, help = "Generate (or reuse) persistent local MITM root CA and exit")]
    generate_ca: bool,

    #[arg(long, requires = "generate_ca", help = "Force regenerate local MITM root CA")]
    force_regenerate_ca: bool,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    unsafe { std::env::set_var("SSLKEYLOGFILE", "/tmp/sslkeys.log"); }

    let _ = CapturePaths::initialize_for_process()?;

    let opt = Opt::parse();

    if opt.generate_ca {
        let dir = generate_default_ca_files(opt.force_regenerate_ca)?;
        println!("Root CA generated: {}", dir.display());
        println!("Import this certificate into OS trust store:");
        println!("  {}", dir.join("mitm-root-ca.crt").display());
        return Ok(());
    }

    let service_port = format!("{}:{}", opt.ip, opt.port);

    let (tx, rx) = mpsc::unbounded_channel();
    let callback = Arc::new(move |p: PacketSummary| {
        let _ = tx.send(p);
    });

    let upstream_proxy = opt.upstream_proxy.clone();
    let proxy_task = tokio::spawn(async move {
        if let Err(e) = mitm_proxy_main(upstream_proxy, service_port, Some(callback)).await {
            eprintln!("proxy error: {e}");
        }
    });

    if let Err(e) = run_tui(rx).await {
        eprintln!("tui error: {e}");
    }

    proxy_task.abort();
    Ok(())
}