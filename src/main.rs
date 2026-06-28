use std::collections::HashMap;
use tokio::sync::{mpsc, watch};
use tracing::info;
use inspect::filters::FilterManager;
use inspect::filters::http_client::{
    OutboundHttpClientPool,
    OutboundHttpPoolConfig,
    run_outbound_http_worker,
};
use inspect::mitm::proxy::{mitm_proxy_main, PacketEvent};
use inspect::tui::{run_tui, TuiMode, TUI_EVENT_BUFFER};
use inspect::tui::time::TimeDisplayConfig;
use inspect::mitm::proxy::AnyError;
use inspect::mitm::capture::CapturePaths;
use inspect::mitm::dynamic_ca::generate_default_ca_files;
use inspect::options::{Opt, Logger};
use inspect::mitm::flow::{FlowEventDispatcher, FlowEventPublisher, TuiSink};


#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let opt = Opt::init()?;
    let _logger = Logger::build(opt.verbosity);
    opt.log_effective_config();

    if opt.generate_ca {
        let dir = generate_default_ca_files(opt.force_regenerate_ca)?;
        info!("Root CA generated: {}", dir.display());
        info!("Import this certificate into OS trust store:");
        info!("  {}", dir.join("mitm-root-ca.crt").display());
        return Ok(());
    }

    let time_display = TimeDisplayConfig {
        mode: opt.tui_time_mode,
        format: opt.tui_time_format.clone(),
        tz: opt.tui_time_tz.clone(),
    };

    if let Some(view_capture) = opt.view_capture.as_ref() {
        let paths = CapturePaths::initialize_for_existing_capture(view_capture)?;
        info!("Viewing capture: {}", paths.root.display());

        let (_tx, rx) = mpsc::channel(TUI_EVENT_BUFFER);
        let (quit_tx, _quit_rx) = watch::channel(false);

        if let Err(e) = run_tui(rx, quit_tx, time_display, TuiMode::Viewer).await {
            eprintln!("tui error: {e}");
        }

        return Ok(());
    }

    let service_port = format!("{}:{}", opt.ip, opt.port);

    let _ = CapturePaths::initialize_for_process()?;

    let (tx, rx) = mpsc::channel::<PacketEvent>(TUI_EVENT_BUFFER);
    let (flow_events, flow_event_rx) = FlowEventPublisher::channel(TUI_EVENT_BUFFER);

    let flow_event_dispatcher = FlowEventDispatcher::new()
        .with_sink(TuiSink::new(tx));

    let flow_event_dispatcher_task = tokio::spawn(async move {
        flow_event_dispatcher.run(flow_event_rx).await;
    });

    let upstream_proxy = opt.upstream_proxy.clone();
    let ua_profile = opt.ua_profile;
    let connect_ua_profile = opt.connect_ua_profile;
    let proxy_mode = opt.proxy_mode;
    let upstream_handshake_timeout_ms = opt.upstream_handshake_timeout_ms;
    let upstream_request_timeout_sec = opt.upstream_request_timeout_sec;
    let body_save_limit_bytes = opt.effective_body_save_limit_bytes();
    let body_omit_content_types = opt.body_omit_content_types.clone();
    let outbound_http_configs = opt
        .outbound_http_clients
        .clone()
        .into_iter()
        .map(|config| {
            let name = config.name.clone();
            (name, OutboundHttpPoolConfig::from(config))
        })
        .collect::<HashMap<_, _>>();
    let filter_manager = FilterManager::new("./filters");
    let (quit_tx, quit_rx) = watch::channel(false);

    let outbound_http_pool = if outbound_http_configs.is_empty() {
        None
    } else {
        let (pool, rx) = OutboundHttpClientPool::new(outbound_http_configs, TUI_EVENT_BUFFER);
        let configs = pool.configs();

        tokio::spawn(async move {
            run_outbound_http_worker(rx, configs).await;
        });

        Some(pool)
    };
    
    let filter_reload_manager = filter_manager.clone();
    let filter_reload_quit_rx = quit_rx.clone();
    let filter_reload_task = tokio::spawn(async move {
        filter_reload_manager
            .reload_loop(filter_reload_quit_rx)
            .await;
    });

    let proxy_task = tokio::spawn(async move {
        if let Err(e) = mitm_proxy_main(
            upstream_proxy,
            service_port,
            ua_profile,
            connect_ua_profile,
            proxy_mode,
            upstream_handshake_timeout_ms,
            upstream_request_timeout_sec,
            body_save_limit_bytes,
            body_omit_content_types,
            outbound_http_pool,
            filter_manager,
            flow_events,
            quit_rx,
        ).await {
            eprintln!("proxy error: {e}");
        }
    });

    if let Err(e) = run_tui(rx, quit_tx.clone(), time_display, TuiMode::Capture).await {
        eprintln!("tui error: {e}");
    }

    let _ = proxy_task.await;
    flow_event_dispatcher_task.abort();
    let _ = filter_reload_task.await;
    Ok(())
}