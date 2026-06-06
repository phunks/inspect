use clap::{ArgAction, Parser, ValueEnum};
use tracing::info;
use tracing_appender::{self, rolling::daily};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, EnvFilter, Registry};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use crate::AnyResult;
use crate::mitm::dynamic_ca::generate_default_ca_files;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum UaProfile {
    Auto,
    Chrome,
    Firefox,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ProxyMode {
    Observe,
    Emulate,
}

#[derive(Parser, Debug)]
#[command(version)]
pub struct Opt {
    #[arg(short, long, default_value_t = 62019)]
    /// Set port to listen on
    pub port: u16,

    #[arg(short, long, default_value = "127.0.0.1")]
    /// Set ip to listen on
    pub ip: String,

    /// Log verbosity level. -vv for more verbosity.
    /// Environmental variable `RUST_LOG` overrides this flag!
    #[arg(short, action = ArgAction::Count, default_value_t = 0)]
    pub verbosity: u8,

    #[arg(long, num_args(0..=1), default_missing_value="false", help = "Upstream proxy address in format 'host:port'")]
    pub upstream_proxy: Option<String>,

    #[arg(long, value_enum, default_value_t = UaProfile::Auto, help = "UA for normal upstream HTTP requests")]
    pub ua_profile: UaProfile,

    #[arg(long, value_enum, help = "UA for upstream proxy CONNECT. If omitted, inherits --ua-profile")]
    pub connect_ua_profile: Option<UaProfile>,

    #[arg(long, value_enum, default_value_t = ProxyMode::Observe)]
    pub proxy_mode: ProxyMode,

    #[arg(long, default_value_t = 60_000, help = "Upstream request timeout in milliseconds")]
    pub upstream_timeout_ms: u64,

    #[arg(long, help = "Generate (or reuse) persistent local MITM root CA and exit")]
    pub generate_ca: bool,

    #[arg(long, requires = "generate_ca", help = "Force regenerate local MITM root CA")]
    force_regenerate_ca: bool,

    #[arg(long, num_args(0..=1), default_missing_value="true", help = "SSLKEYLOGFILE environment variable")]
    preshared_key_log: Option<String>,
}

impl Opt {
    pub fn init() -> AnyResult<Self> {
        let opt = Opt::parse();

        if opt.is_preshared_key_log_enabled() {
            let a = if let Some(path) = opt.preshared_key_log_file() {
                info!("Using SSL key log file: {path}");
                path
            } else {
                let path = "/tmp/sslkeys.log";
                info!("Using default SSL key log file: {path}");
                path
            };
            unsafe { std::env::set_var("SSLKEYLOGFILE", a); }
        }

        if opt.generate_ca {
            let dir = generate_default_ca_files(opt.force_regenerate_ca)?;
            info!("Root CA generated: {}", dir.display());
            info!("Import this certificate into OS trust store:");
            info!("  {}", dir.join("mitm-root-ca.crt").display());
            // return Ok(());
        }
        Ok(opt)
    }

    pub fn is_preshared_key_log_enabled(&self) -> bool {
        self.preshared_key_log.is_some()
    }

    pub fn preshared_key_log_file(&self) -> Option<&str> {
        match &self.preshared_key_log {
            Some(val) if val == "true" => None,
            Some(val) => Some(val),
            None => None,
        }
    }
}

pub struct Logger {
    _guard: WorkerGuard,
}

impl Logger {
    pub fn build(verbosity: u8) -> Self {
        let file_appender = daily("/tmp", "debug_inspect.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
            match verbosity {
                0 => "warn".to_string(),
                1 => "info".to_string(),
                2 => "debug".to_string(),
                _ => "trace".to_string(),
            }
        });

        let file_layer = fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_target(verbosity > 1)
            .with_level(verbosity > 2)
            .with_thread_ids(verbosity > 3)
            .with_thread_names(verbosity > 4);

        Registry::default()
            .with(EnvFilter::new(filter))
            .with(file_layer)
            .init();

        Self { _guard: guard }
    }
}
