use clap::{ArgAction, CommandFactory, Parser, ValueEnum};
use clap::parser::ValueSource;
use serde::Deserialize;
use tracing::info;
use tracing_appender::{self, rolling::daily};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, EnvFilter, Registry};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use crate::mitm::proxy::AnyResult;

#[derive(Debug, Clone, Copy, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum UaProfile {
    Auto,
    Chrome,
    Firefox,
}

#[derive(Debug, Clone, Copy, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyMode {
    Observe,
    Emulate,
}

#[derive(Debug, Clone, Copy, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TimeMode {
    RFC3339z,
    Absolute,
    Elapsed,
    Epoch,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    port: Option<u16>,
    ip: Option<String>,
    view_capture: Option<std::path::PathBuf>,
    verbosity: Option<u8>,
    upstream_proxy: Option<String>,
    ua_profile: Option<UaProfile>,
    connect_ua_profile: Option<UaProfile>,
    proxy_mode: Option<ProxyMode>,
    upstream_handshake_timeout_ms: Option<u64>,
    upstream_request_timeout_sec: Option<u64>,
    body_save_limit_bytes: Option<usize>,
    body_save_unlimited: Option<bool>,
    generate_ca: Option<bool>,
    force_regenerate_ca: Option<bool>,
    preshared_key_log: Option<String>,
    tui_time_mode: Option<TimeMode>,
    tui_time_format: Option<String>,
    tui_time_tz: Option<String>,
}

#[derive(Parser, Debug)]
#[command(version)]
pub struct Opt {
    #[arg(long, value_name = "FILE", default_value = "config.toml")]
    /// Config TOML file path
    pub config: std::path::PathBuf,

    #[arg(short, long, default_value_t = 62019)]
    /// Set port to listen on
    pub port: u16,

    #[arg(short, long, default_value = "127.0.0.1")]
    /// Set ip to listen on
    pub ip: String,

    #[arg(long, value_name = "DIR", help = "Open an existing capture directory in read-only TUI view mode")]
    pub view_capture: Option<std::path::PathBuf>,

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

    #[arg(long, default_value_t = 10_000, help = "Upstream connect/TLS handshake timeout in milliseconds")]
    pub upstream_handshake_timeout_ms: u64,

    #[arg(long, default_value_t = 60, help = "Upstream request/read timeout in seconds")]
    pub upstream_request_timeout_sec: u64,

    #[arg(long, default_value_t = 3 * 1024, help = "Maximum bytes to save per captured body")]
    pub body_save_limit_bytes: usize,

    #[arg(long, help = "Save captured bodies without truncation")]
    pub body_save_unlimited: bool,

    #[arg(long, help = "Generate (or reuse) persistent local MITM root CA and exit")]
    pub generate_ca: bool,

    #[arg(long, requires = "generate_ca", help = "Force regenerate local MITM root CA")]
    pub force_regenerate_ca: bool,

    #[arg(long, num_args(0..=1), default_missing_value="true", help = "SSLKEYLOGFILE environment variable")]
    preshared_key_log: Option<String>,

    #[arg(long, value_enum, default_value_t = TimeMode::RFC3339z, help = "TUI time mode: rfc3339|absolute|elapsed|epoch")]
    pub tui_time_mode: TimeMode,

    #[arg(long, default_value = "%H:%M:%S%.3f", help = "TUI absolute time format (chrono strftime style)")]
    pub tui_time_format: String,

    #[arg(long, default_value = "utc", help = "TUI timezone: local|utc|+09:00|-05:30")]
    pub tui_time_tz: String,
}

impl Opt {
    pub fn init() -> AnyResult<Self> {
        let mut opt = Opt::parse();
        let matches = Opt::command().get_matches();

        opt.apply_config_if_present(&matches)?;

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

        Ok(opt)
    }

    fn apply_config_if_present(&mut self, matches: &clap::ArgMatches) -> AnyResult<()> {
        if !self.config.is_file() {
            return Ok(());
        }

        let text = std::fs::read_to_string(&self.config)?;
        let config: FileConfig = toml::from_str(&text)?;

        if !cli_specified(matches, "port") {
            if let Some(value) = config.port {
                self.port = value;
            }
        }

        if !cli_specified(matches, "ip") {
            if let Some(value) = config.ip {
                self.ip = value;
            }
        }

        if !cli_specified(matches, "view_capture") {
            if let Some(value) = config.view_capture {
                self.view_capture = Some(value);
            }
        }

        if !cli_specified(matches, "verbosity") {
            if let Some(value) = config.verbosity {
                self.verbosity = value;
            }
        }

        if !cli_specified(matches, "upstream_proxy") {
            if let Some(value) = config.upstream_proxy {
                self.upstream_proxy = Some(value);
            }
        }

        if !cli_specified(matches, "ua_profile") {
            if let Some(value) = config.ua_profile {
                self.ua_profile = value;
            }
        }

        if !cli_specified(matches, "connect_ua_profile") {
            if let Some(value) = config.connect_ua_profile {
                self.connect_ua_profile = Some(value);
            }
        }

        if !cli_specified(matches, "proxy_mode") {
            if let Some(value) = config.proxy_mode {
                self.proxy_mode = value;
            }
        }

        if !cli_specified(matches, "upstream_handshake_timeout_ms") {
            if let Some(value) = config.upstream_handshake_timeout_ms {
                self.upstream_handshake_timeout_ms = value;
            }
        }

        if !cli_specified(matches, "upstream_request_timeout_sec") {
            if let Some(value) = config.upstream_request_timeout_sec {
                self.upstream_request_timeout_sec = value;
            }
        }

        if !cli_specified(matches, "body_save_limit_bytes") {
            if let Some(value) = config.body_save_limit_bytes {
                self.body_save_limit_bytes = value;
            }
        }

        if !cli_specified(matches, "body_save_unlimited") {
            if let Some(value) = config.body_save_unlimited {
                self.body_save_unlimited = value;
            }
        }

        if !cli_specified(matches, "generate_ca") {
            if let Some(value) = config.generate_ca {
                self.generate_ca = value;
            }
        }

        if !cli_specified(matches, "force_regenerate_ca") {
            if let Some(value) = config.force_regenerate_ca {
                self.force_regenerate_ca = value;
            }
        }

        if !cli_specified(matches, "preshared_key_log") {
            if let Some(value) = config.preshared_key_log {
                self.preshared_key_log = Some(value);
            }
        }

        if !cli_specified(matches, "tui_time_mode") {
            if let Some(value) = config.tui_time_mode {
                self.tui_time_mode = value;
            }
        }

        if !cli_specified(matches, "tui_time_format") {
            if let Some(value) = config.tui_time_format {
                self.tui_time_format = value;
            }
        }

        if !cli_specified(matches, "tui_time_tz") {
            if let Some(value) = config.tui_time_tz {
                self.tui_time_tz = value;
            }
        }

        Ok(())
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

    pub fn log_effective_config(&self) {
        info!(
                config = %self.config.display(),
                ip = %self.ip,
                port = self.port,
                view_capture = ?self.view_capture,
                verbosity = self.verbosity,
                upstream_proxy = ?self.upstream_proxy,
                ua_profile = ?self.ua_profile,
                connect_ua_profile = ?self.connect_ua_profile,
                proxy_mode = ?self.proxy_mode,
                upstream_handshake_timeout_ms = self.upstream_handshake_timeout_ms,
                upstream_request_timeout_sec = self.upstream_request_timeout_sec,
                body_save_limit_bytes = self.body_save_limit_bytes,
                body_save_unlimited = self.body_save_unlimited,
                effective_body_save_limit_bytes = ?self.effective_body_save_limit_bytes(),
                generate_ca = self.generate_ca,
                force_regenerate_ca = self.force_regenerate_ca,
                preshared_key_log_enabled = self.is_preshared_key_log_enabled(),
                preshared_key_log_file = ?self.preshared_key_log_file(),
                tui_time_mode = ?self.tui_time_mode,
                tui_time_format = %self.tui_time_format,
                tui_time_tz = %self.tui_time_tz,
                "effective inspect config"
            );
    }

    pub fn effective_body_save_limit_bytes(&self) -> Option<usize> {
        if self.body_save_unlimited {
            None
        } else {
            Some(self.body_save_limit_bytes)
        }
    }
}

fn cli_specified(matches: &clap::ArgMatches, id: &str) -> bool {
    matches
        .value_source(id)
        .is_some_and(|source| source == ValueSource::CommandLine)
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
