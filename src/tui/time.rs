use chrono::{FixedOffset, Local, TimeZone, Utc};
use crate::options::TimeMode;

#[derive(Clone, Debug)]
pub struct TimeDisplayConfig {
    pub mode: TimeMode,
    pub format: String,
    pub tz: String,
}

#[derive(Clone, Debug)]
enum TuiTimeZone {
    Local,
    Utc,
    Offset(FixedOffset),
}

impl TuiTimeZone {
    fn parse(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase();
        if lower == "local" {
            return Self::Local;
        }
        if lower == "utc" || lower == "z" {
            return Self::Utc;
        }

        let raw = s.trim();
        if raw.len() == 6 && (raw.starts_with('+') || raw.starts_with('-')) && raw.as_bytes()[3] == b':' {
            let sign = if raw.starts_with('-') { -1 } else { 1 };
            let hh = raw[1..3].parse::<i32>().ok();
            let mm = raw[4..6].parse::<i32>().ok();
            if let (Some(h), Some(m)) = (hh, mm) {
                let sec = sign * (h * 3600 + m * 60);
                if let Some(ofs) = FixedOffset::east_opt(sec) {
                    return Self::Offset(ofs);
                }
            }
        }

        Self::Local
    }
}

#[derive(Clone, Debug)]
pub struct TimeFormatter {
    mode: TimeMode,
    fmt: String,
    tz: TuiTimeZone,
    first_epoch_ms: Option<i64>,
}

impl TimeFormatter {
    pub(crate) fn new(cfg: TimeDisplayConfig) -> Self {
        Self {
            mode: cfg.mode,
            fmt: cfg.format,
            tz: TuiTimeZone::parse(&cfg.tz),
            first_epoch_ms: None,
        }
    }

    pub(crate) fn format_packet_time_rfc3339(&self, raw_time: &str, epoch_ms: i64) -> String {
        let Some(dt_utc) = Utc.timestamp_millis_opt(epoch_ms).single() else {
            return raw_time.to_string();
        };

        match &self.tz {
            TuiTimeZone::Utc => {
                dt_utc.to_rfc3339_opts(chrono::format::SecondsFormat::Millis, true)
            }
            TuiTimeZone::Local => {
                dt_utc
                    .with_timezone(&Local)
                    .to_rfc3339_opts(chrono::format::SecondsFormat::Millis, false)
            }
            TuiTimeZone::Offset(ofs) => {
                dt_utc
                    .with_timezone(ofs)
                    .to_rfc3339_opts(chrono::format::SecondsFormat::Millis, false)
            }
        }
    }

    fn format_includes_tz(fmt: &str) -> bool {
        fmt.contains("%z")
            || fmt.contains("%:z")
            || fmt.contains("%::z")
            || fmt.contains("%:::z")
            || fmt.contains("%Z")
    }

    pub(crate) fn format_packet_time(&mut self, raw_time: &str, epoch_ms: i64) -> String {
        match self.mode {
            TimeMode::RFC3339z => self.format_packet_time_rfc3339(raw_time, epoch_ms),
            TimeMode::Epoch => epoch_ms.to_string(),
            TimeMode::Elapsed => {
                let base = *self.first_epoch_ms.get_or_insert(epoch_ms);
                let delta = (epoch_ms - base).max(0);
                let h = delta / 3_600_000;
                let m = (delta % 3_600_000) / 60_000;
                let s = (delta % 60_000) / 1_000;
                let ms = delta % 1_000;
                format!("{h:02}:{m:02}:{s:02}.{ms:03}")
            }
            TimeMode::Absolute => {
                let Some(dt_utc) = Utc.timestamp_millis_opt(epoch_ms).single() else {
                    return "-".to_string();
                };

                match &self.tz {
                    TuiTimeZone::Utc => {
                        let mut s = dt_utc.format(&self.fmt).to_string();
                        if !Self::format_includes_tz(&self.fmt) && !s.ends_with('z') && !s.ends_with('Z') {
                            s.push('z');
                        }
                        s
                    }
                    TuiTimeZone::Local => dt_utc.with_timezone(&Local).format(&self.fmt).to_string(),
                    TuiTimeZone::Offset(ofs) => dt_utc.with_timezone(ofs).format(&self.fmt).to_string(),
                }
            }
        }
    }
}