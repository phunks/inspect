use tuie::prelude::*;
use terminal_colorsaurus::{theme_mode, QueryOptions, ThemeMode};

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scheme {
    Dark,
    Light,
}

// Background color detection via OSC 11 is unreliable under tmux
fn detected_scheme() -> Scheme {
    static SCHEME: OnceLock<Scheme> = OnceLock::new();

    *SCHEME.get_or_init(|| {
        match theme_mode(QueryOptions::default()) {
            Ok(ThemeMode::Light) => Scheme::Light,
            _ => Scheme::Dark,
        }
    })
}

fn is_light() -> bool {
    detected_scheme() == Scheme::Light
}

pub(crate) fn popup_bg() -> Color {
    if is_light() {
        Color::grey256(255)
    } else {
        Color::grey256(3)
    }
}

pub(crate) fn panel_outer_bg() -> Color {
    if is_light() {
        Color::grey256(255)
    } else {
        Color::grey256(1)
    }
}

pub(crate) fn panel_inner_bg() -> Color {
    if is_light() {
        Color::grey256(255)
    } else {
        Color::grey256(2)
    }
}

#[allow(dead_code)]
pub(crate) fn popup_fg() -> Color {
    Color::Foreground
}

pub(crate) fn panel_fg() -> Color {
    Color::Foreground
}

pub(crate) fn panel_border_fg() -> Color {
    if is_light() {
        Color::grey256(240)
    } else {
        Color::grey256(250)
    }
}

pub(crate) fn muted_fg() -> Color {
    if is_light() {
        Color::grey256(240)
    } else {
        Color::grey256(250)
    }
}

pub(crate) fn accent_fg() -> Color {
    Color::YELLOW
}
