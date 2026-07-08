use tracing::debug;
use tuie::prelude::*;

pub(crate) fn is_light() -> bool {
    let aa = tuie::get_runtime_info().color_scheme;
// debug!("{:?}", aa);
    matches!(
        aa,
        Some(ColorScheme::Light)
    )
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
        Color::grey256(254)
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

pub(crate) fn panel_border_fg() -> Color {
    if is_light() {
        Color::grey256(8)
    } else {
        Color::grey256(250)
    }
}

pub(crate) fn muted_fg() -> Color {
    if is_light() {
        Color::grey256(8)
    } else {
        Color::BRIGHT_BLACK
    }
}

pub(crate) fn accent_fg() -> Color {
    Color::YELLOW
}

pub(crate) fn unknown_bg() -> Color {
    Color::BRIGHT_RED
}
pub(crate) fn unknown_fg() -> Color {
    Color::BRIGHT_MAGENTA
}