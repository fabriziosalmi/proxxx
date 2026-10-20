use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

/// Resource metric class for per-metric usage colouring (`#334`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageMetric {
    Cpu,
    Memory,
    Disk,
}

impl UsageMetric {
    /// Alias for [`UsageMetric::Disk`] used by storage pool summaries.
    pub const STORAGE: Self = Self::Disk;
}

/// Severity level for a resource usage percentage (`#334`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsageLevel {
    Ok,
    Elevated,
    High,
    Critical,
}

impl UsageLevel {
    /// Foreground colour for this usage level on the dark [`Theme`] palette.
    #[must_use]
    pub const fn color(self) -> Color {
        match self {
            Self::Ok => Theme::SUCCESS,
            Self::Elevated => Theme::WARNING,
            Self::High => Theme::ORANGE,
            Self::Critical => Theme::DANGER,
        }
    }

    /// [`Style`] with the foreground set to [`Self::color`].
    #[must_use]
    pub fn style(self) -> Style {
        Style::default().fg(self.color())
    }

    /// Non-colour marker appended to critical usage cells (`"!"` at [`Self::Critical`], `""` otherwise).
    #[must_use]
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Critical => "!",
            Self::Ok | Self::Elevated | Self::High => "",
        }
    }
}

/// Inclusive lower-bound percentage thresholds `(elevated, high, critical)` for a [`UsageMetric`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UsageThresholds {
    pub metric: UsageMetric,
    pub elevated: f64,
    pub high: f64,
    pub critical: f64,
}

/// Fixed per-metric percentage thresholds (`#334`, inclusive lower bounds).
///
/// CPU thresholds are higher because CPU load is spiky; memory and disk/storage
/// fill up and stay full.
pub const USAGE_THRESHOLDS: [UsageThresholds; 3] = [
    UsageThresholds {
        metric: UsageMetric::Cpu,
        elevated: 60.0,
        high: 80.0,
        critical: 95.0,
    },
    UsageThresholds {
        metric: UsageMetric::Memory,
        elevated: 70.0,
        high: 80.0,
        critical: 90.0,
    },
    UsageThresholds {
        metric: UsageMetric::Disk,
        elevated: 70.0,
        high: 80.0,
        critical: 90.0,
    },
];

/// Return the [`UsageThresholds`] entry for `metric` from [`USAGE_THRESHOLDS`].
#[must_use]
pub const fn usage_thresholds(metric: UsageMetric) -> UsageThresholds {
    match metric {
        UsageMetric::Cpu => USAGE_THRESHOLDS[0],
        UsageMetric::Memory => USAGE_THRESHOLDS[1],
        UsageMetric::Disk => USAGE_THRESHOLDS[2],
    }
}

/// Pure classifier mapping `(metric, percent)` to [`UsageLevel`] using [`USAGE_THRESHOLDS`].
///
/// Lower bounds are inclusive (`percent >= threshold`). `NaN` and negative values
/// return [`UsageLevel::Ok`] without panicking.
#[must_use]
pub fn usage_level(metric: UsageMetric, percent: f64) -> UsageLevel {
    let t = usage_thresholds(metric);
    if percent >= t.critical {
        UsageLevel::Critical
    } else if percent >= t.high {
        UsageLevel::High
    } else if percent >= t.elevated {
        UsageLevel::Elevated
    } else {
        UsageLevel::Ok
    }
}

/// Dark-background TUI colour palette. The full palette is exposed even
/// though not every entry is referenced in every view; views pull what
/// they need without API churn.
#[allow(dead_code)]
pub struct Theme;

#[allow(dead_code)]
impl Theme {
    // ── Semantic Colors ─────────────────────────────────
    pub const ACCENT: Color = Color::Rgb(99, 102, 241); // Indigo-500 (brand)
    pub const SUCCESS: Color = Color::Rgb(34, 197, 94); // Green-500 (running, ok, low-usage)
    pub const WARNING: Color = Color::Rgb(234, 179, 8); // Yellow-500 (stale, elevated-usage)
    pub const ORANGE: Color = Color::Rgb(249, 115, 22); // Orange-500 (high-usage)
    pub const DANGER: Color = Color::Rgb(239, 68, 68); // Red-500 (stopped, critical-usage, errors)
    pub const INFO: Color = Color::Rgb(59, 130, 246); // Blue-500 (paused, intentional state)

    // ── Surfaces ────────────────────────────────────────
    pub const BG: Color = Color::Rgb(15, 15, 20); // Near-black
    pub const BG_ELEVATED: Color = Color::Rgb(24, 24, 32); // Slightly lighter
    pub const BG_SELECTED: Color = Color::Rgb(30, 30, 45); // Selection highlight
    pub const BORDER: Color = Color::Rgb(55, 55, 75); // Subtle borders
    pub const BORDER_FOCUS: Color = Color::Rgb(99, 102, 241); // Focused border = accent

    // ── Text ────────────────────────────────────────────
    pub const TEXT: Color = Color::Rgb(229, 231, 235); // Gray-200
    pub const TEXT_DIM: Color = Color::Rgb(107, 114, 128); // Gray-500
    pub const TEXT_MUTED: Color = Color::Rgb(75, 85, 99); // Gray-600

    // ── Preset Styles ───────────────────────────────────

    #[must_use]
    pub fn title() -> Style {
        Style::default().fg(Self::TEXT).add_modifier(Modifier::BOLD)
    }

    #[must_use]
    pub fn header() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    #[must_use]
    pub fn selected() -> Style {
        Style::default()
            .bg(Self::BG_SELECTED)
            .fg(Self::TEXT)
            .add_modifier(Modifier::BOLD)
    }

    #[must_use]
    pub fn status_badge(status: &str) -> Style {
        match status {
            "running" | "online" => Style::default().fg(Self::SUCCESS),
            "stopped" | "offline" => Style::default().fg(Self::DANGER),
            "paused" | "suspended" => Style::default().fg(Self::INFO),
            _ => Style::default().fg(Self::WARNING),
        }
    }

    #[must_use]
    pub fn usage_level(metric: UsageMetric, percent: f64) -> UsageLevel {
        usage_level(metric, percent)
    }

    #[must_use]
    pub fn usage_color(metric: UsageMetric, percent: f64) -> Color {
        usage_level(metric, percent).color()
    }

    /// Format and style a table cell for a usage metric (`#334`).
    ///
    /// When `has_max` is `false` (`max == 0` or missing data), returns `text`
    /// with [`Style::default()`] and no marker. When `has_max` is `true`,
    /// appends [`UsageLevel::marker`] (`"!"` at [`UsageLevel::Critical`]) and
    /// styles the cell with [`UsageLevel::style`].
    #[must_use]
    pub fn usage_span(
        text: String,
        metric: UsageMetric,
        percent: f64,
        has_max: bool,
    ) -> Span<'static> {
        if !has_max {
            return Span::raw(text);
        }
        let level = usage_level(metric, percent);
        let marker = level.marker();
        let labeled = if marker.is_empty() {
            text
        } else {
            format!("{text}{marker}")
        };
        Span::styled(labeled, level.style())
    }

    #[must_use]
    pub fn border() -> Style {
        Style::default().fg(Self::BORDER)
    }

    #[must_use]
    pub fn border_focus() -> Style {
        Style::default().fg(Self::BORDER_FOCUS)
    }

    #[must_use]
    pub fn dim() -> Style {
        Style::default().fg(Self::TEXT_DIM)
    }

    #[must_use]
    pub fn muted() -> Style {
        Style::default().fg(Self::TEXT_MUTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_thresholds_boundaries_and_edge_cases() {
        assert_eq!(usage_level(UsageMetric::Cpu, 0.0), UsageLevel::Ok);
        assert_eq!(usage_level(UsageMetric::Cpu, 59.9), UsageLevel::Ok);
        assert_eq!(usage_level(UsageMetric::Cpu, 60.0), UsageLevel::Elevated);
        assert_eq!(usage_level(UsageMetric::Cpu, 79.9), UsageLevel::Elevated);
        assert_eq!(usage_level(UsageMetric::Cpu, 80.0), UsageLevel::High);
        assert_eq!(usage_level(UsageMetric::Cpu, 94.9), UsageLevel::High);
        assert_eq!(usage_level(UsageMetric::Cpu, 95.0), UsageLevel::Critical);
        assert_eq!(usage_level(UsageMetric::Cpu, 100.0), UsageLevel::Critical);
    }

    #[test]
    fn memory_and_disk_thresholds_boundaries() {
        for metric in [UsageMetric::Memory, UsageMetric::Disk] {
            assert_eq!(usage_level(metric, 0.0), UsageLevel::Ok);
            assert_eq!(usage_level(metric, 69.9), UsageLevel::Ok);
            assert_eq!(usage_level(metric, 70.0), UsageLevel::Elevated);
            assert_eq!(usage_level(metric, 79.9), UsageLevel::Elevated);
            assert_eq!(usage_level(metric, 80.0), UsageLevel::High);
            assert_eq!(usage_level(metric, 89.9), UsageLevel::High);
            assert_eq!(usage_level(metric, 90.0), UsageLevel::Critical);
            assert_eq!(usage_level(metric, 100.0), UsageLevel::Critical);
        }
    }

    #[test]
    fn nan_and_negative_percentages_map_to_ok_without_panic() {
        for metric in [UsageMetric::Cpu, UsageMetric::Memory, UsageMetric::Disk] {
            assert_eq!(usage_level(metric, f64::NAN), UsageLevel::Ok);
            assert_eq!(usage_level(metric, -0.1), UsageLevel::Ok);
            assert_eq!(usage_level(metric, -100.0), UsageLevel::Ok);
            assert_eq!(usage_level(metric, f64::NEG_INFINITY), UsageLevel::Ok);
        }
    }

    #[test]
    fn usage_span_with_max_zero_returns_unstyled_without_marker() {
        let span = Theme::usage_span("0%".to_string(), UsageMetric::Disk, 99.0, false);
        assert_eq!(span.content.as_ref(), "0%");
        assert_eq!(span.style, Style::default());

        let crit = Theme::usage_span("96%".to_string(), UsageMetric::Disk, 96.0, true);
        assert_eq!(crit.content.as_ref(), "96%!");
        assert_eq!(crit.style.fg, Some(Theme::DANGER));
    }

    fn srgb_channel_to_linear(c: u8) -> f64 {
        let s = f64::from(c) / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }

    #[allow(clippy::suboptimal_flops)]
    fn relative_luminance(color: Color) -> f64 {
        let Color::Rgb(r, g, b) = color else {
            panic!("expected Color::Rgb, got {color:?}");
        };
        0.2126 * srgb_channel_to_linear(r)
            + 0.7152 * srgb_channel_to_linear(g)
            + 0.0722 * srgb_channel_to_linear(b)
    }

    fn wcag_contrast_ratio(a: Color, b: Color) -> f64 {
        let la = relative_luminance(a);
        let lb = relative_luminance(b);
        let (lighter, darker) = if la >= lb { (la, lb) } else { (lb, la) };
        (lighter + 0.05) / (darker + 0.05)
    }

    #[test]
    fn every_usage_level_colour_meets_wcag_aa_contrast_against_bg() {
        for level in [
            UsageLevel::Ok,
            UsageLevel::Elevated,
            UsageLevel::High,
            UsageLevel::Critical,
        ] {
            let ratio = wcag_contrast_ratio(level.color(), Theme::BG);
            assert!(
                ratio >= 4.5,
                "level {level:?} colour {:?} has WCAG contrast ratio {ratio:.2}:1 < 4.5:1 against Theme::BG",
                level.color()
            );
        }
    }
}
