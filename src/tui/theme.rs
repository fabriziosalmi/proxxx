use ratatui::style::{Color, Modifier, Style};

/// Color palette — adapts to terminal capabilities. The full palette
/// is exposed even though not every entry is referenced today; views
/// pull what they need and adding a new entry doesn't require API
/// churn.
#[allow(dead_code)]
pub struct Theme;

#[allow(dead_code)]
impl Theme {
    // ── Semantic Colors ─────────────────────────────────
    pub const ACCENT: Color = Color::Rgb(99, 102, 241); // Indigo-500 (brand)
    pub const SUCCESS: Color = Color::Rgb(34, 197, 94); // Green-500 (running, ok, low-usage)
    pub const WARNING: Color = Color::Rgb(234, 179, 8); // Yellow-500 (stale, mid-usage)
    pub const DANGER: Color = Color::Rgb(239, 68, 68); // Red-500 (stopped, high-usage, errors)
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

    pub fn title() -> Style {
        Style::default().fg(Self::TEXT).add_modifier(Modifier::BOLD)
    }

    pub fn header() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn selected() -> Style {
        Style::default()
            .bg(Self::BG_SELECTED)
            .fg(Self::TEXT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn status_badge(status: &str) -> Style {
        match status {
            "running" | "online" => Style::default().fg(Self::SUCCESS),
            "stopped" | "offline" => Style::default().fg(Self::DANGER),
            "paused" | "suspended" => Style::default().fg(Self::INFO),
            _ => Style::default().fg(Self::WARNING),
        }
    }

    pub fn gauge_color(percent: f64) -> Color {
        if percent < 50.0 {
            Self::SUCCESS
        } else if percent < 80.0 {
            Self::WARNING
        } else {
            Self::DANGER
        }
    }

    pub fn border() -> Style {
        Style::default().fg(Self::BORDER)
    }

    pub fn border_focus() -> Style {
        Style::default().fg(Self::BORDER_FOCUS)
    }

    pub fn dim() -> Style {
        Style::default().fg(Self::TEXT_DIM)
    }

    pub fn muted() -> Style {
        Style::default().fg(Self::TEXT_MUTED)
    }
}
