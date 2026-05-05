//! Compact stdout sparkline + summary stats for time-series data.
//!
//! Used by the `proxxx metrics` CLI to render rrddata responses
//! without spinning up a TUI. The Unicode block-element charset
//! (`▁▂▃▄▅▆▇█`) gives 8 levels of resolution per character; a 60-
//! point series fits in 60 columns — well under the typical 80-col
//! terminal width.
//!
//! Design:
//! - **NaN-tolerant**: PVE rrddata contains `null` values when the
//!   metric was unavailable for an interval. We expose them as
//!   `Option<f64>` (caller filters), then NaN/None render as a space
//!   in the sparkline so gaps stay visible.
//! - **Constant-series safe**: when min == max the normalized value
//!   `(v - min) / range` would be 0/0; we render the whole series at
//!   the mid block (▄) so the operator sees "flat" instead of a
//!   confusing artefact.
//! - **No allocation in the hot path** beyond the `String` collect:
//!   stats run in one pass, sparkline in another.

const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// Rendered for None / NaN buckets so gaps stay visible in the
/// sparkline at the same column position they occupied in the data.
const GAP: char = ' ';

/// Three-number summary of a series, ignoring None / NaN.
/// `count` is the number of FINITE values that contributed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
}

impl Summary {
    /// One-pass min/max/sum over a slice of `Option<f64>`. Skips
    /// None and non-finite (NaN, ±Inf) values. Returns None when no
    /// finite values exist (e.g. all-empty series).
    #[must_use]
    pub fn of(values: &[Option<f64>]) -> Option<Self> {
        let mut count = 0usize;
        let mut sum = 0.0f64;
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for &v in values {
            if let Some(x) = v {
                if x.is_finite() {
                    count += 1;
                    sum += x;
                    if x < min {
                        min = x;
                    }
                    if x > max {
                        max = x;
                    }
                }
            }
        }
        if count == 0 {
            None
        } else {
            #[allow(clippy::cast_precision_loss)]
            let avg = sum / count as f64;
            Some(Self {
                count,
                min,
                max,
                avg,
            })
        }
    }
}

/// Render `values` as a Unicode block-element sparkline.
///
/// - None / NaN → space (preserves column alignment with the source
///   series).
/// - All-finite + flat (min == max) → the mid block repeated.
/// - Otherwise → block selected from the 8-step ramp, normalized to
///   the series' own (min, max) range.
///
/// Output length equals input length (bytes can vary because each
/// block char is multi-byte UTF-8).
#[must_use]
pub fn render(values: &[Option<f64>]) -> String {
    let Some(s) = Summary::of(values) else {
        // No finite values at all — render an all-gap line so the
        // operator sees the slot count without misleading data.
        return GAP.to_string().repeat(values.len());
    };
    let range = s.max - s.min;
    values
        .iter()
        .map(|&v| match v {
            Some(x) if x.is_finite() => {
                if range == 0.0 {
                    BLOCKS[3]
                } else {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let idx = (((x - s.min) / range) * 7.0).round() as usize;
                    BLOCKS[idx.min(7)]
                }
            }
            _ => GAP,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_skips_none_and_nan() {
        let v = vec![Some(1.0), None, Some(f64::NAN), Some(3.0), Some(5.0)];
        let s = Summary::of(&v).expect("3 finite values");
        assert_eq!(s.count, 3);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 5.0);
        assert!((s.avg - 3.0).abs() < 1e-9);
    }

    #[test]
    fn summary_returns_none_when_all_empty() {
        let v = vec![None::<f64>, None, None];
        assert!(Summary::of(&v).is_none());
        // Same for all-NaN.
        let v2 = vec![Some(f64::NAN), Some(f64::INFINITY), Some(f64::NEG_INFINITY)];
        assert!(Summary::of(&v2).is_none());
    }

    #[test]
    fn render_preserves_length_with_gaps() {
        let v = vec![Some(1.0), None, Some(3.0), Some(f64::NAN), Some(5.0)];
        let out = render(&v);
        // 5 input slots → 5 output chars (none of which are
        // multi-codepoint clusters, so .chars() count == 5).
        assert_eq!(out.chars().count(), 5);
        // Gap chars sit at index 1 and 3.
        let chars: Vec<char> = out.chars().collect();
        assert_eq!(chars[1], GAP);
        assert_eq!(chars[3], GAP);
    }

    #[test]
    fn render_flat_series_uses_middle_block() {
        let v = vec![Some(2.0); 10];
        let out = render(&v);
        // All same → all middle block (BLOCKS[3] = ▄).
        assert!(out.chars().all(|c| c == BLOCKS[3]));
    }

    #[test]
    fn render_ramp_uses_full_range() {
        // 0..7 should map onto each of the 8 blocks once.
        let v: Vec<Option<f64>> = (0..8).map(|i| Some(f64::from(i))).collect();
        let out = render(&v);
        let chars: Vec<char> = out.chars().collect();
        assert_eq!(chars[0], BLOCKS[0]);
        assert_eq!(chars[7], BLOCKS[7]);
    }

    #[test]
    fn render_empty_returns_empty() {
        assert!(render(&[]).is_empty());
    }

    #[test]
    fn render_all_none_returns_only_gaps() {
        let v: Vec<Option<f64>> = vec![None; 5];
        let out = render(&v);
        assert_eq!(out, "     ");
    }
}
