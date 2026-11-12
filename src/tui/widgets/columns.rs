//! Column widths for the TUI tables, chosen from the data and the space.
//!
//! The tables used fixed widths plus one `Min` column, and two things
//! went wrong on a real terminal. On a wide one the `Min` column took
//! every spare cell (the node name filled half of a 160-column screen
//! while the numbers sat crammed on the right); on an 80-column one the
//! layout solver shrank every column, so `stopped` printed as `stopp`
//! and `local-lvm` as `local-`. Here a column is as wide as its widest
//! value (within bounds), the last column takes what is left, and when
//! the columns do not fit the least useful ones are left out whole
//! instead of every one being cut.

use ratatui::layout::Constraint;

/// One table column: its header, the width it needs and whether it can
/// be left out when the table does not fit.
#[derive(Debug, Clone)]
pub struct Column {
    pub header: &'static str,
    pub width: u16,
    /// 0: always shown. Otherwise the column is dropped when the table
    /// is too wide, highest number first.
    pub drop: u8,
}

impl Column {
    #[must_use]
    pub const fn new(header: &'static str, width: u16, drop: u8) -> Self {
        Self {
            header,
            width,
            drop,
        }
    }
}

/// The width of a column holding `values`: the widest value or the
/// header, whichever is wider, within `min..=max`.
#[must_use]
pub fn content_width<'a>(
    header: &str,
    values: impl IntoIterator<Item = &'a str>,
    min: u16,
    max: u16,
) -> u16 {
    let widest = values
        .into_iter()
        .map(|v| v.chars().count())
        .chain(std::iter::once(header.chars().count()))
        .max()
        .unwrap_or(0);
    u16::try_from(widest).unwrap_or(u16::MAX).clamp(min, max)
}

/// Indices of the columns to show in `avail` cells, with one cell
/// between columns (ratatui's default spacing). Columns are dropped,
/// highest `drop` first, until the rest fit; columns with `drop == 0`
/// always stay.
#[must_use]
pub fn fit(columns: &[Column], avail: u16) -> Vec<usize> {
    let mut keep: Vec<usize> = (0..columns.len()).collect();
    loop {
        let need: usize = keep
            .iter()
            .filter_map(|&i| columns.get(i))
            .map(|c| usize::from(c.width))
            .sum::<usize>()
            + keep.len().saturating_sub(1);
        if need <= usize::from(avail) {
            break;
        }
        let Some(pos) = keep
            .iter()
            .enumerate()
            .filter(|(_, &i)| columns.get(i).is_some_and(|c| c.drop > 0))
            .max_by_key(|(pos, &i)| (columns.get(i).map_or(0, |c| c.drop), *pos))
            .map(|(pos, _)| pos)
        else {
            break;
        };
        keep.remove(pos);
    }
    keep
}

/// Constraints for the kept columns: each its width, the last one
/// `Min(width)` so it takes the space left over.
#[must_use]
pub fn constraints(columns: &[Column], keep: &[usize]) -> Vec<Constraint> {
    keep.iter()
        .enumerate()
        .filter_map(|(n, &i)| {
            let c = columns.get(i)?;
            Some(if n + 1 == keep.len() {
                Constraint::Min(c.width)
            } else {
                Constraint::Length(c.width)
            })
        })
        .collect()
}

/// The items of `row` at the kept indices, in order.
#[must_use]
pub fn pick<T: Clone>(row: &[T], keep: &[usize]) -> Vec<T> {
    keep.iter().filter_map(|&i| row.get(i).cloned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_width_takes_the_widest_value_within_bounds() {
        assert_eq!(content_width("name", ["web", "database-01"], 4, 30), 11);
        assert_eq!(content_width("name", ["a"], 4, 30), 4);
        assert_eq!(content_width("name", ["x".repeat(80).as_str()], 4, 30), 30);
    }

    #[test]
    fn fit_drops_the_highest_drop_number_first_and_keeps_the_rest() {
        let cols = [
            Column::new("vmid", 6, 0),
            Column::new("name", 20, 0),
            Column::new("disk", 8, 2),
            Column::new("tags", 10, 1),
        ];
        // All: 6 + 20 + 8 + 10 + 3 spaces = 47.
        assert_eq!(fit(&cols, 47), vec![0, 1, 2, 3]);
        // One short: disk (drop 2) goes before tags (drop 1).
        assert_eq!(fit(&cols, 46), vec![0, 1, 3]);
        assert_eq!(fit(&cols, 30), vec![0, 1]);
        // Never below the columns that must stay.
        assert_eq!(fit(&cols, 5), vec![0, 1]);
    }

    #[test]
    fn the_last_kept_column_takes_the_leftover() {
        let cols = [Column::new("a", 3, 0), Column::new("b", 5, 1)];
        assert_eq!(
            constraints(&cols, &[0, 1]),
            vec![Constraint::Length(3), Constraint::Min(5)]
        );
        assert_eq!(constraints(&cols, &[0]), vec![Constraint::Min(3)]);
        assert_eq!(pick(&["x", "y"], &[1]), vec!["y"]);
    }
}
