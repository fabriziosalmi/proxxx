//! Shared filesystem path utilities.
//!
//! Centralises tilde expansion (`~` and `~/...`) so config fields
//! (`token_secret_file`, `pbs.token_secret_file`, `telegram.bot_token_file`,
//! `ssh.key_path`, `ssh.known_hosts`, `ssh.guests.*.key_path`),
//! `proxxx doctor`, `proxxx init --interactive`, and cloud-init
//! `sshkey_file` all resolve paths identically.

use std::path::{Path, PathBuf};

/// Expand a leading `~` or `~/...` against an explicit `home` directory.
///
/// Rules:
/// - `"~"` expands to `home` when `home` is `Some` and non-empty.
/// - `"~/rest"` expands to `home.join("rest")` when `home` is `Some` and non-empty.
/// - Absolute paths (`"/abs"`), relative paths (`"rel"`), and named-user
///   prefixes (`"~user"`, `"~user/x"`) are returned unchanged.
#[must_use]
pub fn expand_tilde_with_home(path: &str, home: Option<&Path>) -> PathBuf {
    let valid_home = home.filter(|h| !h.as_os_str().is_empty());
    if path == "~" {
        if let Some(h) = valid_home {
            return h.to_path_buf();
        }
    } else if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(h) = valid_home {
            return h.join(stripped);
        }
    }
    PathBuf::from(path)
}

/// Expand a leading `~` or `~/...` using the process `HOME` environment variable.
///
/// Leaves `/abs`, `rel`, and `~user` paths untouched. If `HOME` is unset or
/// empty, returns `PathBuf::from(path)` unchanged.
#[must_use]
pub fn expand_tilde(path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expand_tilde_with_home(path, home.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_bare_tilde_and_tilde_slash_and_leaves_abs_rel_and_tilde_user_as_is() {
        let home = Path::new("/tmp/proxxx-unit-home");
        assert_eq!(
            expand_tilde_with_home("~", Some(home)),
            PathBuf::from("/tmp/proxxx-unit-home")
        );
        assert_eq!(
            expand_tilde_with_home("~/x", Some(home)),
            PathBuf::from("/tmp/proxxx-unit-home/x")
        );
        assert_eq!(
            expand_tilde_with_home("~/nested/dir/file.txt", Some(home)),
            PathBuf::from("/tmp/proxxx-unit-home/nested/dir/file.txt")
        );
        assert_eq!(
            expand_tilde_with_home("/abs", Some(home)),
            PathBuf::from("/abs")
        );
        assert_eq!(
            expand_tilde_with_home("rel", Some(home)),
            PathBuf::from("rel")
        );
        assert_eq!(
            expand_tilde_with_home("~user", Some(home)),
            PathBuf::from("~user")
        );
        assert_eq!(
            expand_tilde_with_home("~user/x", Some(home)),
            PathBuf::from("~user/x")
        );
        assert_eq!(expand_tilde_with_home("~", None), PathBuf::from("~"));
        assert_eq!(expand_tilde_with_home("~/x", None), PathBuf::from("~/x"));
        assert_eq!(
            expand_tilde_with_home("~/x", Some(Path::new(""))),
            PathBuf::from("~/x")
        );

        if let Some(real_home) = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| !h.as_os_str().is_empty())
        {
            assert_eq!(expand_tilde("~"), real_home);
            assert_eq!(expand_tilde("~/x"), real_home.join("x"));
        }
        assert_eq!(expand_tilde("/abs"), PathBuf::from("/abs"));
        assert_eq!(expand_tilde("rel"), PathBuf::from("rel"));
        assert_eq!(expand_tilde("~user"), PathBuf::from("~user"));
    }
}
