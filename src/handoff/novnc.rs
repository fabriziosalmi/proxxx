//! noVNC handoff — open the Proxmox web UI's noVNC console (#1c).
//!
//! Honest scope: we do NOT inject auth tickets into the URL. Proxmox
//! supports a `#PVEAuthCookie=...` URL fragment trick but it leaks the
//! ticket into shell history, browser history, screenshots, etc. The
//! reliable + safe path is: user is already logged into the web UI in
//! their browser, we just deep-link them to the right console panel.
//!
//! If the user isn't logged in, the web UI redirects to its login form
//! and they sign in once — same UX as clicking "Console" in the GUI.

use crate::api::types::GuestType;

/// Build the deep-link URL for a guest's noVNC console.
///
/// `api_base_url` is the same URL the REST client uses (e.g.
/// `"https://pve1.lan:8006"`). The web UI shares the host:port — the
/// query keys (`console`, `novnc`, `vmid`, `node`) match what the
/// PVE web UI's "Console" button sets in its address bar.
/// Extract `host:port` from a REST base URL — strip the scheme and any
/// trailing path, keep the authority. The PVE web UI shares host:port
/// with the API, so both deep-link builders below reuse this.
fn host_port_of(api_base_url: &str) -> &str {
    let after_scheme = api_base_url
        .split_once("://")
        .map_or(api_base_url, |(_, rest)| rest);
    after_scheme
        .split_once('/')
        .map_or(after_scheme, |(h, _)| h)
}

#[must_use]
pub fn build_novnc_url(api_base_url: &str, node: &str, vmid: u32, guest_type: GuestType) -> String {
    // For QEMU the console kind is `kvm`; for LXC it's `lxc`.
    let console_kind = match guest_type {
        GuestType::Qemu => "kvm",
        GuestType::Lxc => "lxc",
    };
    let host_port = host_port_of(api_base_url);
    format!(
        "https://{host_port}/?console={console_kind}&novnc=1&vmid={vmid}&node={node}&resize=scale"
    )
}

/// Build a deep-link into the PVE web UI's API-token panel
/// (Datacenter → Permissions → API Tokens).
///
/// `api_base_url` is the same URL the REST client uses (e.g.
/// `"https://pve1.lan:8006"`); the web UI shares host:port. The
/// `#v1:0:18:...` fragment is PVE's internal tree-route for that view —
/// version-specific, so it lives here (one place to fix if a future PVE
/// renumbers the route) rather than hard-coded in every consumer.
#[must_use]
pub fn token_page_url(api_base_url: &str) -> String {
    let host_port = host_port_of(api_base_url);
    format!("https://{host_port}/#v1:0:18:4:::::::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_url_uses_kvm_console_kind() {
        let url = build_novnc_url("https://pve1.lan:8006", "pve1", 100, GuestType::Qemu);
        assert!(url.contains("console=kvm"));
        assert!(url.contains("vmid=100"));
        assert!(url.contains("node=pve1"));
        assert!(url.contains("novnc=1"));
        assert!(url.starts_with("https://pve1.lan:8006/"));
    }

    #[test]
    fn lxc_url_uses_lxc_console_kind() {
        let url = build_novnc_url("https://pve1.lan:8006", "pve1", 200, GuestType::Lxc);
        assert!(url.contains("console=lxc"));
        assert!(!url.contains("console=kvm"));
        assert!(url.contains("vmid=200"));
    }

    #[test]
    fn handles_base_url_with_trailing_path() {
        let url = build_novnc_url(
            "https://pve.local:8006/api2/json",
            "pve1",
            1,
            GuestType::Qemu,
        );
        assert!(url.starts_with("https://pve.local:8006/?"));
        assert!(!url.contains("/api2/json"));
    }

    #[test]
    fn url_includes_resize_scale_for_better_default_ux() {
        // resize=scale tells noVNC to fit the canvas to the browser
        // window — better than the default which can be tiny.
        let url = build_novnc_url("https://x:8006", "n", 1, GuestType::Qemu);
        assert!(url.contains("resize=scale"));
    }

    #[test]
    fn token_page_url_shares_host_port_with_api() {
        let url = token_page_url("https://pve1.lan:8006");
        assert!(url.starts_with("https://pve1.lan:8006/#"));
        assert!(url.contains("#v1:"));
    }

    #[test]
    fn token_page_url_strips_scheme_and_trailing_path() {
        let url = token_page_url("https://pve.local:8006/api2/json");
        assert!(url.starts_with("https://pve.local:8006/#"));
        assert!(!url.contains("/api2/json"));
    }
}
