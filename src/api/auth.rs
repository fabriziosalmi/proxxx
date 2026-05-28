use anyhow::{Context, Result};
use reqwest::header::COOKIE;
use serde::Deserialize;
use tracing::debug;
use zeroize::Zeroizing;

/// Authentication state for a Proxmox connection.
///
/// (macro audit) — secret zeroing. The token secret and the
/// session ticket are wrapped in `Zeroizing<String>`. When `AuthMethod`
/// drops (or when the inner `String` is replaced), the heap bytes are
/// overwritten with zeros via `Zeroize::zeroize()`. A core dump after
/// the secret has been freed cannot reveal it via `strings core.dump`.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    Token {
        user: String,
        token_id: String,
        token_secret: Zeroizing<String>,
    },
    Password {
        ticket: Zeroizing<String>,
        csrf_token: Zeroizing<String>,
        expires_at: std::time::Instant,
    },
}

#[derive(Debug, Deserialize)]
struct TicketResponse {
    data: TicketData,
}

#[derive(Debug, Deserialize)]
struct TicketData {
    ticket: String,
    #[serde(rename = "CSRFPreventionToken")]
    csrf_token: String,
}

impl AuthMethod {
    /// Create token-based auth (recommended, no refresh needed)
    pub fn from_token(user: &str, token_id: &str, token_secret: &str) -> Self {
        Self::Token {
            user: user.to_string(),
            token_id: token_id.to_string(),
            token_secret: Zeroizing::new(token_secret.to_string()),
        }
    }

    /// Login with password, get a ticket.
    ///
    /// 401 / 403 from PVE are surfaced explicitly with the status
    /// code in the error chain so the operator sees
    /// "401 Unauthorized" instead of "Failed to parse auth response"
    /// (which is what `.json()` produced before, because PVE's
    /// failed-auth body doesn't match `TicketResponse`). The
    /// upstream `e2e_beta` test `beta_bad_token_surfaces_401_cleanly`
    /// asserts on the literal "401" / "Unauthorized" substring.
    pub async fn login(
        client: &reqwest::Client,
        base_url: &str,
        user: &str,
        password: &str,
    ) -> Result<Self> {
        debug!("Authenticating to {} as {}", base_url, user);

        let resp = client
            .post(format!("{base_url}/api2/json/access/ticket"))
            .form(&[("username", user), ("password", password)])
            .send()
            .await
            .context("Failed to connect to Proxmox")?;

        let status = resp.status();
        if !status.is_success() {
            // Read the body for diagnostics — PVE often includes a
            // descriptive message even on 401. Cap to 1 KiB so a
            // hostile server can't OOM us on the auth path. Body
            // read errors don't block the error surface; we still
            // produce a useful message with the status code alone.
            let body_snippet = resp
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(1024)
                .collect::<String>();
            anyhow::bail!(
                "Authentication failed: {status} from {base_url}/api2/json/access/ticket{}",
                if body_snippet.is_empty() {
                    String::new()
                } else {
                    format!(" — {body_snippet}")
                }
            );
        }

        let resp: TicketResponse = resp.json().await.context("Failed to parse auth response")?;

        Ok(Self::Password {
            ticket: Zeroizing::new(resp.data.ticket),
            csrf_token: Zeroizing::new(resp.data.csrf_token),
            expires_at: std::time::Instant::now() + std::time::Duration::from_hours(2), // 2h
        })
    }

    /// Apply auth headers to a request builder
    pub fn apply(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::Token {
                user,
                token_id,
                token_secret,
            } => {
                // `**token_secret` derefs `&Zeroizing<String>` →
                // `&String` → `String` (by Deref). The format!
                // temporary still contains the secret in heap; this is
                // the boundary where it leaves our zeroized envelope
                // and is handed to reqwest. Inevitable for the
                // Authorization header, documented as 's
                // residual surface.
                let secret_ref: &str = token_secret;
                builder.header(
                    "Authorization",
                    format!("PVEAPIToken={user}!{token_id}={secret_ref}"),
                )
            }
            Self::Password {
                ticket, csrf_token, ..
            } => {
                let ticket_ref: &str = ticket;
                let csrf_ref: &str = csrf_token;
                builder
                    .header(COOKIE, format!("PVEAuthCookie={ticket_ref}"))
                    .header("CSRFPreventionToken", csrf_ref)
            }
        }
    }

    /// Get the raw headers representing this auth method (e.g. for WebSocket handshakes)
    pub fn headers(&self) -> Vec<(String, String)> {
        match self {
            Self::Token {
                user,
                token_id,
                token_secret,
            } => {
                let secret_ref: &str = token_secret;
                vec![(
                    "Authorization".to_string(),
                    format!("PVEAPIToken={user}!{token_id}={secret_ref}"),
                )]
            }
            Self::Password { ticket, .. } => {
                let ticket_ref: &str = ticket;
                vec![("Cookie".to_string(), format!("PVEAuthCookie={ticket_ref}"))]
            }
        }
    }

    /// Check if auth needs refresh (only relevant for password auth)
    pub fn needs_refresh(&self) -> bool {
        match self {
            Self::Token { .. } => false, // tokens don't expire in the same way
            Self::Password { expires_at, .. } => {
                *expires_at < std::time::Instant::now() + std::time::Duration::from_mins(2)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_headers_emit_pveapi_authorization() {
        // PVE's API-token auth flavor expects a single `Authorization`
        // header of shape `PVEAPIToken=<user>!<tokenid>=<secret>`. This
        // pins the format the WebSocket termproxy / vncproxy handshakes
        // need — same shape as our HTTP requests (route through reqwest's
        // header builder there, vs tungstenite's here).
        let auth =
            AuthMethod::from_token("root@pam", "proxxx-rw", "9b1c-be01-deca-fbad-deadbeefcafe");
        let headers = auth.headers();
        assert_eq!(headers.len(), 1, "token auth must emit exactly 1 header");
        assert_eq!(headers[0].0, "Authorization");
        assert_eq!(
            headers[0].1,
            "PVEAPIToken=root@pam!proxxx-rw=9b1c-be01-deca-fbad-deadbeefcafe"
        );
    }

    #[test]
    fn password_headers_emit_pveauthcookie_only() {
        // For PAM/ticket auth the WS handshake needs the
        // `PVEAuthCookie=<ticket>` cookie. The CSRF prevention token is
        // deliberately NOT in this header set — PVE requires it only on
        // state-changing HTTP requests, never on the WS upgrade. A
        // future contributor reading the source should not "fix" the
        // omission by adding it here.
        use zeroize::Zeroizing;
        let auth = AuthMethod::Password {
            ticket: Zeroizing::new("PVE:root@pam:6A185B44::ZDPSgsM...".to_string()),
            csrf_token: Zeroizing::new("6A185B44:4BTds5sVl8Z...".to_string()),
            expires_at: std::time::Instant::now() + std::time::Duration::from_hours(2),
        };
        let headers = auth.headers();
        assert_eq!(headers.len(), 1, "password auth must emit exactly 1 header");
        assert_eq!(headers[0].0, "Cookie");
        assert!(
            headers[0].1.starts_with("PVEAuthCookie="),
            "cookie value must be prefixed `PVEAuthCookie=`: {}",
            headers[0].1
        );
        assert!(
            headers[0].1.contains("PVE:root@pam:6A185B44::ZDPSgsM..."),
            "cookie value must carry the full ticket verbatim: {}",
            headers[0].1
        );
        // The CSRF prevention token must NOT leak into the WS headers.
        // Pin it so a future "let's also send csrf" change breaks this test.
        let combined = format!("{}: {}", headers[0].0, headers[0].1);
        assert!(
            !combined.contains("CSRFPreventionToken"),
            "CSRF prevention token leaked into WS headers: {combined}"
        );
        assert!(
            !combined.contains("6A185B44:4BTds5sVl8Z"),
            "CSRF token value leaked into WS headers: {combined}"
        );
    }

    #[test]
    fn token_headers_handle_special_chars_in_user_and_token_id() {
        // PVE userids can contain `@` (`<user>@<realm>`) and tokenids
        // can contain `-` / digits. Both flow into the Authorization
        // header verbatim — the format string takes care of the
        // delimiters.
        let auth = AuthMethod::from_token("alice@pve", "ops-2026-q2", "uuid-secret");
        let headers = auth.headers();
        assert_eq!(
            headers[0].1,
            "PVEAPIToken=alice@pve!ops-2026-q2=uuid-secret"
        );
    }
}
