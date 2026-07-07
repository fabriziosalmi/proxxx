use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::util::secret::SecretString;

/// Default Telegram Bot API base URL. Tests override via
/// `TelegramGateway::with_base_url()` so they can point at a wiremock
/// `MockServer::uri()`. Production code goes through `new()`.
const DEFAULT_TG_API: &str = "https://api.telegram.org/bot";

/// Escape every `MarkdownV2` reserved character with a leading `\`.
///
/// Per <https://core.telegram.org/bots/api#markdownv2-style>, the
/// reserved set is `_*[]()~`>#+-=|{}.!\`. Any of these in
/// non-formatting position must be backslash-escaped or Telegram
/// rejects the message with `400 Bad Request: can't parse entities`.
/// We escape conservatively: every reserved char, regardless of
/// context — over-escaping is harmless because Telegram strips the
/// leading `\` on render.
#[must_use]
pub(crate) fn escape_markdown_v2(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '_' | '*'
                | '['
                | ']'
                | '('
                | ')'
                | '~'
                | '`'
                | '>'
                | '#'
                | '+'
                | '-'
                | '='
                | '|'
                | '{'
                | '}'
                | '.'
                | '!'
                | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[derive(Serialize)]
struct InlineKeyboardButton {
    text: String,
    callback_data: String,
}

#[derive(Serialize)]
struct InlineKeyboardMarkup {
    inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

#[derive(Serialize)]
struct SendMessageReq {
    chat_id: String,
    text: String,
    parse_mode: String,
    reply_markup: InlineKeyboardMarkup,
}

#[derive(Deserialize, Debug)]
struct TgResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Message {
    /// Telegram-assigned id for THIS message. Required for the
    /// lifecycle-edit flow: when a callback arrives, the daemon
    /// reads `cb.message.message_id` and calls `edit_message_text`
    /// to replace the inline-keyboard message with a status footer
    /// (`⏳ Executing…` → `✅ Done` / `❌ Failed`). Without `pub`
    /// the daemon can't access the id from outside the module.
    pub message_id: i64,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Update {
    pub update_id: i64,
    pub callback_query: Option<CallbackQuery>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    pub message: Option<Message>,
    pub data: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct User {
    pub username: Option<String>,
    pub first_name: String,
}

/// HTTP gateway to the Telegram Bot API.
///
/// Phase 5.13 — refactored to take a pre-resolved bot token (so the
/// caller controls the credential hierarchy: env / file / keychain /
/// inline) and an injectable base URL (so tests can point at a
/// wiremock server). The previous shape baked the token + URL into a
/// `TelegramConfig` struct passed by value, which made wiremock-based
/// E2E tests impossible.
pub struct TelegramGateway {
    http: Client,
    /// Pre-resolved bot token. `SecretString`: the token lives as long
    /// as the gateway, so it must be redacted-in-Debug and wiped on
    /// drop. The Telegram API embeds it in every request URL by design
    /// (`{base}{token}/{method}`) — those are the explicit `.expose()`
    /// sites below; the panic-hook scrubber covers the crash path.
    bot_token: SecretString,
    chat_id: String,
    /// Telegram Bot API base, e.g. `"https://api.telegram.org/bot"`.
    /// MUST end without a trailing slash and without the token —
    /// the per-request URL is built as `{base}{token}/{method}`.
    base_url: String,
    /// Phase 17 audit fix: HMAC key used to sign outbound
    /// `callback_data`. Auto-bootstrapped on first `new()` /
    /// `from_config()` call. Tests inject a deterministic key via
    /// `with_base_url_and_key`.
    hmac_key: Vec<u8>,
}

impl TelegramGateway {
    /// Production constructor — uses the public Telegram API endpoint.
    /// `bot_token` must be the resolved token (caller is responsible
    /// for going through `TelegramConfig::resolve_bot_token`).
    ///
    /// Loads (or auto-generates) the HMAC key from disk on each call.
    /// File I/O here is fine: HITL gateways are constructed once per
    /// process, not per request.
    pub fn new(bot_token: impl Into<SecretString>, chat_id: String) -> Result<Self> {
        let hmac_key = crate::hitl::hmac_key::load_or_generate_hmac_key()?;
        Ok(Self {
            // A request timeout so send/edit/approve can't hang forever on a
            // wedged connection. The long-poll path sets its own (longer)
            // per-request timeout, which overrides this client default.
            http: Client::builder().timeout(Duration::from_secs(30)).build()?,
            bot_token: bot_token.into(),
            chat_id,
            base_url: DEFAULT_TG_API.to_string(),
            hmac_key,
        })
    }

    /// Test constructor — point at a wiremock `MockServer::uri()` so the
    /// gateway hits the local fixture instead of api.telegram.org.
    /// The `base_url` should be the full URL up to (but not including)
    /// the bot token segment — typically `format!("{}/bot", server.uri())`.
    ///
    /// Uses a fixed all-zeros HMAC key so tests can pre-compute valid
    /// callback signatures without coordinating on a random secret.
    /// Production code must NEVER take this path.
    #[must_use]
    pub fn with_base_url(
        bot_token: impl Into<SecretString>,
        chat_id: String,
        base_url: String,
    ) -> Self {
        Self::with_base_url_and_key(bot_token, chat_id, base_url, vec![0u8; 32])
    }

    /// Test constructor that accepts an explicit HMAC key — used by the
    /// HMAC-specific tests that need to verify cross-instance signing.
    #[must_use]
    pub fn with_base_url_and_key(
        bot_token: impl Into<SecretString>,
        chat_id: String,
        base_url: String,
        hmac_key: Vec<u8>,
    ) -> Self {
        Self {
            http: Client::new(),
            bot_token: bot_token.into(),
            chat_id,
            base_url,
            hmac_key,
        }
    }

    /// Read-only handle to the HMAC key. The daemon-side verifier needs
    /// this to validate inbound `callback_data` against the same key
    /// that signed it.
    #[must_use]
    pub fn hmac_key(&self) -> &[u8] {
        &self.hmac_key
    }

    /// High-level convenience: resolve the bot token via the configured
    /// hierarchy (env / file / inline / keychain) and build the gateway.
    /// Use this from production call sites; tests should prefer
    /// `with_base_url()` and pass an explicit fake token.
    pub async fn from_config(config: &crate::config::TelegramConfig) -> Result<Self> {
        let token = config.resolve_bot_token().await?;
        Self::new(token, config.chat_id.clone())
    }

    /// Sends a request for approval to the Telegram chat.
    /// Returns the `message_id` to track it.
    pub async fn request_approval(
        &self,
        action: &str,
        target: &str,
        reason: &str,
        txn_id: &str,
    ) -> Result<i64> {
        // Phase 5.13 — escape user-controlled values inserted into the
        // MarkdownV2 message body. Without this, any reason / txn_id /
        // action containing one of MarkdownV2's reserved chars
        // (`[]()~>#+-=|{}.!_*\``) trips Telegram with `400 Bad Request:
        // can't parse entities`. The static prefix is hand-crafted
        // markdown and safe by inspection.
        let text = format!(
            "🚨 *HITL Approval Required*\n\n*Action:* `{}`\n*Target:* `{}`\n*Reason:* {}\n*Txn:* `{}`",
            escape_markdown_v2(action),
            escape_markdown_v2(target),
            escape_markdown_v2(reason),
            escape_markdown_v2(txn_id),
        );

        // Phase 17: HMAC-sign each callback_data so the daemon-side
        // verifier rejects forgeries from anyone who steals the bot
        // token but not the HMAC key. Tag is appended as `:<hex>` to
        // the existing `decision:txn_id` shape; the daemon parser
        // peels it off and re-verifies before consuming the txn.
        let approve_payload = format!("approve:{txn_id}");
        let approve_tag = crate::hitl::hmac_key::sign(&self.hmac_key, &approve_payload);
        let deny_payload = format!("deny:{txn_id}");
        let deny_tag = crate::hitl::hmac_key::sign(&self.hmac_key, &deny_payload);

        let req = SendMessageReq {
            chat_id: self.chat_id.clone(),
            text,
            parse_mode: "MarkdownV2".to_string(),
            reply_markup: InlineKeyboardMarkup {
                inline_keyboard: vec![vec![
                    InlineKeyboardButton {
                        text: "✅ Approve".to_string(),
                        callback_data: format!("{approve_payload}:{approve_tag}"),
                    },
                    InlineKeyboardButton {
                        text: "❌ Deny".to_string(),
                        callback_data: format!("{deny_payload}:{deny_tag}"),
                    },
                ]],
            },
        };

        let url = format!("{}{}/sendMessage", self.base_url, self.bot_token.expose());
        let resp: TgResponse<Message> =
            self.http.post(&url).json(&req).send().await?.json().await?;

        if resp.ok {
            if let Some(m) = resp.result {
                info!(
                    "Approval request sent to Telegram (msg_id: {})",
                    m.message_id
                );
                Ok(m.message_id)
            } else {
                anyhow::bail!("No result in successful response");
            }
        } else {
            anyhow::bail!(
                "Telegram API error: {}",
                resp.description.unwrap_or_default()
            );
        }
    }

    /// Sends a simple message to the Telegram chat as plain text.
    ///
    /// Phase 5.13 — dropped `parse_mode: MarkdownV2` here. The callers
    /// are the alert engine and the `watch --notify` path, both of
    /// which produce free-form text containing rule names like
    /// `[node_offline]` — the brackets trip `MarkdownV2`'s parser. Plain
    /// text renders correctly (emojis are inert unicode) and removes
    /// an entire class of "Telegram rejected your alert" failures.
    /// The `request_approval` path KEEPS `MarkdownV2` because it
    /// produces hand-crafted markdown with `*bold*` and `` `code` ``,
    /// and now escapes the user-controlled inserts.
    pub async fn send_message(&self, text: &str) -> Result<()> {
        let req = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
        });

        let url = format!("{}{}/sendMessage", self.base_url, self.bot_token.expose());
        let resp: TgResponse<Message> =
            self.http.post(&url).json(&req).send().await?.json().await?;

        if resp.ok {
            Ok(())
        } else {
            anyhow::bail!(
                "Telegram API error: {}",
                resp.description.unwrap_or_default()
            );
        }
    }

    /// Long-poll for callback queries (button clicks)
    pub async fn poll_updates(&self, offset: i64, timeout: u64) -> Result<Vec<Update>> {
        let url = format!(
            "{}{}/getUpdates?offset={}&timeout={}&allowed_updates=[\"callback_query\"]",
            self.base_url,
            self.bot_token.expose(),
            offset,
            timeout
        );

        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(timeout + 5))
            .send()
            .await?;

        let tg_resp: TgResponse<Vec<Update>> = resp.json().await?;

        if tg_resp.ok {
            Ok(tg_resp.result.unwrap_or_default())
        } else {
            anyhow::bail!(
                "Telegram getUpdates error: {}",
                tg_resp.description.unwrap_or_default()
            );
        }
    }

    /// Replace the body of a previously-sent message — used by the
    /// HITL daemon to reflect outcome state (`⏳`, `✅`, `❌`,
    /// `⚠️ Stale`) on the original approval message instead of
    /// leaving the inline keyboard stale forever.
    ///
    /// Sends `editMessageText` with the inline keyboard EMPTY
    /// (`reply_markup: { inline_keyboard: [[]] }`) so the buttons
    /// disappear from the message after the outcome is recorded.
    /// Telegram silently ignores the edit if the new content is
    /// identical to the previous body — operators can re-emit the
    /// same status safely.
    ///
    /// `text` is sent as plain text (no `parse_mode`) — same
    /// reasoning as `send_message`: lifecycle status strings contain
    /// `[REDACTED]`, action verbs, error fragments that would trip
    /// `MarkdownV2` parsing if any contained reserved chars.
    pub async fn edit_message_text(&self, message_id: i64, text: &str) -> Result<()> {
        let url = format!(
            "{}{}/editMessageText",
            self.base_url,
            self.bot_token.expose()
        );
        let payload = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "text": text,
            // Empty keyboard = clear the buttons.
            "reply_markup": { "inline_keyboard": Vec::<Vec<()>>::new() },
        });
        let resp = self.http.post(&url).json(&payload).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Telegram returns 400 for "message is not modified" —
            // not actually an error from our perspective. Suppress.
            if body.contains("message is not modified") {
                return Ok(());
            }
            anyhow::bail!("Telegram editMessageText {status}: {body}");
        }
        Ok(())
    }

    /// Answer a callback query to remove the loading state on the button
    pub async fn answer_callback(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let url = format!(
            "{}{}/answerCallbackQuery",
            self.base_url,
            self.bot_token.expose()
        );
        let payload = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text
        });

        self.http.post(&url).json(&payload).send().await?;
        Ok(())
    }
}
