use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

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
    /// Pre-resolved bot token. Held as a plain `String` because reqwest
    /// borrows the URL multiple times per request and `Zeroizing<String>`
    /// would force `Deref` calls on every send. The caller's
    /// `Zeroizing` wrapper (config layer) covers the credential lifetime
    /// up to construction; once inside the gateway the token lives as
    /// long as the gateway itself.
    bot_token: String,
    chat_id: String,
    /// Telegram Bot API base, e.g. `"https://api.telegram.org/bot"`.
    /// MUST end without a trailing slash and without the token —
    /// the per-request URL is built as `{base}{token}/{method}`.
    base_url: String,
}

impl TelegramGateway {
    /// Production constructor — uses the public Telegram API endpoint.
    /// `bot_token` must be the resolved token (caller is responsible
    /// for going through `TelegramConfig::resolve_bot_token`).
    #[must_use]
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            http: Client::new(),
            bot_token,
            chat_id,
            base_url: DEFAULT_TG_API.to_string(),
        }
    }

    /// Test constructor — point at a wiremock `MockServer::uri()` so the
    /// gateway hits the local fixture instead of api.telegram.org.
    /// The `base_url` should be the full URL up to (but not including)
    /// the bot token segment — typically `format!("{}/bot", server.uri())`.
    #[must_use]
    pub fn with_base_url(bot_token: String, chat_id: String, base_url: String) -> Self {
        Self {
            http: Client::new(),
            bot_token,
            chat_id,
            base_url,
        }
    }

    /// High-level convenience: resolve the bot token via the configured
    /// hierarchy (env / file / inline / keychain) and build the gateway.
    /// Use this from production call sites; tests should prefer
    /// `with_base_url()` and pass an explicit fake token.
    pub async fn from_config(config: &crate::config::TelegramConfig) -> Result<Self> {
        let token = config.resolve_bot_token().await?;
        Ok(Self::new(token.to_string(), config.chat_id.clone()))
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

        let req = SendMessageReq {
            chat_id: self.chat_id.clone(),
            text,
            parse_mode: "MarkdownV2".to_string(),
            reply_markup: InlineKeyboardMarkup {
                inline_keyboard: vec![vec![
                    InlineKeyboardButton {
                        text: "✅ Approve".to_string(),
                        callback_data: format!("approve:{txn_id}"),
                    },
                    InlineKeyboardButton {
                        text: "❌ Deny".to_string(),
                        callback_data: format!("deny:{txn_id}"),
                    },
                ]],
            },
        };

        let url = format!("{}{}/sendMessage", self.base_url, self.bot_token);
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

        let url = format!("{}{}/sendMessage", self.base_url, self.bot_token);
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
            self.base_url, self.bot_token, offset, timeout
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
        let url = format!("{}{}/editMessageText", self.base_url, self.bot_token);
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
        let url = format!("{}{}/answerCallbackQuery", self.base_url, self.bot_token);
        let payload = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text
        });

        self.http.post(&url).json(&payload).send().await?;
        Ok(())
    }
}
