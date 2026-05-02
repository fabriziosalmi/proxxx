use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

const TG_API: &str = "https://api.telegram.org/bot";

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

#[derive(Deserialize, Debug)]
pub struct Message {
    message_id: i64,
}

#[derive(Deserialize, Debug)]
pub struct Update {
    pub update_id: i64,
    pub callback_query: Option<CallbackQuery>,
}

#[derive(Deserialize, Debug)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    pub message: Option<Message>,
    pub data: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct User {
    pub username: Option<String>,
    pub first_name: String,
}

use crate::config::TelegramConfig;

pub struct TelegramGateway {
    http: Client,
    config: TelegramConfig,
}

impl TelegramGateway {
    #[must_use]
    pub fn new(config: TelegramConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
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
        let text = format!(
            "🚨 *HITL Approval Required*\n\n*Action:* `{action}`\n*Target:* `{target}`\n*Reason:* {reason}\n*Txn:* `{txn_id}`"
        );

        let req = SendMessageReq {
            chat_id: self.config.chat_id.clone(),
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

        let url = format!("{}{}/sendMessage", TG_API, self.config.bot_token);
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

    /// Sends a simple message to the Telegram chat.
    pub async fn send_message(&self, text: &str) -> Result<()> {
        let req = serde_json::json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "MarkdownV2"
        });

        let url = format!("{}{}/sendMessage", TG_API, self.config.bot_token);
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
            TG_API, self.config.bot_token, offset, timeout
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

    /// Answer a callback query to remove the loading state on the button
    pub async fn answer_callback(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let url = format!("{}{}/answerCallbackQuery", TG_API, self.config.bot_token);
        let payload = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text
        });

        self.http.post(&url).json(&payload).send().await?;
        Ok(())
    }
}
