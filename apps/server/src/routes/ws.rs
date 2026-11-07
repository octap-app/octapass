//! `GET /v1/ws`: live change notifications. The server says which vault
//! changed and its new revision, never what changed; clients then sync.
//!
//! Browsers can't set headers on a WebSocket, so the access token comes in
//! the first message instead of `Authorization`. That also means the
//! connection is only as good as that token: it closes when the token
//! expires unless the client sends a fresh one.

use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use octapass_api::problem::Problem;
use octapass_api::{ClientMessage, ServerMessage, WS_CLOSE_PROTOCOL, WS_CLOSE_UNAUTHORIZED};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, sleep_until, timeout};

use crate::db::{self, items, sessions::Session};
use crate::error::{ApiError, ApiResult};
use crate::events::Event;
use crate::extract::session_for;
use crate::state::AppState;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Client messages are small JSON objects holding at most a token.
const MAX_MESSAGE: usize = 4096;
const CLOSE_INTERNAL: u16 = 1011;

#[utoipa::path(
    get, path = "/v1/ws", tag = "sync",
    responses(
        (status = 101, description = "WebSocket. Send `ClientMessage` auth first; the server sends `ServerMessage`s. \
            Closes with 4401 when the connection isn't authenticated, 4400 on a protocol error."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Not a WebSocket upgrade"),
    )
)]
pub async fn ws(
    State(state): State<AppState>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> ApiResult<Response> {
    let upgrade = upgrade.map_err(|rejection| ApiError::BadRequest(rejection.body_text()))?;
    Ok(upgrade
        .max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| Connection::run(state, socket)))
}

struct Connection {
    state: AppState,
    socket: WebSocket,
    session: Session,
    expires: Instant,
}

/// Why the server ends a connection.
enum Close {
    /// The peer left, or the socket broke. Nothing more to send.
    Gone,
    Unauthorized(&'static str),
    Protocol(&'static str),
    Internal,
}

impl Connection {
    async fn run(state: AppState, mut socket: WebSocket) {
        let first = match timeout(AUTH_TIMEOUT, socket.recv()).await {
            Ok(Some(Ok(message))) => message,
            Ok(_) => return,
            Err(_) => return close(&mut socket, Close::Unauthorized("no auth message")).await,
        };
        let session = match authenticate(&state, &mut socket, first).await {
            Ok(session) => session,
            Err(reason) => return close(&mut socket, reason).await,
        };
        let mut connection = Self {
            expires: expiry(&session),
            state,
            socket,
            session,
        };
        let reason = connection.serve().await;
        close(&mut connection.socket, reason).await;
    }

    async fn serve(&mut self) -> Close {
        // Subscribe before confirming, so nothing after "authenticated" is missed.
        let mut events = self.state.events.subscribe(&self.session.account_id);
        if let Err(reason) = self.authenticated().await {
            return reason;
        }
        let period = self.state.config.ws_heartbeat;
        let mut heartbeat = tokio::time::interval_at(Instant::now() + period, period);
        let mut awaiting_pong = false;
        loop {
            let result = tokio::select! {
                message = self.socket.recv() => {
                    awaiting_pong = false;
                    match message {
                        Some(Ok(message)) => self.on_message(message).await,
                        Some(Err(_)) | None => Err(Close::Gone),
                    }
                }
                event = events.recv() => self.on_event(event).await,
                _ = heartbeat.tick() => {
                    if awaiting_pong {
                        Err(Close::Gone)
                    } else {
                        awaiting_pong = true;
                        self.send(Message::Ping(Default::default())).await
                    }
                }
                () = sleep_until(self.expires) => Err(Close::Unauthorized("access token expired")),
            };
            if let Err(reason) = result {
                return reason;
            }
        }
    }

    async fn on_message(&mut self, message: Message) -> Result<(), Close> {
        match message {
            // Pings are answered by the WebSocket layer; any frame proves liveness.
            Message::Ping(_) | Message::Pong(_) => Ok(()),
            Message::Close(_) => Err(Close::Gone),
            message => {
                let session = authenticate(&self.state, &mut self.socket, message).await?;
                if session.device_id != self.session.device_id {
                    return Err(Close::Protocol("auth must be for the same device"));
                }
                self.expires = expiry(&session);
                self.session = session;
                self.authenticated().await
            }
        }
    }

    async fn on_event(&mut self, event: Result<Event, RecvError>) -> Result<(), Close> {
        match event {
            Ok(Event::VaultChanged { vault_id, revision }) => {
                self.send_json(&ServerMessage::VaultChanged { vault_id, revision })
                    .await
            }
            Ok(Event::MembershipChanged { vault_id }) => {
                self.send_json(&ServerMessage::MembershipChanged { vault_id })
                    .await
            }
            Ok(Event::SessionRevoked { device_id }) if device_id == self.session.device_id => {
                self.send_json(&ServerMessage::SessionRevoked).await?;
                Err(Close::Unauthorized("session revoked"))
            }
            Ok(Event::SessionRevoked { .. }) => Ok(()),
            Ok(Event::AccountDeleted) => {
                self.send_json(&ServerMessage::AccountDeleted).await?;
                Err(Close::Unauthorized("account deleted"))
            }
            // Too far behind to know what changed: report every vault.
            Err(RecvError::Lagged(_)) => {
                let vaults = items::revisions(&self.state.db, &self.session.account_id)
                    .await
                    .map_err(|_| Close::Internal)?;
                for (vault_id, revision) in vaults {
                    self.send_json(&ServerMessage::VaultChanged { vault_id, revision })
                        .await?;
                }
                Ok(())
            }
            Err(RecvError::Closed) => Err(Close::Internal),
        }
    }

    async fn authenticated(&mut self) -> Result<(), Close> {
        let expires_in = self
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs();
        self.send_json(&ServerMessage::Authenticated { expires_in })
            .await
    }

    async fn send_json(&mut self, message: &ServerMessage) -> Result<(), Close> {
        let json = serde_json::to_string(message).expect("server messages serialise");
        self.send(Message::Text(json.into())).await
    }

    async fn send(&mut self, message: Message) -> Result<(), Close> {
        self.socket.send(message).await.map_err(|_| Close::Gone)
    }
}

/// Checks an `auth` message. Tokens of a deleted account are told so before
/// the connection closes.
async fn authenticate(
    state: &AppState,
    socket: &mut WebSocket,
    message: Message,
) -> Result<Session, Close> {
    let Message::Text(text) = message else {
        return Err(Close::Protocol("expected a text message"));
    };
    let Ok(ClientMessage::Auth { access_token }) = serde_json::from_str(&text) else {
        return Err(Close::Protocol("expected an auth message"));
    };
    match session_for(state, &access_token).await {
        Ok(session) => {
            db::sessions::touch_device(&state.db, &session.device_id, db::now())
                .await
                .map_err(|_| Close::Internal)?;
            Ok(session)
        }
        Err(ApiError::AccountDeleted) => {
            let json = serde_json::to_string(&ServerMessage::AccountDeleted)
                .expect("server messages serialise");
            socket
                .send(Message::Text(json.into()))
                .await
                .map_err(|_| Close::Gone)?;
            Err(Close::Unauthorized("account deleted"))
        }
        Err(ApiError::Unauthorized) => Err(Close::Unauthorized("invalid access token")),
        Err(_) => Err(Close::Internal),
    }
}

fn expiry(session: &Session) -> Instant {
    let remaining = u64::try_from(session.access_expires_at - db::now()).unwrap_or(0);
    Instant::now() + Duration::from_millis(remaining)
}

async fn close(socket: &mut WebSocket, reason: Close) {
    let (code, reason) = match reason {
        Close::Gone => return,
        Close::Unauthorized(reason) => (WS_CLOSE_UNAUTHORIZED, reason),
        Close::Protocol(reason) => (WS_CLOSE_PROTOCOL, reason),
        Close::Internal => (CLOSE_INTERNAL, "internal error"),
    };
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
}
