//! Dienstmotor: mandatory operator authorization for new connections.
//!
//! Every PunchHoleRequest / RequestRelay must carry, in its `token` field, a connection
//! ticket issued by the Dienstmotor auth API after an Authentik login. hbbs asks the auth
//! API (`POST {DM_AUTH_URL}`) to verify it before forwarding anything to the target peer.
//! Any failure (no ticket, rejected ticket, timeout, service down, not configured) denies
//! the request. Established sessions never pass through here again.

use crate::common::get_arg;
use hbb_common::log;
use once_cell::sync::Lazy;
use std::{net::SocketAddr, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(3);
pub const MSG_LOGIN_REQUIRED: &str = "Dienstmotor: sign in to start a connection";
pub const MSG_UNAVAILABLE: &str = "Dienstmotor: authorization service unavailable, try again later";

static CONFIG: Lazy<(String, String)> = Lazy::new(|| {
    let url = get_arg("DM_AUTH_URL");
    let token = get_arg("DM_AUTH_TOKEN");
    if url.is_empty() || token.is_empty() {
        log::error!("DM_AUTH_URL / DM_AUTH_TOKEN not set: every new connection will be refused");
    }
    (url, token)
});

static CLIENT: Lazy<Option<reqwest::Client>> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| log::error!("dm_auth http client: {e}"))
        .ok()
});

/// Returns `Err(message for the operator)` unless the auth API accepts `ticket` for a
/// connection from `addr` to `peer_id`.
pub async fn authorize(ticket: &str, peer_id: &str, addr: SocketAddr, kind: &str) -> Result<(), String> {
    if ticket.is_empty() {
        log::info!("dm_auth: {kind} to {peer_id} from {addr} denied: no ticket");
        return Err(MSG_LOGIN_REQUIRED.to_owned());
    }
    let (url, token) = &*CONFIG;
    authorize_with(url, token, ticket, peer_id, addr, kind).await
}

async fn authorize_with(
    url: &str,
    token: &str,
    ticket: &str,
    peer_id: &str,
    addr: SocketAddr,
    kind: &str,
) -> Result<(), String> {
    let Some(client) = CLIENT.as_ref().filter(|_| !url.is_empty() && !token.is_empty()) else {
        return Err(MSG_UNAVAILABLE.to_owned());
    };
    let ip = hbb_common::try_into_v4(addr).ip().to_string();
    let body = serde_json::json!({
        "ticket": ticket,
        "peer_id": peer_id,
        "source_ip": ip,
        "kind": kind,
    });
    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .and_then(|r| r.error_for_status());
    let value: serde_json::Value = match resp {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("dm_auth: bad response from auth API: {e}");
                return Err(MSG_UNAVAILABLE.to_owned());
            }
        },
        Err(e) => {
            log::warn!("dm_auth: auth API request failed: {e}");
            return Err(MSG_UNAVAILABLE.to_owned());
        }
    };
    if value.get("allowed").and_then(|v| v.as_bool()) == Some(true) {
        log::info!("dm_auth: {kind} to {peer_id} from {addr} allowed");
        return Ok(());
    }
    let reason = value.get("reason").and_then(|v| v.as_str()).unwrap_or("denied");
    log::info!("dm_auth: {kind} to {peer_id} from {addr} denied: {reason}");
    Err(format!("Dienstmotor: authorization rejected ({reason}), sign in again"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn fake_api(status: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        format!("http://{addr}/internal/authorize")
    }

    fn from() -> SocketAddr {
        "198.51.100.7:40000".parse().unwrap()
    }

    #[tokio::test]
    async fn missing_ticket_is_refused() {
        assert_eq!(
            authorize("", "123456789", from(), "punch").await,
            Err(MSG_LOGIN_REQUIRED.to_owned())
        );
    }

    #[tokio::test]
    async fn accepted_ticket_is_allowed() {
        let url = fake_api("200 OK", r#"{"allowed":true,"reason":""}"#).await;
        assert!(authorize_with(&url, "t", "dm1.a.b", "123456789", from(), "punch").await.is_ok());
    }

    #[tokio::test]
    async fn rejected_ticket_is_refused() {
        let url = fake_api("200 OK", r#"{"allowed":false,"reason":"ticket replay"}"#).await;
        let err = authorize_with(&url, "t", "dm1.a.b", "123456789", from(), "relay").await.unwrap_err();
        assert!(err.contains("ticket replay"));
    }

    #[tokio::test]
    async fn unreachable_or_failing_service_fails_closed() {
        let url = fake_api("500 Internal Server Error", r#"{"allowed":true}"#).await;
        assert_eq!(
            authorize_with(&url, "t", "dm1.a.b", "123456789", from(), "punch").await,
            Err(MSG_UNAVAILABLE.to_owned())
        );
        assert_eq!(
            authorize_with("http://127.0.0.1:9/x", "t", "dm1.a.b", "123456789", from(), "punch").await,
            Err(MSG_UNAVAILABLE.to_owned())
        );
        assert_eq!(
            authorize_with("", "", "dm1.a.b", "123456789", from(), "punch").await,
            Err(MSG_UNAVAILABLE.to_owned())
        );
    }
}
