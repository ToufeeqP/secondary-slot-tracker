use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde_json::{json, Value};
use subxt::utils::H256;
use tokio::{net::TcpListener, sync::RwLock};

const STALE_AFTER: Duration = Duration::from_secs(120);

#[derive(Clone, Default)]
pub struct TrackerStatus(Arc<RwLock<Option<Progress>>>);

struct Progress {
    number: u32,
    hash: H256,
    slot: u64,
    tracked_at: u64,
    updated: Instant,
}

impl TrackerStatus {
    pub async fn record(&self, number: u32, hash: H256, slot: u64) {
        *self.0.write().await = Some(Progress {
            number,
            hash,
            slot,
            tracked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            updated: Instant::now(),
        });
    }

    async fn snapshot(&self) -> (StatusCode, Json<Value>) {
        let progress = self.0.read().await;
        let (status, block) = match progress.as_ref() {
            None => ("starting", Value::Null),
            Some(p) => {
                let elapsed = p.updated.elapsed();
                (
                    if elapsed < STALE_AFTER {
                        "healthy"
                    } else {
                        "stale"
                    },
                    json!({
                        "number": p.number,
                        "hash": format!("{:#x}", p.hash),
                        "slot": p.slot,
                        "tracked_at_unix_seconds": p.tracked_at,
                        "seconds_since_last_block": elapsed.as_secs(),
                    }),
                )
            }
        };
        let code = if status == "healthy" {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (
            code,
            Json(json!({"status": status, "last_tracked_block": block})),
        )
    }
}

async fn health(State(status): State<TrackerStatus>) -> (StatusCode, Json<Value>) {
    status.snapshot().await
}

pub async fn serve(listener: TcpListener, state: TrackerStatus) -> Result<()> {
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn router(state: TrackerStatus) -> Router {
    Router::new()
        .route("/health", get(health))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercise the actual listener and JSON over HTTP while no tracker progress occurs.
    #[tokio::test]
    async fn http_server_detects_stalls_and_recovers() {
        let state = TrackerStatus::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/health", listener.local_addr().unwrap());
        let server = tokio::spawn(serve(listener, state.clone()));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 503);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["status"], "starting");
        assert!(body["last_tracked_block"].is_null());

        state.record(42, H256::repeat_byte(1), 123).await;
        // Just before the threshold, the tracker must still be healthy.
        state.0.write().await.as_mut().unwrap().updated =
            Instant::now() - (STALE_AFTER - Duration::from_secs(1));
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["last_tracked_block"]["number"], 42);
        assert!(
            body["last_tracked_block"]["tracked_at_unix_seconds"]
                .as_u64()
                .unwrap()
                > 0
        );

        // Simulate elapsed time without waiting two minutes or updating progress.
        state.0.write().await.as_mut().unwrap().updated = Instant::now() - STALE_AFTER;
        for _ in 0..3 {
            let response = client.get(&url).send().await.unwrap();
            assert_eq!(response.status().as_u16(), 503);
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["status"], "stale");
            assert_eq!(body["last_tracked_block"]["number"], 42);
            assert!(
                body["last_tracked_block"]["seconds_since_last_block"]
                    .as_u64()
                    .unwrap()
                    >= 120
            );
        }

        state.record(43, H256::repeat_byte(2), 124).await;
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["last_tracked_block"]["number"], 43);
        assert_eq!(body["last_tracked_block"]["seconds_since_last_block"], 0);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn health_route_reports_progress() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let state = TrackerStatus::default();
        for (path, expected) in [
            ("/health", StatusCode::SERVICE_UNAVAILABLE),
            ("/status", StatusCode::NOT_FOUND),
        ] {
            let response = router(state.clone())
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if path == "/status" {
                continue;
            }
            assert_eq!(response.headers()["content-type"], "application/json");
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["status"], "starting");
        }
        state.record(42, H256::zero(), 123).await;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reports_startup_progress_and_staleness() {
        let state = TrackerStatus::default();
        let (code, Json(body)) = state.snapshot().await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "starting");
        assert!(body["last_tracked_block"].is_null());

        state.record(42, H256::repeat_byte(1), 123).await;
        let (code, Json(body)) = state.snapshot().await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["last_tracked_block"]["number"], 42);
        assert_eq!(body["last_tracked_block"]["slot"], 123);
        assert_eq!(
            body["last_tracked_block"]["hash"],
            format!("{:#x}", H256::repeat_byte(1))
        );

        state.0.write().await.as_mut().unwrap().updated = Instant::now() - STALE_AFTER;
        let (code, Json(body)) = state.snapshot().await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "stale");
        assert_eq!(body["last_tracked_block"]["number"], 42);
    }
}
