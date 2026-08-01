//! Optional Tier-2 history exporter status and absence-tolerant worker.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::State;
use axum::Json;
use fabric_history::{
    ExportSource, HistoryConfig, HistoryDsn, HistoryError, HistoryExporter, HistoryMode,
    HistoryRecord, PostgresHistoryTarget,
};
use fabric_store::FabricStore;
use serde_json::{json, Value};

use crate::state::HubState;
use crate::utils::utc_now;

owned_router! {
    pub fn router, ROUTES {
        "GET" get "/history/status" => get_history_status;
    }
}

pub async fn get_history_status(State(state): State<Arc<HubState>>) -> Json<Value> {
    Json(state.history_status.lock().await.clone())
}

#[derive(Clone)]
struct HubHistorySource {
    store: Arc<dyn FabricStore>,
}

#[async_trait]
impl ExportSource for HubHistorySource {
    async fn streams(&self) -> Result<Vec<String>, HistoryError> {
        self.store
            .history_streams()
            .await
            .map_err(|_| HistoryError::Source("Tier-1 stream discovery failed".into()))
    }

    async fn fetch_after(
        &self,
        stream: &str,
        sequence: i64,
        limit: usize,
    ) -> Result<Vec<HistoryRecord>, HistoryError> {
        let durable = self
            .store
            .history_watermark(stream)
            .await
            .map_err(|_| HistoryError::Source("Tier-1 watermark read failed".into()))?;
        self.store
            .fetch_history_rows(stream, sequence.max(durable), limit)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| HistoryRecord {
                        stream: row.stream,
                        sequence: row.sequence,
                        record_id: row.record_id,
                        occurred_at_ms: row.occurred_at_ms,
                        payload: row.payload,
                    })
                    .collect()
            })
            .map_err(|_| HistoryError::Source("Tier-1 history read failed".into()))
    }

    async fn commit_watermark(&self, stream: &str, sequence: i64) -> Result<(), HistoryError> {
        self.store
            .commit_history_watermark(stream, sequence, &utc_now())
            .await
            .map_err(|_| HistoryError::Source("Tier-1 watermark commit failed".into()))
    }
}

pub fn spawn_export_loop(state: Arc<HubState>) {
    tokio::spawn(async move {
        loop {
            let retry_seconds = export_once(&state).await;
            tokio::time::sleep(Duration::from_secs(retry_seconds.clamp(1, 3600))).await;
        }
    });
}

async fn export_once(state: &Arc<HubState>) -> u64 {
    let Ok(document) = state.store.get_settings_document().await else {
        set_status(
            state,
            json!({"health":"degraded","mode":"unknown","last_error":"settings read failed"}),
        )
        .await;
        return 30;
    };
    let Ok(snapshot) =
        fabric_settings::SettingsSnapshot::new(document.revision, document.value, json!({}))
    else {
        set_status(
            state,
            json!({"health":"degraded","mode":"unknown","last_error":"settings validation failed"}),
        )
        .await;
        return 30;
    };
    let history = &snapshot.effective["history"];
    let mode = match history["mode"].as_str().unwrap_or("thin") {
        "external" => HistoryMode::External,
        "fabric-managed" => HistoryMode::FabricManaged,
        _ => HistoryMode::Thin,
    };
    let dsn = history["external_db"]["dsn"]
        .as_str()
        .map(str::to_owned)
        .and_then(|value| HistoryDsn::new(value).ok());
    let autodetect = history["external_db"]["autodetect"]
        .as_bool()
        .unwrap_or(false);
    let provision = history["external_db"]["provision"]
        .as_bool()
        .unwrap_or(false);
    let retry = history["external_db"]["retry_seconds"]
        .as_u64()
        .unwrap_or(30);
    let config = HistoryConfig {
        mode,
        dsn: dsn.clone(),
        autodetect,
        provision,
    };
    if let Err(error) = config.validate() {
        set_status(
            state,
            json!({"health":"degraded","mode": mode, "last_error": error.to_string()}),
        )
        .await;
        return retry;
    }

    let source = HubHistorySource {
        store: Arc::clone(&state.store),
    };
    let target = dsn.map(PostgresHistoryTarget::new);
    let mut exporter = HistoryExporter::new(source, target);
    let status = exporter.tick().await;
    let mut value = serde_json::to_value(status).unwrap_or_else(
        |_| json!({"health":"degraded","last_error":"status serialization failed"}),
    );
    value["mode"] = json!(mode);
    value["settings_revision"] = json!(document.revision);
    set_status(state, value).await;
    retry
}

async fn set_status(state: &HubState, value: Value) {
    *state.history_status.lock().await = value;
}
