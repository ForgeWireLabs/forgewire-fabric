//! Optional Tier-2 history export. This crate must never participate in
//! Tier-1 dispatch, consensus, or availability decisions.

use async_trait::async_trait;
use postgres_native_tls::MakeTlsConnector;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HistoryMode {
    Thin,
    External,
    FabricManaged,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HistoryDsn(String);

impl HistoryDsn {
    pub fn new(value: impl Into<String>) -> Result<Self, HistoryError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(HistoryError::Configuration("history DSN is empty".into()));
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HistoryDsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoryDsn([REDACTED])")
    }
}
impl Serialize for HistoryDsn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryConfig {
    pub mode: HistoryMode,
    pub dsn: Option<HistoryDsn>,
    pub autodetect: bool,
    pub provision: bool,
}

impl HistoryConfig {
    pub fn validate(&self) -> Result<(), HistoryError> {
        match self.mode {
            HistoryMode::Thin if self.dsn.is_some() => Err(HistoryError::Configuration(
                "thin mode must not use a DSN".into(),
            )),
            HistoryMode::External if self.dsn.is_none() => Err(HistoryError::Configuration(
                "external mode requires an operator DSN".into(),
            )),
            HistoryMode::FabricManaged if !self.provision => Err(HistoryError::Configuration(
                "fabric-managed mode requires explicit provision=true".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryRecord {
    pub stream: String,
    pub sequence: i64,
    pub record_id: String,
    pub occurred_at_ms: i64,
    pub payload: Value,
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("configuration: {0}")]
    Configuration(String),
    #[error("source: {0}")]
    Source(String),
    #[error("target: {0}")]
    Target(String),
}

#[async_trait]
pub trait ExportSource: Send + Sync {
    async fn streams(&self) -> Result<Vec<String>, HistoryError>;
    async fn fetch_after(
        &self,
        stream: &str,
        sequence: i64,
        limit: usize,
    ) -> Result<Vec<HistoryRecord>, HistoryError>;
    async fn commit_watermark(&self, stream: &str, sequence: i64) -> Result<(), HistoryError>;
}

#[async_trait]
pub trait HistoryTarget: Send + Sync {
    async fn ensure_schema(&self) -> Result<(), HistoryError>;
    async fn upsert(&self, records: &[HistoryRecord]) -> Result<(), HistoryError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportHealth {
    Disabled,
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportStatus {
    pub health: ExportHealth,
    pub exported: usize,
    pub watermarks: BTreeMap<String, i64>,
    pub retry_after_ms: Option<u64>,
    pub last_error: Option<String>,
}

pub struct HistoryExporter<S, T> {
    source: S,
    target: Option<T>,
    watermarks: BTreeMap<String, i64>,
    batch: usize,
    retry: Duration,
}

impl<S: ExportSource, T: HistoryTarget> HistoryExporter<S, T> {
    pub fn new(source: S, target: Option<T>) -> Self {
        Self {
            source,
            target,
            watermarks: BTreeMap::new(),
            batch: 500,
            retry: Duration::from_secs(30),
        }
    }
    /// Never returns an error: Tier-2 failure is reported as degraded status.
    pub async fn tick(&mut self) -> ExportStatus {
        let Some(target) = &self.target else {
            return self.status(ExportHealth::Disabled, 0, None);
        };
        if let Err(error) = target.ensure_schema().await {
            return self.status(ExportHealth::Degraded, 0, Some(error.to_string()));
        }
        let streams = match self.source.streams().await {
            Ok(v) => v,
            Err(e) => return self.status(ExportHealth::Degraded, 0, Some(e.to_string())),
        };
        let mut exported = 0;
        for stream in streams {
            let after = *self.watermarks.get(&stream).unwrap_or(&0);
            let records = match self.source.fetch_after(&stream, after, self.batch).await {
                Ok(v) => v,
                Err(e) => {
                    return self.status(ExportHealth::Degraded, exported, Some(e.to_string()))
                }
            };
            if records.is_empty() {
                continue;
            }
            if let Err(error) = target.upsert(&records).await {
                return self.status(ExportHealth::Degraded, exported, Some(error.to_string()));
            }
            let watermark = records.iter().map(|r| r.sequence).max().unwrap_or(after);
            if self
                .source
                .commit_watermark(&stream, watermark)
                .await
                .is_err()
            {
                return self.status(
                    ExportHealth::Degraded,
                    exported,
                    Some("source watermark commit failed".into()),
                );
            }
            self.watermarks.insert(stream, watermark.max(after));
            exported += records.len();
        }
        self.status(ExportHealth::Healthy, exported, None)
    }
    fn status(&self, health: ExportHealth, exported: usize, error: Option<String>) -> ExportStatus {
        ExportStatus {
            retry_after_ms: (health == ExportHealth::Degraded)
                .then_some(self.retry.as_millis() as u64),
            health,
            exported,
            watermarks: self.watermarks.clone(),
            last_error: error,
        }
    }
}

pub struct PostgresHistoryTarget {
    dsn: HistoryDsn,
}
impl PostgresHistoryTarget {
    pub fn new(dsn: HistoryDsn) -> Self {
        Self { dsn }
    }
}

fn tls_connector(dsn: &HistoryDsn) -> Result<MakeTlsConnector, HistoryError> {
    if !dsn
        .expose()
        .to_ascii_lowercase()
        .contains("sslmode=require")
    {
        return Err(HistoryError::Configuration(
            "history DSN must explicitly set sslmode=require".into(),
        ));
    }
    native_tls::TlsConnector::builder()
        .build()
        .map(MakeTlsConnector::new)
        .map_err(|_| HistoryError::Target("TLS initialization failed".into()))
}

#[async_trait]
impl HistoryTarget for PostgresHistoryTarget {
    async fn ensure_schema(&self) -> Result<(), HistoryError> {
        let (client, connection) =
            tokio_postgres::connect(self.dsn.expose(), tls_connector(&self.dsn)?)
                .await
                .map_err(|_| HistoryError::Target("PostgreSQL TLS connection failed".into()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client.batch_execute("CREATE TABLE IF NOT EXISTS fabric_history (stream TEXT NOT NULL, sequence BIGINT NOT NULL, record_id TEXT NOT NULL, occurred_at_ms BIGINT NOT NULL, payload JSONB NOT NULL, PRIMARY KEY(stream, sequence), UNIQUE(stream, record_id)); CREATE OR REPLACE VIEW task_history AS SELECT * FROM fabric_history WHERE stream='tasks'; CREATE OR REPLACE VIEW cost_events AS SELECT * FROM fabric_history WHERE stream='cost'; CREATE OR REPLACE VIEW audit_events_archive AS SELECT * FROM fabric_history WHERE stream='audit';").await.map_err(|_| HistoryError::Target("history schema initialization failed".into()))
    }
    async fn upsert(&self, records: &[HistoryRecord]) -> Result<(), HistoryError> {
        let (mut client, connection) =
            tokio_postgres::connect(self.dsn.expose(), tls_connector(&self.dsn)?)
                .await
                .map_err(|_| HistoryError::Target("PostgreSQL TLS connection failed".into()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let tx = client
            .transaction()
            .await
            .map_err(|_| HistoryError::Target("history transaction start failed".into()))?;
        for r in records {
            tx.execute("INSERT INTO fabric_history(stream,sequence,record_id,occurred_at_ms,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(stream,sequence) DO UPDATE SET record_id=EXCLUDED.record_id,occurred_at_ms=EXCLUDED.occurred_at_ms,payload=EXCLUDED.payload", &[&r.stream,&r.sequence,&r.record_id,&r.occurred_at_ms,&r.payload]).await.map_err(|_| HistoryError::Target("history record upsert failed".into()))?;
        }
        tx.commit()
            .await
            .map_err(|_| HistoryError::Target("history transaction commit failed".into()))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateProbe {
    pub address: SocketAddr,
    pub reachable: bool,
}

/// Observational only: opens a TCP socket and sends no authentication or query bytes.
pub async fn probe_candidates(candidates: &[SocketAddr], timeout: Duration) -> Vec<CandidateProbe> {
    let mut result = Vec::with_capacity(candidates.len());
    for address in candidates {
        let reachable = tokio::time::timeout(timeout, TcpStream::connect(address))
            .await
            .is_ok_and(|r| r.is_ok());
        result.push(CandidateProbe {
            address: *address,
            reachable,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    struct Source(Vec<HistoryRecord>);
    #[async_trait]
    impl ExportSource for Source {
        async fn streams(&self) -> Result<Vec<String>, HistoryError> {
            Ok(vec!["audit".into()])
        }
        async fn fetch_after(
            &self,
            _: &str,
            seq: i64,
            _: usize,
        ) -> Result<Vec<HistoryRecord>, HistoryError> {
            Ok(self
                .0
                .iter()
                .filter(|r| r.sequence > seq)
                .cloned()
                .collect())
        }
        async fn commit_watermark(&self, _: &str, _: i64) -> Result<(), HistoryError> {
            Ok(())
        }
    }
    #[derive(Clone)]
    struct Target {
        rows: Arc<Mutex<Vec<HistoryRecord>>>,
        fail: bool,
    }
    #[async_trait]
    impl HistoryTarget for Target {
        async fn ensure_schema(&self) -> Result<(), HistoryError> {
            Ok(())
        }
        async fn upsert(&self, records: &[HistoryRecord]) -> Result<(), HistoryError> {
            if self.fail {
                return Err(HistoryError::Target("offline".into()));
            }
            let mut rows = self.rows.lock().unwrap();
            for r in records {
                if !rows
                    .iter()
                    .any(|x| x.stream == r.stream && x.sequence == r.sequence)
                {
                    rows.push(r.clone());
                }
            }
            Ok(())
        }
    }
    fn record(seq: i64) -> HistoryRecord {
        HistoryRecord {
            stream: "audit".into(),
            sequence: seq,
            record_id: format!("r{seq}"),
            occurred_at_ms: seq,
            payload: serde_json::json!({"seq":seq}),
        }
    }
    #[test]
    fn dsn_never_serializes_or_debugs_value() {
        let d = HistoryDsn::new("postgres://user:secret@host/db").unwrap();
        assert!(!format!("{d:?}").contains("secret"));
        assert_eq!(serde_json::to_string(&d).unwrap(), "\"[REDACTED]\"");
    }
    #[tokio::test]
    async fn absent_target_is_thin_history_not_failure() {
        let mut e: HistoryExporter<_, Target> = HistoryExporter::new(Source(vec![record(1)]), None);
        assert_eq!(e.tick().await.health, ExportHealth::Disabled);
    }
    #[tokio::test]
    async fn watermark_is_monotonic_and_upsert_idempotent() {
        let rows = Arc::new(Mutex::new(vec![]));
        let t = Target {
            rows: rows.clone(),
            fail: false,
        };
        let mut e = HistoryExporter::new(Source(vec![record(1), record(2)]), Some(t));
        assert_eq!(e.tick().await.exported, 2);
        assert_eq!(e.tick().await.exported, 0);
        assert_eq!(e.watermarks["audit"], 2);
        assert_eq!(rows.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn target_failure_degrades_without_error_return() {
        let t = Target {
            rows: Arc::new(Mutex::new(vec![])),
            fail: true,
        };
        let mut e = HistoryExporter::new(Source(vec![record(1)]), Some(t));
        let s = e.tick().await;
        assert_eq!(s.health, ExportHealth::Degraded);
        assert!(s.retry_after_ms.is_some());
    }
    #[tokio::test]
    async fn optional_real_postgres_smoke() {
        let Ok(raw) = std::env::var("FORGEWIRE_HISTORY_TEST_DSN") else {
            return;
        };
        let target = PostgresHistoryTarget::new(HistoryDsn::new(raw).unwrap());
        target.ensure_schema().await.unwrap();
        target.upsert(&[record(9_999_991)]).await.unwrap();
    }
}
