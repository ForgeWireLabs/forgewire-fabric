//! ForgeWire Fabric native hub daemon.
//!
//! Axum HTTP server implementing v2 API parity with the Python FastAPI hub.
//! Routes map 1:1 to the ENDPOINT_AUTH_MATRIX.md surface.

#![deny(rust_2018_idioms)]

pub mod auth;
pub mod routes;
pub mod state;
pub mod utils;
