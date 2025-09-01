pub mod migrations;
pub mod schema;

use sqlx_d1::D1Connection;
use thiserror::Error;
use worker::{Env, Error as WorkerError};

#[derive(Error, Debug)]
#[allow(dead_code)] // Library error type - may be used by external consumers
pub enum DbError {
    #[error("Database operation failed: {0}")]
    OperationFailed(String),
    #[error("Record not found")]
    NotFound,
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
}

#[derive(Clone)]
pub struct Database {
    pub conn: D1Connection,
}

impl Database {
    pub async fn new(env: &Env) -> Result<Self, WorkerError> {
        let d1 = env.d1("DB")?;
        let conn = D1Connection::new(d1);
        Ok(Self { conn })
    }
}

// D1 error conversion for WASM
impl From<sqlx_d1::Error> for DbError {
    fn from(err: sqlx_d1::Error) -> Self {
        // Map sqlx-d1 errors to our DbError type
        DbError::OperationFailed(err.to_string())
    }
}
