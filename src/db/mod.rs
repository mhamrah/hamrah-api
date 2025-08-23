pub mod schema;
pub mod migrations;

use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, ConnectOptions};
use worker::Env;
use thiserror::Error;
use std::str::FromStr;

#[derive(Error, Debug)]
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
    pub pool: SqlitePool,
}

impl Database {
    pub async fn new(env: &Env) -> Result<Self, worker::Error> {
        // For Cloudflare D1, we'll connect using the D1 HTTP API
        // Note: This is a simplified approach - in production you might want to use D1 HTTP API directly
        let database_url = env.var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite::memory:".to_string());
            
        let options = SqliteConnectOptions::from_str(&database_url)
            .map_err(|e| worker::Error::from(format!("Invalid database URL: {}", e)))?
            .create_if_missing(true);
        
        let pool = SqlitePool::connect_with(options)
            .await
            .map_err(|e| worker::Error::from(format!("Failed to connect to database: {}", e)))?;
        
        Ok(Self { pool })
    }
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => DbError::NotFound,
            sqlx::Error::Database(db_err) => {
                if db_err.is_unique_violation() {
                    DbError::ConstraintViolation("Unique constraint violation".to_string())
                } else if db_err.is_foreign_key_violation() {
                    DbError::ConstraintViolation("Foreign key violation".to_string())
                } else {
                    DbError::OperationFailed(db_err.to_string())
                }
            }
            _ => DbError::OperationFailed(err.to_string()),
        }
    }
}