//! Shared Send + Sync facades for Env/DB with a serial executor API.
//!
//! Why this exists
//! ---------------
//! Axum handlers require their returned futures to be `Send`. Cloudflare Workers
//! (WASM) Env/D1 connection objects are not `Send`/`Sync`, which means any handler
//! that directly holds them across `.await` points will fail the `Handler` bound.
//!
//! The pattern here is to:
//! - Expose tiny, `Send + Sync` "handles" (`SharedHandles`) that can be stored on the
//!   Axum router and passed around freely.
//! - Keep all access to non-Send state (Env, Database) out of handlers.
//! - Route all DB/Env work through a single-threaded executor facade so the handler
//!   async future only ever awaits on Send-safe "tickets"/"receivers", rather than
//!   capturing non-Send state itself.
//!
//! This file provides the public façade types and an executor interface that is
//! `Send + Sync` from the handler's perspective. The concrete single-threaded
//! executor wiring (that actually owns the non-Send Env/DB and runs jobs) can be
//! added next and plugged into these handles without changing handler signatures.
//!
//! Usage (intended):
//! -----------------
//! - Create the concrete single-threaded executor at startup with ownership of
//!   Database and Env (both non-Send).
//! - Build `SharedHandles` with `DbHandle::new(executor.clone())` and
//!   `EnvHandle::new(executor.clone(), "PIPELINE_SERVICE".into())`.
//! - Mount `SharedHandles` as Axum state (or an Extension), not the raw Env/DB.
//! - In handlers, call `handles.db.run(|mut db| async move { /* d1 queries with db */ })`
//!   or `handles.env.run(|env| async move { /* service binding calls with env */ })`.
//!
//! The key point is the handler only holds `Arc<...>` to these handles (Send + Sync).
//! The non-Send Database/Env are hidden behind the executor and never cross `.await`.

use crate::single_thread_executor::LocalSingleThreadExecutor;

use std::fmt;
use std::future::Future;
use std::sync::Arc;

/// A Send + Sync ticket returned by the executor APIs so handlers can `await`
/// results without holding non-Send state.
///
/// This is deliberately opaque; only the executor will produce these.
pub struct Ticket<T> {
    /// Placeholder so this type is `Send + Sync` without bringing non-Send state
    /// into handler futures. The real executor will return a concrete impl Future
    /// that is `Send`, but we keep the API surface stable by wrapping it.
    ///
    /// For now we just box an async fn pointer returning the value immediately.
    /// This allows the API to compile before the real executor is wired up.
    inner: Box<dyn Future<Output = T> + Send + 'static>,
}

impl<T> Ticket<T> {
    pub fn new<F>(fut: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        Self {
            inner: Box::new(fut),
        }
    }
}

impl<T> Future for Ticket<T> {
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Safety: `inner` is a boxed future; projecting a pin into it is safe.
        let fut = unsafe { std::pin::Pin::new_unchecked(&mut *self.inner) };
        fut.poll(cx)
    }
}

/// Public, Send + Sync façade for DB work.
///
/// Handlers only know about this type and its `run` method, which returns a
/// Send-safe `Ticket<T>` so the handler future itself remains `Send`.
#[derive(Clone)]
pub struct DbHandle {
    exec: Arc<LocalSingleThreadExecutor>,
}

impl fmt::Debug for DbHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbHandle").finish()
    }
}

impl DbHandle {
    pub fn new(exec: Arc<LocalSingleThreadExecutor>) -> Self {
        Self { exec }
    }

    /// Run a DB operation on the single-threaded executor that owns the non-Send
    /// `Database`. The provided closure must not capture non-Send references; all
    /// non-Send access happens through the provided `db` argument inside the executor.
    ///
    /// Example (once executor is wired):
    ///   let row = handles.db
    ///       .run(|mut db| async move {
    ///           sqlx_d1::query_as::<MyRow>("SELECT * FROM links WHERE id = ?")
    ///               .bind(id)
    ///               .fetch_one(&mut db.conn)
    ///               .await
    ///       })
    ///       .await?;
    pub fn run<F, Fut, T>(&self, f: F) -> Ticket<T>
    where
        F: FnOnce(crate::db::Database) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        self.exec.run_db(f)
    }
}

/// Public, Send + Sync façade for Env work (service bindings, secrets lookup, etc.)
///
/// Do not capture and hold Env across `.await` in handlers. Route via `run`.
#[derive(Clone)]
pub struct EnvHandle {
    exec: Arc<LocalSingleThreadExecutor>,
    /// Provide only the bits handlers actually need in Send + Sync form.
    /// For example, a service binding's configured name.
    pipeline_service_binding: Arc<String>,
}

impl fmt::Debug for EnvHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvHandle")
            .field("pipeline_service_binding", &self.pipeline_service_binding)
            .finish()
    }
}

impl EnvHandle {
    pub fn new(exec: Arc<LocalSingleThreadExecutor>, pipeline_service_binding: String) -> Self {
        Self {
            exec,
            pipeline_service_binding: Arc::new(pipeline_service_binding),
        }
    }

    /// Access to the configured pipeline service binding name (pure, Send + Sync).
    pub fn pipeline_service_name(&self) -> &str {
        &self.pipeline_service_binding
    }

    /// Run an Env operation on the single-threaded executor that owns the non-Send
    /// `worker::Env`. The closure gets an owned `worker::Env` and must return a future.
    ///
    /// Example (once executor is wired):
    ///   handles.env
    ///       .run(|env| async move {
    ///           // call service binding
    ///           let fetcher = env.service("PIPELINE_SERVICE")?;
    ///           // ...
    ///           Ok(())
    ///       })
    ///       .await?;
    pub fn run<F, Fut, T, E>(&self, f: F) -> Ticket<Result<T, E>>
    where
        F: FnOnce(worker::Env) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        self.exec.run_env(f)
    }
}

/// A Send + Sync bundle for Axum state/extension usage.
/// Keep this in the router. Never keep non-Send types in here.
///
/// Typical construction flow (to be wired at startup):
///   let exec = Arc::new(YourConcreteSingleThreadExecutor::new(db, env));
///   let handles = SharedHandles::new(
///       DbHandle::new(exec.clone()),
///       EnvHandle::new(exec.clone(), "PIPELINE_SERVICE".into()),
///   );
#[derive(Clone, Debug)]
pub struct SharedHandles {
    pub db: Arc<DbHandle>,
    pub env: Arc<EnvHandle>,
}

impl SharedHandles {
    pub fn new(db: DbHandle, env: EnvHandle) -> Self {
        Self {
            db: Arc::new(db),
            env: Arc::new(env),
        }
    }
}
