/*!
Single-threaded executor that owns Env and Database, exposing Send tickets.

This executor is designed for Cloudflare Workers (WASM) + Axum:

- Handlers must return Send futures, but worker::Env and the D1 connection are not Send.
- We hide non-Send state behind a single-threaded "actor" that owns Env and Database.
- Handlers call Send + Sync facades (DbHandle/EnvHandle) which submit jobs to this actor.
- Each job is processed serially on the isolate's event loop and completes by resolving a Send
  oneshot future (a Ticket<T>) that the handler `.await`s.

Notes:
- This file depends on `wasm-bindgen-futures` for `spawn_local`. If not present, add:
  wasm-bindgen-futures = "0.4"
  to Cargo.toml [dependencies].
*/

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::db::Database;
use crate::shared_handles::{DbHandle, SharedHandles};
use crate::shared_handles::{EnvHandle, Ticket};
use worker::Env;

// Local boxed future (no Send bound required for the internal actor)
type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

// -------------------------------------------------------------------------------------------------
// Simple oneshot channel (Send) to deliver results back to handlers as Ticket<T>
// -------------------------------------------------------------------------------------------------

struct OneShotState<T> {
    value: Option<T>,
    waker: Option<Waker>,
}

#[derive(Clone)]
struct OneShotSender<T> {
    inner: Arc<Mutex<OneShotState<T>>>,
}

impl<T> OneShotSender<T> {
    fn send(self, v: T) {
        let mut inner = self.inner.lock().unwrap();
        inner.value = Some(v);
        if let Some(w) = inner.waker.take() {
            w.wake();
        }
    }
}

struct OneShotReceiver<T> {
    inner: Arc<Mutex<OneShotState<T>>>,
}

impl<T> OneShotReceiver<T> {
    fn new() -> (OneShotSender<T>, Self) {
        let inner = Arc::new(Mutex::new(OneShotState {
            value: None,
            waker: None,
        }));
        (
            OneShotSender {
                inner: inner.clone(),
            },
            Self { inner },
        )
    }
}

impl<T> Future for OneShotReceiver<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(v) = inner.value.take() {
            Poll::Ready(v)
        } else {
            inner.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Job abstractions
// -------------------------------------------------------------------------------------------------

trait DbJobDyn {
    fn run(self: Box<Self>, db: Database) -> LocalBoxFuture<'static, ()>;
}

trait EnvJobDyn {
    fn run(self: Box<Self>, env: Env) -> LocalBoxFuture<'static, ()>;
}

enum Job {
    Db(Box<dyn DbJobDyn>),
    Env(Box<dyn EnvJobDyn>),
}

// Concrete DB job capturing user closure and its oneshot sender
struct DbJob<T, F, Fut>
where
    F: FnOnce(Database) -> Fut + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    f: Option<F>,
    tx: OneShotSender<T>,
}

impl<T, F, Fut> DbJob<T, F, Fut>
where
    F: FnOnce(Database) -> Fut + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    fn new(f: F, tx: OneShotSender<T>) -> Self {
        Self { f: Some(f), tx }
    }
}

impl<T, F, Fut> DbJobDyn for DbJob<T, F, Fut>
where
    F: FnOnce(Database) -> Fut + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    fn run(self: Box<Self>, db: Database) -> LocalBoxFuture<'static, ()> {
        let mut f_opt = self.f;
        let tx = self.tx;
        Box::pin(async move {
            let f = f_opt.take().expect("DbJob already taken");
            let out = f(db).await;
            tx.send(out);
        })
    }
}

// Concrete Env job capturing user closure and its oneshot sender
struct EnvJob<T, E, F, Fut>
where
    F: FnOnce(Env) -> Fut + 'static,
    Fut: Future<Output = Result<T, E>> + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    f: Option<F>,
    tx: OneShotSender<Result<T, E>>,
}

impl<T, E, F, Fut> EnvJob<T, E, F, Fut>
where
    F: FnOnce(Env) -> Fut + 'static,
    Fut: Future<Output = Result<T, E>> + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    fn new(f: F, tx: OneShotSender<Result<T, E>>) -> Self {
        Self { f: Some(f), tx }
    }
}

impl<T, E, F, Fut> EnvJobDyn for EnvJob<T, E, F, Fut>
where
    F: FnOnce(Env) -> Fut + 'static,
    Fut: Future<Output = Result<T, E>> + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    fn run(self: Box<Self>, env: Env) -> LocalBoxFuture<'static, ()> {
        let mut f_opt = self.f;
        let tx = self.tx;
        Box::pin(async move {
            let f = f_opt.take().expect("EnvJob already taken");
            let out = f(env).await;
            tx.send(out);
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Single-threaded actor that owns non-Send Env + Database
// -------------------------------------------------------------------------------------------------

struct Actor {
    db: Database,
    env: Env,
    queue: VecDeque<Job>,
    processing: bool,
}

impl Actor {
    fn new(db: Database, env: Env) -> Self {
        Self {
            db,
            env,
            queue: VecDeque::new(),
            processing: false,
        }
    }

    fn enqueue(job: Job) {
        ACTOR.with(|cell| {
            let mut guard = cell.borrow_mut();
            let actor = guard.as_mut().expect("Actor not initialized");
            actor.queue.push_back(job);
            if !actor.processing {
                actor.processing = true;
                Self::spawn_processor();
            }
        });
    }

    fn spawn_processor() {
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let next_job = ACTOR.with(|cell| {
                    let mut guard = cell.borrow_mut();
                    let actor = guard.as_mut().expect("Actor not initialized");
                    actor.queue.pop_front()
                });

                match next_job {
                    Some(Job::Db(db_job)) => {
                        let db_clone = ACTOR.with(|cell| {
                            let guard = cell.borrow();
                            let actor = guard.as_ref().expect("Actor not initialized");
                            actor.db.clone()
                        });
                        db_job.run(db_clone).await;
                    }
                    Some(Job::Env(env_job)) => {
                        let env_clone = ACTOR.with(|cell| {
                            let guard = cell.borrow();
                            let actor = guard.as_ref().expect("Actor not initialized");
                            actor.env.clone()
                        });
                        env_job.run(env_clone).await;
                    }
                    None => {
                        // Mark idle and stop
                        ACTOR.with(|cell| {
                            let mut guard = cell.borrow_mut();
                            let actor = guard.as_mut().expect("Actor not initialized");
                            actor.processing = false;
                        });
                        break;
                    }
                }
            }
        });
    }
}

thread_local! {
    static ACTOR: RefCell<Option<Actor>> = const { RefCell::new(None) };
}

// -------------------------------------------------------------------------------------------------
// Public executor type implementing SingleThreadExecutor
// -------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct LocalSingleThreadExecutor;

impl LocalSingleThreadExecutor {
    pub fn new(db: Database, env: Env) -> Self {
        // Initialize the actor for this isolate. Subsequent calls will replace it.
        ACTOR.with(|cell| {
            *cell.borrow_mut() = Some(Actor::new(db, env));
        });
        Self
    }

    /// Convenience helper to build SharedHandles (Send + Sync) wired to this executor.
    /// `pipeline_service_binding` is the service binding name used by your pipeline worker.
    pub fn build_shared_handles(
        db: Database,
        env: Env,
        pipeline_service_binding: &str,
    ) -> SharedHandles {
        let exec = Arc::new(LocalSingleThreadExecutor::new(db, env));
        let db_handle = DbHandle::new(exec.clone());
        let env_handle = EnvHandle::new(exec.clone(), pipeline_service_binding.to_string());
        SharedHandles::new(db_handle, env_handle)
    }
}

impl LocalSingleThreadExecutor {
    pub fn run_db<F, Fut, T>(&self, f: F) -> Ticket<T>
    where
        F: FnOnce(Database) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = OneShotReceiver::<T>::new();

        // Erase Send requirement for the inner closure by boxing the job. The closure will
        // execute on the isolate's single-threaded actor and never leaves this thread.
        let job = DbJob::new(f, tx);
        Actor::enqueue(Job::Db(Box::new(job)));

        Ticket::new(rx)
    }

    pub fn run_env<F, Fut, T, E>(&self, f: F) -> Ticket<Result<T, E>>
    where
        F: FnOnce(Env) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let (tx, rx) = OneShotReceiver::<Result<T, E>>::new();

        let job = EnvJob::new(f, tx);
        Actor::enqueue(Job::Env(Box::new(job)));

        Ticket::new(rx)
    }
}
