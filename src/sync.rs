use std::sync::{Mutex, Arc, MutexGuard};
use rocket::State;

pub type AsyncObj<T> = Arc<Mutex<T>>;
pub type AsyncState<'r, T> = State<'r, AsyncObj<T>>;

pub trait Asyncable<T> {
    fn new_async(s: T) -> AsyncObj<T>;
}

impl<T> Asyncable<T> for T {
    fn new_async(s: T) -> AsyncObj<T> {
        Arc::new(Mutex::new(s))
    }
}

pub trait EpiLock<T> {
    fn epilock(&self) -> MutexGuard<T>;
}

impl<T> EpiLock<T> for AsyncObj<T> {
    fn epilock(&self) -> MutexGuard<T> {
        match self.lock() {
            Ok(t) => t,
            Err(e) => {
                error!("A mutex was poisoned, this is bad");
                e.into_inner() // It's as simple as this, thanks to Rust!
            }
        }
    }
}
