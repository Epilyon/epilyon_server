/*
 * Epilyon, keeping EPITA students organized
 * Copyright (C) 2019-2020 Adrien 'Litarvan' Navratil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::sync::{MutexGuard, Mutex};

use log::error;

pub trait EpiLock<T> {
    fn epilock(&self) -> MutexGuard<T>;
}

impl<T> EpiLock<T> for Mutex<T> {
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
