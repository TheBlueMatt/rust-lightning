// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and impls for receiving messages about the network and storing the topology live here.

pub mod network_graph;
pub mod router;
pub mod scorer;

use routing::network_graph::NodeId;
use routing::router::RouteHop;

use prelude::*;
use core::ops::{Deref, DerefMut};
use sync::{Mutex, MutexGuard};

/// An interface used to score payment channels for path finding.
///
///	Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
pub trait Score {
	/// Returns the fee in msats willing to be paid to avoid routing through the given channel
	/// in the direction from `source` to `target`.
	fn channel_penalty_msat(&self, short_channel_id: u64, source: &NodeId, target: &NodeId) -> u64;

	/// Handles updating channel penalties after failing to route through a channel.
	fn payment_path_failed(&mut self, path: &Vec<RouteHop>, short_channel_id: u64);
}

///
pub trait LockableScore<'b> {
	///
	type Locked: Score + 'b;
	///
	fn lock(&'b self) -> Self::Locked;
}

impl<'b, S: Score + 'b, T: Deref<Target=Mutex<S>>> LockableScore<'b> for T {
	type Locked = MutexGuard<'b, S>;
	fn lock(&'b self) -> MutexGuard<'b, S> {
		self.deref().lock().unwrap()
	}
}

impl<'a, S: Score> Score for MutexGuard<'a, S> {
	fn channel_penalty_msat(&self, short_channel_id: u64, source: &NodeId, target: &NodeId) -> u64 {
		self.deref().channel_penalty_msat(short_channel_id, source, target)
	}

	fn payment_path_failed(&mut self, path: &Vec<RouteHop>, short_channel_id: u64) {
		self.deref_mut().payment_path_failed(path, short_channel_id)
	}
}
