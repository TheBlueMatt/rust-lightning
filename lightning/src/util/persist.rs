// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a simple key-value store trait KVStorePersister that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.

use core::ops::Deref;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{BlockHash, Txid};

use crate::io;
use crate::prelude::{Vec, String};
use crate::routing::scoring::WriteableScore;

use crate::chain;
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::{Persist, MonitorUpdateId};
use crate::sign::{EntropySource, NodeSigner, WriteableEcdsaChannelSigner, SignerProvider};
use crate::chain::transaction::OutPoint;
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use crate::ln::channelmanager::ChannelManager;
use crate::routing::router::Router;
use crate::routing::gossip::NetworkGraph;
use crate::util::logger::Logger;
use crate::util::ser::{ReadableArgs, Writeable};

/// The namespace under which the [`ChannelManager`] will be persisted.
pub const CHANNEL_MANAGER_PERSISTENCE_NAMESPACE: &str = "";
/// The key under which the [`ChannelManager`] will be persisted.
pub const CHANNEL_MANAGER_PERSISTENCE_KEY: &str = "manager";

/// The namespace under which [`ChannelMonitor`]s will be persisted.
pub const CHANNEL_MONITOR_PERSISTENCE_NAMESPACE: &str = "monitors";

/// The namespace under which the [`NetworkGraph`] will be persisted.
pub const NETWORK_GRAPH_PERSISTENCE_NAMESPACE: &str = "";
/// The key under which the [`NetworkGraph`] will be persisted.
pub const NETWORK_GRAPH_PERSISTENCE_KEY: &str = "network_graph";

/// The namespace under which the [`WriteableScore`] will be persisted.
pub const SCORER_PERSISTENCE_NAMESPACE: &str = "";
/// The key under which the [`WriteableScore`] will be persisted.
pub const SCORER_PERSISTENCE_KEY: &str = "scorer";

/// Provides an interface that allows to store and retrieve persisted values that are associated
/// with given keys.
///
/// In order to avoid collisions the key space is segmented based on the given `namespace`s.
/// Implementations of this trait are free to handle them in different ways, as long as
/// per-namespace key uniqueness is asserted.
///
/// Keys and namespaces are required to be valid ASCII strings that do not contain control
/// characters, and the empty namespace (`""`) is assumed to be a valid namespace.
pub trait KVStore {
	/// Returns the data stored for the given `namespace` and `key`.
	///
	/// Returns an [`ErrorKind::NotFound`] if the given `key` could not be found in the given `namespace`.
	///
	/// [`ErrorKind::NotFound`]: io::ErrorKind::NotFound
	fn read(&self, namespace: &str, key: &str) -> io::Result<Vec<u8>>;
	/// Persists the given data under the given `key`.
	///
	/// Will create the given `namespace` if not already present in the store.
	fn write(&self, namespace: &str, key: &str, buf: &[u8]) -> io::Result<()>;
	/// Removes any data that had previously been persisted under the given `key`.
	fn remove(&self, namespace: &str, key: &str) -> io::Result<()>;
	/// Returns a list of keys that are stored under the given `namespace`.
	///
	/// Will return an empty list if the `namespace` is unknown.
	fn list(&self, namespace: &str) -> io::Result<Vec<String>>;
}

/// Trait that handles persisting a [`ChannelManager`], [`NetworkGraph`], and [`WriteableScore`] to disk.
pub trait Persister<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref, S: WriteableScore<'a>>
	where M::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: 'static + BroadcasterInterface,
		ES::Target: 'static + EntropySource,
		NS::Target: 'static + NodeSigner,
		SP::Target: 'static + SignerProvider,
		F::Target: 'static + FeeEstimator,
		R::Target: 'static + Router,
		L::Target: 'static + Logger,
{
	/// Persist the given ['ChannelManager'] to disk, returning an error if persistence failed.
	fn persist_manager(&self, channel_manager: &ChannelManager<M, T, ES, NS, SP, F, R, L>) -> Result<(), io::Error>;

	/// Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	fn persist_graph(&self, network_graph: &NetworkGraph<L>) -> Result<(), io::Error>;

	/// Persist the given [`WriteableScore`] to disk, returning an error if persistence failed.
	fn persist_scorer(&self, scorer: &S) -> Result<(), io::Error>;
}


impl<'a, A: KVStore, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref, S: WriteableScore<'a>> Persister<'a, M, T, ES, NS, SP, F, R, L, S> for A
	where M::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: 'static + BroadcasterInterface,
		ES::Target: 'static + EntropySource,
		NS::Target: 'static + NodeSigner,
		SP::Target: 'static + SignerProvider,
		F::Target: 'static + FeeEstimator,
		R::Target: 'static + Router,
		L::Target: 'static + Logger,
{
	/// Persist the given ['ChannelManager'] to disk, returning an error if persistence failed.
	fn persist_manager(&self, channel_manager: &ChannelManager<M, T, ES, NS, SP, F, R, L>) -> Result<(), io::Error> {
		self.write(CHANNEL_MANAGER_PERSISTENCE_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_KEY, &channel_manager.encode())
	}

	/// Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	fn persist_graph(&self, network_graph: &NetworkGraph<L>) -> Result<(), io::Error> {
		self.write(NETWORK_GRAPH_PERSISTENCE_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_KEY, &network_graph.encode())
	}

	/// Persist the given [`WriteableScore`] to disk, returning an error if persistence failed.
	fn persist_scorer(&self, scorer: &S) -> Result<(), io::Error> {
		self.write(SCORER_PERSISTENCE_NAMESPACE, SCORER_PERSISTENCE_KEY, &scorer.encode())
	}
}

impl<ChannelSigner: WriteableEcdsaChannelSigner, K: KVStore> Persist<ChannelSigner> for K {
	// TODO: We really need a way for the persister to inform the user that its time to crash/shut
	// down once these start returning failure.
	// A PermanentFailure implies we should probably just shut down the node since we're
	// force-closing channels without even broadcasting!

	fn persist_new_channel(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChannelSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		let key = format!("{}_{}", funding_txo.txid.to_hex(), funding_txo.index);
		match self.write(CHANNEL_MONITOR_PERSISTENCE_NAMESPACE, &key, &monitor.encode()) {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
		}
	}

	fn update_persisted_channel(&self, funding_txo: OutPoint, _update: Option<&ChannelMonitorUpdate>, monitor: &ChannelMonitor<ChannelSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		let key = format!("{}_{}", funding_txo.txid.to_hex(), funding_txo.index);
		match self.write(CHANNEL_MONITOR_PERSISTENCE_NAMESPACE, &key, &monitor.encode()) {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
		}
	}
}

/// Read previously persisted [`ChannelMonitor`]s from the store.
pub fn read_channel_monitors<K: Deref, ES: Deref, SP: Deref>(
	kv_store: K, entropy_source: ES, signer_provider: SP,
) -> io::Result<Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::Signer>)>>
where
	K::Target: KVStore,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
{
	let mut res = Vec::new();

	for stored_key in kv_store.list(CHANNEL_MONITOR_PERSISTENCE_NAMESPACE)? {
		let txid = Txid::from_hex(stored_key.split_at(64).0).map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidData, "Invalid tx ID in stored key")
		})?;

		let index: u16 = stored_key.split_at(65).1.parse().map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidData, "Invalid tx index in stored key")
		})?;

		match <(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::Signer>)>::read(
			&mut io::Cursor::new(kv_store.read(CHANNEL_MONITOR_PERSISTENCE_NAMESPACE, &stored_key)?),
			(&*entropy_source, &*signer_provider),
		) {
			Ok((block_hash, channel_monitor)) => {
				if channel_monitor.get_funding_txo().0.txid != txid
					|| channel_monitor.get_funding_txo().0.index != index
				{
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"ChannelMonitor was stored under the wrong key",
					));
				}
				res.push((block_hash, channel_monitor));
			}
			Err(_) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"Failed to deserialize ChannelMonitor"
				))
			}
		}
	}
	Ok(res)
}
