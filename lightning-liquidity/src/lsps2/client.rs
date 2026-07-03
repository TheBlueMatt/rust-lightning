// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-52 / LSPS2 client object, [`LSPS2ClientHandler`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use lightning::util::persist::KVStore;

use core::default::Default;
use core::future::Future as StdFuture;
use core::pin::pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task;

use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::lsps2::event::LSPS2ClientEvent;
use crate::message_queue::MessageQueue;
use crate::persist::{
	LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, LSPS2_CLIENT_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::prelude::hash_map::Entry;
use crate::prelude::{new_hash_map, new_hash_set, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils::async_poll::dummy_waker;

use lightning::impl_ser_tlv_based;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;
use lightning::util::ser::Writeable;

use bitcoin::secp256k1::PublicKey;

use crate::lsps2::msgs::{
	LSPS2BuyRequest, LSPS2BuyResponse, LSPS2GetInfoRequest, LSPS2GetInfoResponse, LSPS2Message,
	LSPS2OpeningFeeParams, LSPS2Request, LSPS2Response,
};

/// Client-side configuration options for JIT channels.
#[derive(Clone, Debug, Copy, Default)]
pub struct LSPS2ClientConfig {}

struct InboundJITChannel {
	payment_size_msat: Option<u64>,
	opening_fee_params: LSPS2OpeningFeeParams,
}

impl InboundJITChannel {
	fn new(payment_size_msat: Option<u64>, opening_fee_params: LSPS2OpeningFeeParams) -> Self {
		Self { payment_size_msat, opening_fee_params }
	}
}

/// The parameters to use when generating an invoice that will be paid via an LSPS2 JIT channel,
/// as negotiated with the LSP in the most recently completed buy flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LSPS2InvoiceParameters {
	/// The node id of the LSP that will open the JIT channel.
	pub counterparty_node_id: PublicKey,
	/// The intercept short channel id to use in the route hint or blinded payment path.
	pub intercept_scid: u64,
	/// The `cltv_expiry_delta` the LSP requires for the hop over `intercept_scid`.
	pub cltv_expiry_delta: u32,
	/// The opening fee parameters we agreed to pay for the channel open.
	pub opening_fee_params: LSPS2OpeningFeeParams,
}

impl_ser_tlv_based!(LSPS2InvoiceParameters, {
	(0, counterparty_node_id, required),
	(2, intercept_scid, required),
	(4, cltv_expiry_delta, required),
	(6, opening_fee_params, required),
});

pub(crate) struct PeerState {
	pending_get_info_requests: HashSet<LSPSRequestId>,
	pending_buy_requests: HashMap<LSPSRequestId, InboundJITChannel>,
	latest_invoice_params: Option<LSPS2InvoiceParameters>,
	needs_persist: bool,
}

impl PeerState {
	fn new() -> Self {
		let pending_get_info_requests = new_hash_set();
		let pending_buy_requests = new_hash_map();
		let latest_invoice_params = None;
		let needs_persist = false;
		Self {
			pending_get_info_requests,
			pending_buy_requests,
			latest_invoice_params,
			needs_persist,
		}
	}

	fn is_prunable(&self) -> bool {
		self.pending_get_info_requests.is_empty()
			&& self.pending_buy_requests.is_empty()
			&& self.latest_invoice_params.is_none()
	}
}

impl_ser_tlv_based!(PeerState, {
	(0, latest_invoice_params, option),
	(_unused, pending_get_info_requests, (static_value, new_hash_set())),
	(_unused, pending_buy_requests, (static_value, new_hash_map())),
	(_unused, needs_persist, (static_value, false)),
});

/// The main object allowing to send and receive bLIP-52 / LSPS2 messages.
///
/// Note that currently only the 'client-trusts-LSP' trust model is supported, i.e., we don't
/// provide any additional API guidance to allow withholding the preimage until the channel is
/// opened. Please refer to the [`bLIP-52 / LSPS2 specification`] for more information.
///
/// [`bLIP-52 / LSPS2 specification`]: https://github.com/lightning/blips/blob/master/blip-0052.md#trust-models
pub struct LSPS2ClientHandler<ES: EntropySource, K: KVStore + Clone> {
	pub(crate) entropy_source: ES,
	kv_store: K,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	config: LSPS2ClientConfig,
	persistence_in_flight: AtomicUsize,
}

impl<ES: EntropySource, K: KVStore + Clone> LSPS2ClientHandler<ES, K> {
	/// Constructs an `LSPS2ClientHandler`.
	pub(crate) fn new(
		per_peer_state: HashMap<PublicKey, Mutex<PeerState>>, entropy_source: ES,
		pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue<K>>, kv_store: K,
		config: LSPS2ClientConfig,
	) -> Self {
		Self {
			entropy_source,
			kv_store,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(per_peer_state),
			config,
			persistence_in_flight: AtomicUsize::new(0),
		}
	}

	/// Returns a reference to the used config.
	pub fn config(&self) -> &LSPS2ClientConfig {
		&self.config
	}

	/// Request the channel opening parameters from the LSP.
	///
	/// This initiates the JIT-channel flow that, at the end of it, will have the LSP
	/// open a channel with sufficient inbound liquidity to be able to receive the payment.
	///
	/// The user will receive the LSP's response via an [`OpeningParametersReady`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///
	/// `token` is an optional `String` that will be provided to the LSP.
	/// It can be used by the LSP as an API key, coupon code, or some other way to identify a user.
	///
	/// Returns the used [`LSPSRequestId`], which will be returned via [`OpeningParametersReady`].
	///
	/// [`OpeningParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::OpeningParametersReady
	pub fn request_opening_params(
		&self, counterparty_node_id: PublicKey, token: Option<String>,
	) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_get_info_requests.insert(request_id.clone());
		}

		let request = LSPS2Request::GetInfo(LSPS2GetInfoRequest { token });
		let msg = LSPS2Message::Request(request_id.clone(), request).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);

		request_id
	}

	/// Confirms a set of chosen channel opening parameters to use for the JIT channel and
	/// requests the necessary invoice generation parameters from the LSP.
	///
	/// Should be called in response to receiving a [`OpeningParametersReady`] event.
	///
	/// The user will receive the LSP's response via an [`InvoiceParametersReady`] event.
	///
	/// If `payment_size_msat` is [`Option::Some`] then the invoice will be for a fixed amount
	/// and MPP can be used to pay it.
	///
	/// If `payment_size_msat` is [`Option::None`] then the invoice can be for an arbitrary amount
	/// but MPP can no longer be used to pay it.
	///
	/// The client agrees to paying an opening fee equal to
	/// `max(min_fee_msat, proportional * (payment_size_msat / 1_000_000))`.
	///
	/// Once the LSP confirms the request, i.e., when we receive the response emitted via
	/// [`InvoiceParametersReady`], the resulting invoice parameters will be cached and persisted
	/// as the latest parameters negotiated with the LSP. They can be retrieved via
	/// [`Self::latest_invoice_params`] until they are wiped via
	/// [`Self::clear_latest_invoice_params`].
	///
	/// Returns the used [`LSPSRequestId`] that was used for the buy request.
	///
	/// [`OpeningParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::OpeningParametersReady
	/// [`InvoiceParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::InvoiceParametersReady
	pub fn select_opening_params(
		&self, counterparty_node_id: PublicKey, payment_size_msat: Option<u64>,
		opening_fee_params: LSPS2OpeningFeeParams,
	) -> Result<LSPSRequestId, APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();

			let jit_channel = InboundJITChannel::new(payment_size_msat, opening_fee_params.clone());
			if peer_state_lock
				.pending_buy_requests
				.insert(request_id.clone(), jit_channel)
				.is_some()
			{
				return Err(APIError::APIMisuseError {
					err: "Failed due to duplicate request_id. This should never happen!"
						.to_string(),
				});
			}
		}

		let request = LSPS2Request::Buy(LSPS2BuyRequest { opening_fee_params, payment_size_msat });
		let msg = LSPS2Message::Request(request_id.clone(), request).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);

		Ok(request_id)
	}

	/// Returns the latest invoice parameters negotiated with each LSP.
	///
	/// The returned [`Vec`] holds, for each LSP (identified by
	/// [`LSPS2InvoiceParameters::counterparty_node_id`]) we ever negotiated parameters with, the
	/// parameters resulting from the buy flow we most recently initiated via
	/// [`Self::select_opening_params`] and that were subsequently confirmed by the LSP.
	///
	/// The parameters are persisted towards the used [`KVStore`], i.e., they will still be
	/// available after restart. They are also used by an [`LSPS2Router`] to inject JIT-channel
	/// blinded payment paths when creating BOLT12 invoices.
	///
	/// [`LSPS2Router`]: crate::lsps2::router::LSPS2Router
	pub fn latest_invoice_params(&self) -> Vec<LSPS2InvoiceParameters> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		outer_state_lock
			.iter()
			.filter_map(|(_, inner_state_lock)| {
				let peer_state = inner_state_lock.lock().unwrap();
				peer_state.latest_invoice_params.clone()
			})
			.collect()
	}

	/// Wipes the latest invoice parameters negotiated with the LSP with the given
	/// `counterparty_node_id`, i.e., they will no longer be returned by
	/// [`Self::latest_invoice_params`], and updates the [`KVStore`] accordingly.
	///
	/// This is a no-op if we never negotiated parameters with the given LSP.
	pub async fn clear_latest_invoice_params(
		&self, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		{
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();
					if peer_state.latest_invoice_params.take().is_some() {
						peer_state.needs_persist = true;
					}
				},
				None => return Ok(()),
			}
		}

		// Note we leave removing any now-empty peer state entries to the prune logic in
		// `persist`, which will also remove them from the store.
		self.persist_peer_state(*counterparty_node_id).await.map_err(|e| APIError::APIMisuseError {
			err: format!("Failed to persist peer state for {}: {}", counterparty_node_id, e),
		})
	}

	fn handle_get_info_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		result: LSPS2GetInfoResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_info response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS2ClientEvent::OpeningParametersReady {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					opening_fee_params_menu: result.opening_fee_params_menu,
				});
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received get_info response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				})
			},
		}

		Ok(())
	}

	fn handle_get_info_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_info error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				let lightning_error = LightningError {
					err: format!(
						"Received get_info error response for request {:?}: {:?}",
						request_id, error
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				};

				event_queue_notifier.enqueue(LSPS2ClientEvent::GetInfoFailed {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					error,
				});

				Err(lightning_error)
			},
			None => {
				return Err(LightningError { err: format!("Received error response for a get_info request from an unknown counterparty {}",counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Debug)});
			},
		}
	}

	fn handle_buy_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		result: LSPS2BuyResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				let jit_channel =
					peer_state.pending_buy_requests.remove(&request_id).ok_or(LightningError {
						err: format!(
							"Received buy response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					})?;

				if let Ok(intercept_scid) = result.jit_channel_scid.to_scid() {
					peer_state.latest_invoice_params = Some(LSPS2InvoiceParameters {
						counterparty_node_id: *counterparty_node_id,
						intercept_scid,
						cltv_expiry_delta: result.lsp_cltv_expiry_delta,
						opening_fee_params: jit_channel.opening_fee_params,
					});
					peer_state.needs_persist = true;

					event_queue_notifier.enqueue(LSPS2ClientEvent::InvoiceParametersReady {
						request_id,
						counterparty_node_id: *counterparty_node_id,
						intercept_scid,
						cltv_expiry_delta: result.lsp_cltv_expiry_delta,
						payment_size_msat: jit_channel.payment_size_msat,
					});
				} else {
					return Err(LightningError {
						err: format!(
							"Received buy response with an invalid intercept scid {:?}",
							result.jit_channel_scid
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received buy response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
		Ok(())
	}

	fn handle_buy_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				peer_state.pending_buy_requests.remove(&request_id).ok_or(LightningError {
					err: format!("Received buy error for an unknown request: {:?}", request_id),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				})?;

				let lightning_error = LightningError {
					err: format!(
						"Received buy error response for request {:?}: {:?}",
						request_id, error
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				};

				event_queue_notifier.enqueue(LSPS2ClientEvent::BuyRequestFailed {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					error,
				});

				Err(lightning_error)
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received error response for a buy request from an unknown counterparty {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}

	async fn persist_peer_state(
		&self, counterparty_node_id: PublicKey,
	) -> Result<(), lightning::io::Error> {
		let fut = {
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(&counterparty_node_id) {
				None => {
					// We dropped the peer state by now.
					return Ok(());
				},
				Some(entry) => {
					let mut peer_state_lock = entry.lock().unwrap();
					if !peer_state_lock.needs_persist {
						// We already have persisted otherwise by now.
						return Ok(());
					} else {
						peer_state_lock.needs_persist = false;
						let key = counterparty_node_id.to_string();
						let encoded = peer_state_lock.encode();
						// Begin the write with the entry lock held. This avoids racing with
						// potentially-in-flight `persist` calls writing state for the same peer.
						self.kv_store.write(
							LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
							LSPS2_CLIENT_PERSISTENCE_SECONDARY_NAMESPACE,
							&key,
							encoded,
						)
					}
				},
			}
		};

		fut.await.map_err(|e| {
			self.per_peer_state
				.read()
				.unwrap()
				.get(&counterparty_node_id)
				.map(|p| p.lock().unwrap().needs_persist = true);
			e
		})
	}

	pub(crate) async fn persist(&self) -> Result<bool, lightning::io::Error> {
		// TODO: We should eventually persist in parallel, however, when we do, we probably want to
		// introduce some batching to upper-bound the number of requests inflight at any given
		// time.

		if self.persistence_in_flight.fetch_add(1, Ordering::AcqRel) > 0 {
			// If we're not the first event processor to get here, just return early, the increment
			// we just did will be treated as "go around again" at the end.
			return Ok(false);
		}

		let res = self.do_persist().await;
		debug_assert!(res.is_err() || self.persistence_in_flight.load(Ordering::Acquire) == 0);
		self.persistence_in_flight.store(0, Ordering::Release);
		res
	}

	async fn do_persist(&self) -> Result<bool, lightning::io::Error> {
		let mut did_persist = false;

		loop {
			let mut need_remove = Vec::new();
			let mut need_persist = Vec::new();

			{
				// First build a list of peers to persist and prune with the read lock. This allows
				// us to avoid the write lock unless we actually need to remove a node.
				let outer_state_lock = self.per_peer_state.read().unwrap();
				for (counterparty_node_id, inner_state_lock) in outer_state_lock.iter() {
					let peer_state_lock = inner_state_lock.lock().unwrap();
					if peer_state_lock.is_prunable() {
						need_remove.push(*counterparty_node_id);
					} else if peer_state_lock.needs_persist {
						need_persist.push(*counterparty_node_id);
					}
				}
			}

			for counterparty_node_id in need_persist.into_iter() {
				debug_assert!(!need_remove.contains(&counterparty_node_id));
				self.persist_peer_state(counterparty_node_id).await?;
				did_persist = true;
			}

			for counterparty_node_id in need_remove {
				let mut future_opt = None;
				{
					// We need to take the `per_peer_state` write lock to remove an entry, but also
					// have to hold it until after the `remove` call returns (but not through
					// future completion) to ensure that writes for the peer's state are
					// well-ordered with other `persist_peer_state` calls even across the removal
					// itself.
					let mut per_peer_state = self.per_peer_state.write().unwrap();
					if let Entry::Occupied(mut entry) = per_peer_state.entry(counterparty_node_id) {
						let state = entry.get_mut().get_mut().unwrap();
						if state.is_prunable() {
							entry.remove();
							let key = counterparty_node_id.to_string();
							future_opt = Some(self.kv_store.remove(
								LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
								LSPS2_CLIENT_PERSISTENCE_SECONDARY_NAMESPACE,
								&key,
								true,
							));
						} else {
							// If the peer got new state, force a re-persist of the current state.
							state.needs_persist = true;
						}
					} else {
						// This should never happen, we can only have one `persist` call
						// in-progress at once and map entries are only removed by it.
						debug_assert!(false);
					}
				}
				if let Some(future) = future_opt {
					future.await?;
					did_persist = true;
				} else {
					self.persist_peer_state(counterparty_node_id).await?;
					did_persist = true;
				}
			}

			if self.persistence_in_flight.fetch_sub(1, Ordering::AcqRel) != 1 {
				// If another thread incremented the state while we were running we should go
				// around again, but only once.
				self.persistence_in_flight.store(1, Ordering::Release);
				continue;
			}
			break;
		}

		Ok(did_persist)
	}
}

impl<ES: EntropySource, K: KVStore + Clone> LSPSProtocolMessageHandler
	for LSPS2ClientHandler<ES, K>
{
	type ProtocolMessage = LSPS2Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(2);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS2Message::Response(request_id, response) => match response {
				LSPS2Response::GetInfo(result) => {
					self.handle_get_info_response(request_id, counterparty_node_id, result)
				},
				LSPS2Response::GetInfoError(error) => {
					self.handle_get_info_error(request_id, counterparty_node_id, error)
				},
				LSPS2Response::Buy(result) => {
					self.handle_buy_response(request_id, counterparty_node_id, result)
				},
				LSPS2Response::BuyError(error) => {
					self.handle_buy_error(request_id, counterparty_node_id, error)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Client handler received LSPS2 request message. This should never happen."
				);
				Err(LightningError { err: format!("Client handler received LSPS2 request message from node {}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

/// A synchroneous wrapper around [`LSPS2ClientHandler`] to be used in contexts where async is not
/// available.
pub struct LSPS2ClientHandlerSync<'a, ES: EntropySource, K: KVStore + Clone> {
	inner: &'a LSPS2ClientHandler<ES, K>,
}

impl<'a, ES: EntropySource, K: KVStore + Clone> LSPS2ClientHandlerSync<'a, ES, K> {
	pub(crate) fn from_inner(inner: &'a LSPS2ClientHandler<ES, K>) -> Self {
		Self { inner }
	}

	/// Returns a reference to the used config.
	///
	/// Wraps [`LSPS2ClientHandler::config`].
	pub fn config(&self) -> &LSPS2ClientConfig {
		self.inner.config()
	}

	/// Request the channel opening parameters from the LSP.
	///
	/// Wraps [`LSPS2ClientHandler::request_opening_params`].
	pub fn request_opening_params(
		&self, counterparty_node_id: PublicKey, token: Option<String>,
	) -> LSPSRequestId {
		self.inner.request_opening_params(counterparty_node_id, token)
	}

	/// Confirms a set of chosen channel opening parameters to use for the JIT channel and
	/// requests the necessary invoice generation parameters from the LSP.
	///
	/// Wraps [`LSPS2ClientHandler::select_opening_params`].
	pub fn select_opening_params(
		&self, counterparty_node_id: PublicKey, payment_size_msat: Option<u64>,
		opening_fee_params: LSPS2OpeningFeeParams,
	) -> Result<LSPSRequestId, APIError> {
		self.inner.select_opening_params(
			counterparty_node_id,
			payment_size_msat,
			opening_fee_params,
		)
	}

	/// Returns the latest invoice parameters negotiated with each LSP.
	///
	/// Wraps [`LSPS2ClientHandler::latest_invoice_params`].
	pub fn latest_invoice_params(&self) -> Vec<LSPS2InvoiceParameters> {
		self.inner.latest_invoice_params()
	}

	/// Wipes the latest invoice parameters negotiated with the LSP with the given
	/// `counterparty_node_id`.
	///
	/// Wraps [`LSPS2ClientHandler::clear_latest_invoice_params`].
	pub fn clear_latest_invoice_params(
		&self, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		let mut fut = pin!(self.inner.clear_latest_invoice_params(counterparty_node_id));

		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("Should not be pending in a sync context");
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::lsps0::ser::LSPSDateTime;
	use crate::lsps2::msgs::LSPS2InterceptScid;
	use crate::persist::read_lsps2_client_peer_states;

	use bitcoin::key::Secp256k1;
	use bitcoin::secp256k1::SecretKey;

	use lightning::util::persist::KVStoreSyncWrapper;
	use lightning::util::test_utils::TestStore;
	use lightning::util::wakers::Notifier;

	use alloc::collections::VecDeque;

	use core::future::Future;
	use core::str::FromStr;
	use core::sync::atomic::{AtomicU64, Ordering};

	struct UniqueTestEntropy {
		counter: AtomicU64,
	}

	impl EntropySource for UniqueTestEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let counter = self.counter.fetch_add(1, Ordering::SeqCst);
			let mut bytes = [0u8; 32];
			bytes[0..8].copy_from_slice(&counter.to_be_bytes());
			bytes
		}
	}

	type TestStoreRef = Arc<KVStoreSyncWrapper<Arc<TestStore>>>;
	type TestClient = LSPS2ClientHandler<Arc<UniqueTestEntropy>, TestStoreRef>;

	fn block_on<F: Future>(fut: F) -> F::Output {
		let mut fut = pin!(fut);
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(res) => res,
			task::Poll::Pending => panic!("Future should not be pending in a sync context"),
		}
	}

	fn setup_test_client_with_store(
		kv_store: TestStoreRef, per_peer_state: HashMap<PublicKey, Mutex<PeerState>>,
	) -> TestClient {
		let test_entropy_source = Arc::new(UniqueTestEntropy { counter: AtomicU64::new(2) });
		let notifier = Arc::new(Notifier::new());
		let message_queue = Arc::new(MessageQueue::new(notifier));

		let persist_notifier = Arc::new(Notifier::new());
		let event_queue =
			Arc::new(EventQueue::new(VecDeque::new(), kv_store.clone(), persist_notifier));
		LSPS2ClientHandler::new(
			per_peer_state,
			test_entropy_source,
			message_queue,
			event_queue,
			kv_store,
			LSPS2ClientConfig::default(),
		)
	}

	fn setup_test_client() -> (TestClient, TestStoreRef, PublicKey, PublicKey) {
		let kv_store = Arc::new(KVStoreSyncWrapper(Arc::new(TestStore::new(false))));
		let client = setup_test_client_with_store(kv_store.clone(), new_hash_map());

		let secp = Secp256k1::new();
		let secret_key_1 = SecretKey::from_slice(&[42u8; 32]).unwrap();
		let secret_key_2 = SecretKey::from_slice(&[43u8; 32]).unwrap();
		let peer_1 = PublicKey::from_secret_key(&secp, &secret_key_1);
		let peer_2 = PublicKey::from_secret_key(&secp, &secret_key_2);

		(client, kv_store, peer_1, peer_2)
	}

	fn dummy_opening_fee_params(min_fee_msat: u64) -> LSPS2OpeningFeeParams {
		LSPS2OpeningFeeParams {
			min_fee_msat,
			proportional: 21,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1,
			max_payment_size_msat: 100_000_000,
			promise: "promise".to_string(),
		}
	}

	fn dummy_buy_response() -> LSPS2BuyResponse {
		LSPS2BuyResponse {
			jit_channel_scid: LSPS2InterceptScid::from(42),
			lsp_cltv_expiry_delta: 144,
			client_trusts_lsp: false,
		}
	}

	fn dummy_invoice_params(
		counterparty_node_id: PublicKey, min_fee_msat: u64,
	) -> LSPS2InvoiceParameters {
		LSPS2InvoiceParameters {
			counterparty_node_id,
			intercept_scid: 42,
			cltv_expiry_delta: 144,
			opening_fee_params: dummy_opening_fee_params(min_fee_msat),
		}
	}

	// Runs the full get_info + buy flow with the given peer and returns the resulting invoice
	// parameters.
	fn negotiate_invoice_params(
		client: &TestClient, peer: PublicKey, min_fee_msat: u64,
	) -> LSPS2InvoiceParameters {
		let opening_fee_params = dummy_opening_fee_params(min_fee_msat);

		let request_id = client.request_opening_params(peer, None);
		let response =
			LSPS2GetInfoResponse { opening_fee_params_menu: vec![opening_fee_params.clone()] };
		client.handle_get_info_response(request_id, &peer, response).unwrap();

		let request_id =
			client.select_opening_params(peer, Some(1_000), opening_fee_params).unwrap();
		client.handle_buy_response(request_id, &peer, dummy_buy_response()).unwrap();

		dummy_invoice_params(peer, min_fee_msat)
	}

	#[test]
	fn stores_latest_invoice_params_per_lsp() {
		let (client, _, peer_1, peer_2) = setup_test_client();

		assert!(client.latest_invoice_params().is_empty());

		// Receiving an opening fee params menu alone doesn't store any parameters.
		let request_id = client.request_opening_params(peer_1, None);
		let menu = vec![dummy_opening_fee_params(42)];
		let response = LSPS2GetInfoResponse { opening_fee_params_menu: menu };
		client.handle_get_info_response(request_id, &peer_1, response).unwrap();
		assert!(client.latest_invoice_params().is_empty());

		// Neither does selecting parameters, until the LSP confirms the buy request.
		let opening_fee_params_1 = dummy_opening_fee_params(100);
		let request_id =
			client.select_opening_params(peer_1, Some(1_000), opening_fee_params_1).unwrap();
		assert!(client.latest_invoice_params().is_empty());

		// A buy response for an unknown request id is rejected and doesn't store any parameters.
		let unknown_request_id = LSPSRequestId("unknown:request:id".to_string());
		assert!(client
			.handle_buy_response(unknown_request_id, &peer_1, dummy_buy_response())
			.is_err());
		assert!(client.latest_invoice_params().is_empty());

		// Once the LSP confirms the buy request, the resulting parameters are stored.
		let params_1 = dummy_invoice_params(peer_1, 100);
		client.handle_buy_response(request_id, &peer_1, dummy_buy_response()).unwrap();
		assert_eq!(client.latest_invoice_params(), vec![params_1.clone()]);

		// Parameters are stored on a per-LSP basis.
		let params_2 = negotiate_invoice_params(&client, peer_2, 300);
		let latest_invoice_params = client.latest_invoice_params();
		assert_eq!(latest_invoice_params.len(), 2);
		assert!(latest_invoice_params.contains(&params_1));
		assert!(latest_invoice_params.contains(&params_2));

		// Parameters negotiated in a subsequent buy flow replace the previously stored ones.
		let params_3 = negotiate_invoice_params(&client, peer_1, 400);
		let latest_invoice_params = client.latest_invoice_params();
		assert_eq!(latest_invoice_params.len(), 2);
		assert!(latest_invoice_params.contains(&params_3));
		assert!(latest_invoice_params.contains(&params_2));
	}

	#[test]
	fn clears_latest_invoice_params() {
		let (client, kv_store, peer_1, peer_2) = setup_test_client();

		// Clearing parameters for an unknown peer is a no-op.
		block_on(client.clear_latest_invoice_params(&peer_1)).unwrap();
		assert!(client.latest_invoice_params().is_empty());

		let _params_1 = negotiate_invoice_params(&client, peer_1, 100);
		let params_2 = negotiate_invoice_params(&client, peer_2, 300);

		block_on(client.clear_latest_invoice_params(&peer_1)).unwrap();
		assert_eq!(client.latest_invoice_params(), vec![params_2.clone()]);

		// As we wiped the only state we held for `peer_1`, its entry is pruned entirely (from
		// memory and the store) by the next `persist` call.
		assert!(client.per_peer_state.read().unwrap().contains_key(&peer_1));
		assert!(block_on(client.persist()).unwrap());
		assert!(!client.per_peer_state.read().unwrap().contains_key(&peer_1));

		let peer_states = block_on(read_lsps2_client_peer_states(kv_store.clone())).unwrap();
		assert!(!peer_states.contains_key(&peer_1));
		let client_2 = setup_test_client_with_store(kv_store, peer_states);
		assert_eq!(client_2.latest_invoice_params(), vec![params_2]);

		// Clearing the parameters of a peer with pending requests wipes the parameters but keeps
		// the remaining peer state around.
		let _pending_request_id = client.request_opening_params(peer_2, None);
		block_on(client.clear_latest_invoice_params(&peer_2)).unwrap();
		assert!(client.latest_invoice_params().is_empty());
		assert!(client.per_peer_state.read().unwrap().contains_key(&peer_2));
	}

	#[test]
	fn persists_latest_invoice_params() {
		let (client, kv_store, peer_1, peer_2) = setup_test_client();

		// There is nothing to persist until we negotiated parameters.
		assert!(!block_on(client.persist()).unwrap());
		assert!(block_on(read_lsps2_client_peer_states(kv_store.clone())).unwrap().is_empty());

		let params_1 = negotiate_invoice_params(&client, peer_1, 100);
		let params_2 = negotiate_invoice_params(&client, peer_2, 300);
		assert!(block_on(client.persist()).unwrap());

		// A fresh client initialized from the store returns the persisted parameters.
		let peer_states = block_on(read_lsps2_client_peer_states(kv_store.clone())).unwrap();
		let client_2 = setup_test_client_with_store(kv_store.clone(), peer_states);
		let latest_invoice_params = client_2.latest_invoice_params();
		assert_eq!(latest_invoice_params.len(), 2);
		assert!(latest_invoice_params.contains(&params_1));
		assert!(latest_invoice_params.contains(&params_2));

		// Persisting again is a no-op as long as the state didn't change.
		assert!(!block_on(client.persist()).unwrap());

		// Negotiating new parameters requires repersistence.
		let params_3 = negotiate_invoice_params(&client, peer_1, 400);
		assert!(block_on(client.persist()).unwrap());
		let peer_states = block_on(read_lsps2_client_peer_states(kv_store.clone())).unwrap();
		let client_3 = setup_test_client_with_store(kv_store, peer_states);
		assert!(client_3.latest_invoice_params().contains(&params_3));
	}
}
