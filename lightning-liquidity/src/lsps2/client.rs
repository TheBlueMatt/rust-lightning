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

use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::lsps2::event::LSPS2ClientEvent;
use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, new_hash_set, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;

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

struct PeerState {
	pending_get_info_requests: HashSet<LSPSRequestId>,
	pending_buy_requests: HashMap<LSPSRequestId, InboundJITChannel>,
	latest_opening_fee_params: Option<LSPS2OpeningFeeParams>,
}

impl PeerState {
	fn new() -> Self {
		let pending_get_info_requests = new_hash_set();
		let pending_buy_requests = new_hash_map();
		let latest_opening_fee_params = None;
		Self { pending_get_info_requests, pending_buy_requests, latest_opening_fee_params }
	}

	fn is_prunable(&self) -> bool {
		self.pending_get_info_requests.is_empty()
			&& self.pending_buy_requests.is_empty()
			&& self.latest_opening_fee_params.is_none()
	}
}

/// The main object allowing to send and receive bLIP-52 / LSPS2 messages.
///
/// Note that currently only the 'client-trusts-LSP' trust model is supported, i.e., we don't
/// provide any additional API guidance to allow withholding the preimage until the channel is
/// opened. Please refer to the [`bLIP-52 / LSPS2 specification`] for more information.
///
/// [`bLIP-52 / LSPS2 specification`]: https://github.com/lightning/blips/blob/master/blip-0052.md#trust-models
pub struct LSPS2ClientHandler<ES: EntropySource, K: KVStore + Clone> {
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	config: LSPS2ClientConfig,
}

impl<ES: EntropySource, K: KVStore + Clone> LSPS2ClientHandler<ES, K> {
	/// Constructs an `LSPS2ClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>,
		pending_events: Arc<EventQueue<K>>, config: LSPS2ClientConfig,
	) -> Self {
		Self {
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
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
	/// [`InvoiceParametersReady`], the chosen parameters will be cached as the latest parameters
	/// negotiated with the LSP. They can be retrieved via [`Self::latest_opening_params`] until
	/// they are wiped via [`Self::clear_latest_opening_params`].
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

	/// Returns the latest opening fee parameters negotiated with each LSP.
	///
	/// The returned [`Vec`] holds, for each LSP (identified by its `counterparty_node_id`) we
	/// ever negotiated parameters with, the opening fee parameters we most recently chose via
	/// [`Self::select_opening_params`] and that were subsequently confirmed by the LSP.
	///
	/// Note that this state is held in-memory only and hence will be lost on restart.
	pub fn latest_opening_params(&self) -> Vec<(PublicKey, LSPS2OpeningFeeParams)> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		outer_state_lock
			.iter()
			.filter_map(|(counterparty_node_id, inner_state_lock)| {
				let peer_state = inner_state_lock.lock().unwrap();
				peer_state
					.latest_opening_fee_params
					.as_ref()
					.map(|params| (*counterparty_node_id, params.clone()))
			})
			.collect()
	}

	/// Wipes the latest opening fee parameters negotiated with the LSP with the given
	/// `counterparty_node_id`, i.e., they will no longer be returned by
	/// [`Self::latest_opening_params`].
	///
	/// This is a no-op if we never negotiated parameters with the given LSP.
	pub fn clear_latest_opening_params(&self, counterparty_node_id: &PublicKey) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(counterparty_node_id) {
			let mut peer_state = inner_state_lock.lock().unwrap();
			peer_state.latest_opening_fee_params = None;
			let is_prunable = peer_state.is_prunable();
			drop(peer_state);
			if is_prunable {
				outer_state_lock.remove(counterparty_node_id);
			}
		}
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
					peer_state.latest_opening_fee_params = Some(jit_channel.opening_fee_params);

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

#[cfg(test)]
mod tests {
	use super::*;

	use crate::lsps0::ser::LSPSDateTime;
	use crate::lsps2::msgs::LSPS2InterceptScid;

	use bitcoin::key::Secp256k1;
	use bitcoin::secp256k1::SecretKey;

	use lightning::util::persist::KVStoreSyncWrapper;
	use lightning::util::test_utils::TestStore;
	use lightning::util::wakers::Notifier;

	use alloc::collections::VecDeque;

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

	type TestClient =
		LSPS2ClientHandler<Arc<UniqueTestEntropy>, Arc<KVStoreSyncWrapper<Arc<TestStore>>>>;

	fn setup_test_client() -> (TestClient, PublicKey, PublicKey) {
		let test_entropy_source = Arc::new(UniqueTestEntropy { counter: AtomicU64::new(2) });
		let notifier = Arc::new(Notifier::new());
		let message_queue = Arc::new(MessageQueue::new(notifier));

		let kv_store = Arc::new(KVStoreSyncWrapper(Arc::new(TestStore::new(false))));
		let persist_notifier = Arc::new(Notifier::new());
		let event_queue = Arc::new(EventQueue::new(VecDeque::new(), kv_store, persist_notifier));
		let client = LSPS2ClientHandler::new(
			test_entropy_source,
			message_queue,
			event_queue,
			LSPS2ClientConfig::default(),
		);

		let secp = Secp256k1::new();
		let secret_key_1 = SecretKey::from_slice(&[42u8; 32]).unwrap();
		let secret_key_2 = SecretKey::from_slice(&[43u8; 32]).unwrap();
		let peer_1 = PublicKey::from_secret_key(&secp, &secret_key_1);
		let peer_2 = PublicKey::from_secret_key(&secp, &secret_key_2);

		(client, peer_1, peer_2)
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

	// Runs the full get_info + buy flow with the given peer and returns the negotiated
	// parameters.
	fn negotiate_opening_params(
		client: &TestClient, peer: PublicKey, min_fee_msat: u64,
	) -> LSPS2OpeningFeeParams {
		let opening_fee_params = dummy_opening_fee_params(min_fee_msat);

		let request_id = client.request_opening_params(peer, None);
		let response =
			LSPS2GetInfoResponse { opening_fee_params_menu: vec![opening_fee_params.clone()] };
		client.handle_get_info_response(request_id, &peer, response).unwrap();

		let request_id =
			client.select_opening_params(peer, Some(1_000), opening_fee_params.clone()).unwrap();
		client.handle_buy_response(request_id, &peer, dummy_buy_response()).unwrap();

		opening_fee_params
	}

	#[test]
	fn stores_latest_opening_params_per_lsp() {
		let (client, peer_1, peer_2) = setup_test_client();

		assert!(client.latest_opening_params().is_empty());

		// Receiving an opening fee params menu alone doesn't store any parameters.
		let request_id = client.request_opening_params(peer_1, None);
		let menu = vec![dummy_opening_fee_params(42)];
		let response = LSPS2GetInfoResponse { opening_fee_params_menu: menu };
		client.handle_get_info_response(request_id, &peer_1, response).unwrap();
		assert!(client.latest_opening_params().is_empty());

		// Neither does selecting parameters, until the LSP confirms the buy request.
		let params_1 = dummy_opening_fee_params(100);
		let request_id =
			client.select_opening_params(peer_1, Some(1_000), params_1.clone()).unwrap();
		assert!(client.latest_opening_params().is_empty());

		// A buy response for an unknown request id is rejected and doesn't store any parameters.
		let unknown_request_id = LSPSRequestId("unknown:request:id".to_string());
		assert!(client
			.handle_buy_response(unknown_request_id, &peer_1, dummy_buy_response())
			.is_err());
		assert!(client.latest_opening_params().is_empty());

		// Once the LSP confirms the buy request, the selected parameters are stored.
		client.handle_buy_response(request_id, &peer_1, dummy_buy_response()).unwrap();
		assert_eq!(client.latest_opening_params(), vec![(peer_1, params_1.clone())]);

		// Parameters are stored on a per-LSP basis.
		let params_2 = negotiate_opening_params(&client, peer_2, 300);
		let latest_opening_params = client.latest_opening_params();
		assert_eq!(latest_opening_params.len(), 2);
		assert!(latest_opening_params.contains(&(peer_1, params_1)));
		assert!(latest_opening_params.contains(&(peer_2, params_2.clone())));

		// Parameters negotiated in a subsequent buy flow replace the previously stored ones.
		let params_3 = negotiate_opening_params(&client, peer_1, 400);
		let latest_opening_params = client.latest_opening_params();
		assert_eq!(latest_opening_params.len(), 2);
		assert!(latest_opening_params.contains(&(peer_1, params_3)));
		assert!(latest_opening_params.contains(&(peer_2, params_2)));
	}

	#[test]
	fn clears_latest_opening_params() {
		let (client, peer_1, peer_2) = setup_test_client();

		// Clearing parameters for an unknown peer is a no-op.
		client.clear_latest_opening_params(&peer_1);
		assert!(client.latest_opening_params().is_empty());

		let _params_1 = negotiate_opening_params(&client, peer_1, 100);
		let params_2 = negotiate_opening_params(&client, peer_2, 300);

		client.clear_latest_opening_params(&peer_1);
		assert_eq!(client.latest_opening_params(), vec![(peer_2, params_2)]);

		// As we wiped the only state we held for `peer_1`, its entry should have been pruned
		// entirely.
		assert!(!client.per_peer_state.read().unwrap().contains_key(&peer_1));

		// Clearing the parameters of a peer with pending requests wipes the parameters but keeps
		// the remaining peer state around.
		let _pending_request_id = client.request_opening_params(peer_2, None);
		client.clear_latest_opening_params(&peer_2);
		assert!(client.latest_opening_params().is_empty());
		assert!(client.per_peer_state.read().unwrap().contains_key(&peer_2));
	}
}
