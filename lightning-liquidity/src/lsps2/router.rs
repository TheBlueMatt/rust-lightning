// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains an bLIP-52 / LSPS2-aware [`Router`] that injects JIT-channel blinded payment paths.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use lightning::blinded_path::payment::{
	BlindedPaymentPath, ForwardTlvs, PaymentConstraints, PaymentContext, PaymentForwardNode,
	PaymentRelay, ReceiveTlvs,
};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{PaymentId, MIN_FINAL_CLTV_EXPIRY_DELTA};
use lightning::routing::router::{InFlightHtlcs, Route, RouteParameters, Router};
use lightning::sign::{EntropySource, ReceiveAuthKey};
use lightning::types::features::BlindedHopFeatures;
use lightning::types::payment::PaymentHash;
use lightning::util::persist::KVStore;
use lightning::util::ser::Writeable;

use crate::lsps2::client::{LSPS2ClientHandler, LSPS2InvoiceParameters};
use crate::lsps2::utils::is_expired_opening_fee_params;
use crate::sync::{Arc, RwLock};

/// The [`PaymentContext::payment_metadata`] key under which we encode the
/// [`LSPS2InvoiceParameters`] used to construct a JIT-channel blinded payment path.
///
/// LDK features use metadata keys in the range 128-256 to reduce the chance of conflicts with
/// application-set entries. Here, we use 128 plus the LSPS2 protocol number.
pub const LSPS2_PAYMENT_METADATA_KEY: u64 = 128 + 2;

/// A [`Router`] wrapper that injects bLIP-52 / LSPS2 JIT-channel blinded payment paths based on
/// the latest invoice parameters negotiated with each LSP, while delegating all other routing
/// behavior to the wrapped inner router.
///
/// For blinded payment paths (i.e., in BOLT12 invoices), it appends paths using the LSPS2
/// intercept SCID as the forwarding hop so that the LSP can intercept the HTLC and open a JIT
/// channel. Paths from the inner router (e.g., through pre-existing channels) are included as
/// well, allowing payers to use existing inbound liquidity when available.
///
/// Before constructing a JIT-channel path, the used [`LSPS2InvoiceParameters`] are encoded into
/// the path's [`PaymentContext::payment_metadata`] under [`LSPS2_PAYMENT_METADATA_KEY`]. As the
/// metadata is handed back to us by the payer, this allows to, e.g., verify the fee skimmed for
/// the channel open against the negotiated opening fee parameters upon receipt.
///
/// As the [`LSPS2ClientHandler`] holding the negotiated parameters usually can only be built
/// *after* the [`Router`] (the [`LiquidityManager`] requires access to the channel manager, which
/// itself requires a router), the handler is wired up after construction via
/// [`Self::set_lsps2_client_handler`]. Until then, the wrapper simply delegates to the inner
/// router.
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub struct LSPS2Router<R: Router, ES: EntropySource, K: KVStore + Clone> {
	inner_router: R,
	lsps2_client_handler: RwLock<Option<Arc<LSPS2ClientHandler<ES, K>>>>,
}

impl<R: Router, ES: EntropySource, K: KVStore + Clone> LSPS2Router<R, ES, K> {
	/// Constructs a new wrapper around `inner_router`.
	pub fn new(inner_router: R) -> Self {
		Self { inner_router, lsps2_client_handler: RwLock::new(None) }
	}

	/// Wires up the given LSPS2 client handler whose latest negotiated invoice parameters will be
	/// used to construct JIT-channel blinded payment paths.
	///
	/// A shareable handle to the handler can be retrieved via
	/// [`LiquidityManager::lsps2_client_handler_arc`].
	///
	/// [`LiquidityManager::lsps2_client_handler_arc`]: crate::LiquidityManager::lsps2_client_handler_arc
	pub fn set_lsps2_client_handler(&self, lsps2_client_handler: Arc<LSPS2ClientHandler<ES, K>>) {
		*self.lsps2_client_handler.write().unwrap() = Some(lsps2_client_handler);
	}
}

fn inject_payment_metadata(tlvs: &mut ReceiveTlvs, invoice_params: &LSPS2InvoiceParameters) {
	let encoded_params = invoice_params.encode();
	let payment_metadata = match &mut tlvs.payment_context {
		PaymentContext::Bolt12Offer(context) => &mut context.payment_metadata,
		PaymentContext::AsyncBolt12Offer(context) => &mut context.payment_metadata,
		PaymentContext::Bolt12Refund(context) => &mut context.payment_metadata,
	};
	payment_metadata
		.get_or_insert_with(BTreeMap::new)
		.insert(LSPS2_PAYMENT_METADATA_KEY, encoded_params);
}

impl<R: Router, ES: EntropySource, K: KVStore + Clone> Router for LSPS2Router<R, ES, K> {
	fn find_route(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		self.inner_router.find_route(payer, route_params, first_hops, inflight_htlcs)
	}

	fn find_route_with_id(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
		payment_hash: PaymentHash, payment_id: PaymentId,
	) -> Result<Route, &'static str> {
		self.inner_router.find_route_with_id(
			payer,
			route_params,
			first_hops,
			inflight_htlcs,
			payment_hash,
			payment_id,
		)
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, local_node_receive_key: ReceiveAuthKey,
		first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs, amount_msats: Option<u64>,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		// Retrieve paths through existing channels from the inner router.
		let inner_res = self.inner_router.create_blinded_payment_paths(
			recipient,
			local_node_receive_key,
			first_hops,
			tlvs.clone(),
			amount_msats,
			secp_ctx,
		);

		let handler_lock = self.lsps2_client_handler.read().unwrap();
		let lsps2_client_handler = match handler_lock.as_ref() {
			Some(lsps2_client_handler) => lsps2_client_handler,
			None => return inner_res,
		};

		// JIT-channel paths are applicable both to normal offers and async offers that resolve
		// via a static invoice server. In both cases the intercept SCID lets the LSP intercept
		// the HTLC and open the JIT channel before forwarding the payment.
		match tlvs.payment_context {
			PaymentContext::Bolt12Offer(_) | PaymentContext::AsyncBolt12Offer(_) => {},
			_ => return inner_res,
		}

		// Add paths with intercept SCIDs to have the payer use them when sending payments,
		// prompting the LSP node to intercept the HTLCs, hence triggering a JIT channel open. We
		// however also keep the inner router's paths so the payer can use pre-existing inbound
		// liquidity when available rather than always triggering a JIT channel open. As BOLT12
		// specifies that paths should be ordered by preference, adding JIT paths to the end of
		// the list *should* have the payer prefer pre-existing channels. However, there of course
		// is no guarantee that the payer's router will actually process the paths in this exact
		// order.
		let mut paths = inner_res.unwrap_or_default();
		for invoice_params in lsps2_client_handler.latest_invoice_params() {
			if is_expired_opening_fee_params(&invoice_params.opening_fee_params) {
				continue;
			}

			if let Some(amount_msats) = amount_msats {
				let opening_fee_params = &invoice_params.opening_fee_params;
				if amount_msats < opening_fee_params.min_payment_size_msat
					|| amount_msats > opening_fee_params.max_payment_size_msat
				{
					continue;
				}
			}

			// Note the value is provided by the LSP, so we simply skip bogus values that would
			// overflow the wire encoding.
			let cltv_expiry_delta = match invoice_params.cltv_expiry_delta.try_into() {
				Ok(cltv_expiry_delta) => cltv_expiry_delta,
				Err(_) => continue,
			};

			let payment_relay = PaymentRelay {
				cltv_expiry_delta,
				fee_proportional_millionths: 0,
				fee_base_msat: 0,
			};
			let payment_constraints = PaymentConstraints {
				max_cltv_expiry: tlvs
					.payment_constraints
					.max_cltv_expiry
					.saturating_add(invoice_params.cltv_expiry_delta),
				htlc_minimum_msat: 0,
			};

			let forward_node = PaymentForwardNode {
				tlvs: ForwardTlvs {
					short_channel_id: invoice_params.intercept_scid,
					payment_relay,
					payment_constraints,
					features: BlindedHopFeatures::empty(),
					next_blinding_override: None,
				},
				node_id: invoice_params.counterparty_node_id,
				htlc_maximum_msat: u64::MAX,
			};

			// Encode the used parameters in the path's payment metadata so we have access to them
			// again when receiving the payment.
			let mut tlvs = tlvs.clone();
			inject_payment_metadata(&mut tlvs, &invoice_params);

			// We deliberately use `BlindedPaymentPath::new` without dummy hops here. Since the
			// LSP is a publicly-exposed introduction node and already knows the recipient, adding
			// dummy hops would not provide meaningful privacy benefits in the LSPS2 JIT-channel
			// context.
			let path_res = BlindedPaymentPath::new(
				&[forward_node],
				recipient,
				local_node_receive_key,
				tlvs,
				u64::MAX,
				MIN_FINAL_CLTV_EXPIRY_DELTA,
				&lsps2_client_handler.entropy_source,
				secp_ctx,
			);
			match path_res {
				Ok(path) => paths.push(path),
				Err(()) => continue,
			}
		}

		if paths.is_empty() {
			return Err(());
		}

		Ok(paths)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::events::EventQueue;
	use crate::lsps0::ser::{LSPSDateTime, LSPSProtocolMessageHandler};
	use crate::lsps2::client::LSPS2ClientConfig;
	use crate::lsps2::msgs::{
		LSPS2BuyResponse, LSPS2InterceptScid, LSPS2Message, LSPS2OpeningFeeParams, LSPS2Response,
	};
	use crate::message_queue::MessageQueue;
	use crate::sync::Mutex;

	use bitcoin::network::Network;
	use bitcoin::secp256k1::SecretKey;

	use lightning::blinded_path::payment::{Bolt12OfferContext, Bolt12RefundContext};
	use lightning::blinded_path::{IntroductionNode, NodeIdLookUp};
	use lightning::offers::invoice_request::InvoiceRequestFields;
	use lightning::offers::offer::OfferId;
	use lightning::sign::{NodeSigner, Recipient};
	use lightning::types::payment::PaymentSecret;
	use lightning::util::persist::KVStoreSyncWrapper;
	use lightning::util::ser::Readable;
	use lightning::util::test_utils::{TestKeysInterface, TestStore};
	use lightning::util::wakers::Notifier;

	use alloc::collections::VecDeque;
	use alloc::string::ToString;

	use core::str::FromStr;
	use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
	type TestRouter =
		LSPS2Router<MockRouter, Arc<UniqueTestEntropy>, Arc<KVStoreSyncWrapper<Arc<TestStore>>>>;

	struct MockRouter {
		create_blinded_payment_paths_calls: AtomicUsize,
		paths_to_return: Mutex<Option<Vec<BlindedPaymentPath>>>,
	}

	impl MockRouter {
		fn new() -> Self {
			Self {
				create_blinded_payment_paths_calls: AtomicUsize::new(0),
				paths_to_return: Mutex::new(None),
			}
		}

		fn create_blinded_payment_paths_calls(&self) -> usize {
			self.create_blinded_payment_paths_calls.load(Ordering::Acquire)
		}
	}

	impl Router for MockRouter {
		fn find_route(
			&self, _payer: &PublicKey, _route_params: &RouteParameters,
			_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs,
		) -> Result<Route, &'static str> {
			Err("mock router")
		}

		fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
			&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
			_first_hops: Vec<ChannelDetails>, _tlvs: ReceiveTlvs, _amount_msats: Option<u64>,
			_secp_ctx: &Secp256k1<T>,
		) -> Result<Vec<BlindedPaymentPath>, ()> {
			self.create_blinded_payment_paths_calls.fetch_add(1, Ordering::AcqRel);
			match self.paths_to_return.lock().unwrap().take() {
				Some(paths) => Ok(paths),
				None => Err(()),
			}
		}
	}

	struct RecordingLookup {
		next_node_id: PublicKey,
		short_channel_id: Mutex<Option<u64>>,
	}

	impl NodeIdLookUp for RecordingLookup {
		fn next_node_id(&self, short_channel_id: u64) -> Option<PublicKey> {
			*self.short_channel_id.lock().unwrap() = Some(short_channel_id);
			Some(self.next_node_id)
		}
	}

	fn setup_test_client() -> TestClient {
		let test_entropy_source = Arc::new(UniqueTestEntropy { counter: AtomicU64::new(2) });
		let notifier = Arc::new(Notifier::new());
		let message_queue = Arc::new(MessageQueue::new(notifier));

		let kv_store = Arc::new(KVStoreSyncWrapper(Arc::new(TestStore::new(false))));
		let persist_notifier = Arc::new(Notifier::new());
		let event_queue =
			Arc::new(EventQueue::new(VecDeque::new(), kv_store.clone(), persist_notifier));
		LSPS2ClientHandler::new(
			crate::prelude::new_hash_map(),
			test_entropy_source,
			message_queue,
			event_queue,
			kv_store,
			LSPS2ClientConfig::default(),
		)
	}

	fn setup_test_router() -> (TestRouter, Arc<TestClient>) {
		let client = Arc::new(setup_test_client());
		let router = LSPS2Router::new(MockRouter::new());
		router.set_lsps2_client_handler(Arc::clone(&client));
		(router, client)
	}

	fn pubkey(byte: u8) -> PublicKey {
		let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
		PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
	}

	fn dummy_opening_fee_params(valid_until: &str) -> LSPS2OpeningFeeParams {
		LSPS2OpeningFeeParams {
			min_fee_msat: 100,
			proportional: 21,
			valid_until: LSPSDateTime::from_str(valid_until).unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1_000,
			max_payment_size_msat: 100_000_000,
			promise: "promise".to_string(),
		}
	}

	// Negotiates invoice parameters with the given LSP via the client handler's public API.
	fn negotiate_invoice_params(
		client: &TestClient, counterparty_node_id: PublicKey, intercept_scid: u64,
		cltv_expiry_delta: u32, valid_until: &str,
	) -> LSPS2InvoiceParameters {
		let opening_fee_params = dummy_opening_fee_params(valid_until);
		let request_id = client
			.select_opening_params(counterparty_node_id, Some(5_000), opening_fee_params.clone())
			.unwrap();
		let buy_response = LSPS2BuyResponse {
			jit_channel_scid: LSPS2InterceptScid::from(intercept_scid),
			lsp_cltv_expiry_delta: cltv_expiry_delta,
			client_trusts_lsp: false,
		};
		let message = LSPS2Message::Response(request_id, LSPS2Response::Buy(buy_response));
		client.handle_message(message, &counterparty_node_id).unwrap();

		LSPS2InvoiceParameters {
			counterparty_node_id,
			intercept_scid,
			cltv_expiry_delta,
			opening_fee_params,
		}
	}

	fn bolt12_offer_tlvs() -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
				offer_id: OfferId([8; 32]),
				payment_metadata: None,
				invoice_request: InvoiceRequestFields {
					payer_signing_pubkey: pubkey(9),
					quantity: None,
					payer_note_truncated: None,
					human_readable_name: None,
				},
			}),
		}
	}

	fn bolt12_refund_tlvs() -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {
				payment_metadata: None,
			}),
		}
	}

	#[test]
	fn delegates_route_finding() {
		let (router, _client) = setup_test_router();

		let route_params = RouteParameters::from_payment_params_and_value(
			lightning::routing::router::PaymentParameters::from_node_id(pubkey(10), 144),
			1_000,
		);
		let res = router.find_route(&pubkey(9), &route_params, None, InFlightHtlcs::new());
		assert_eq!(res.err(), Some("mock router"));

		let res = router.find_route_with_id(
			&pubkey(9),
			&route_params,
			None,
			InFlightHtlcs::new(),
			PaymentHash([0; 32]),
			PaymentId([0; 32]),
		);
		assert_eq!(res.err(), Some("mock router"));
	}

	#[test]
	fn delegates_when_no_client_handler_is_set() {
		let router: TestRouter = LSPS2Router::new(MockRouter::new());
		let secp_ctx = Secp256k1::new();

		let res = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(),
			Some(10_000),
			&secp_ctx,
		);

		assert!(res.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn delegates_when_no_params_were_negotiated() {
		let (router, _client) = setup_test_router();
		let secp_ctx = Secp256k1::new();

		let res = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(),
			Some(10_000),
			&secp_ctx,
		);

		assert!(res.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn delegates_when_context_is_not_bolt12_offer() {
		let (router, client) = setup_test_router();
		let secp_ctx = Secp256k1::new();

		negotiate_invoice_params(&client, pubkey(11), 42, 48, "2035-05-20T08:30:45Z");

		let res = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_refund_tlvs(),
			Some(10_000),
			&secp_ctx,
		);

		assert!(res.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn creates_jit_channel_paths_from_stored_params() {
		let (router, client) = setup_test_router();
		let secp_ctx = Secp256k1::new();

		let lsp_keys = TestKeysInterface::new(&[43; 32], Network::Testnet);
		let lsp_node_id = lsp_keys.get_node_id(Recipient::Node).unwrap();

		let intercept_scid = 42;
		let cltv_expiry_delta = 48;
		negotiate_invoice_params(
			&client,
			lsp_node_id,
			intercept_scid,
			cltv_expiry_delta,
			"2035-05-20T08:30:45Z",
		);

		let recipient = pubkey(10);
		let mut paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs(),
				Some(5_000),
				&secp_ctx,
			)
			.unwrap();

		assert_eq!(paths.len(), 1);
		let mut path = paths.pop().unwrap();
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(lsp_node_id));
		assert_eq!(path.payinfo.fee_base_msat, 0);
		assert_eq!(path.payinfo.fee_proportional_millionths, 0);
		assert_eq!(
			path.payinfo.cltv_expiry_delta,
			cltv_expiry_delta as u16 + MIN_FINAL_CLTV_EXPIRY_DELTA
		);

		// Advancing the path through the LSP hop reveals the intercept SCID it forwards over.
		let lookup =
			RecordingLookup { next_node_id: recipient, short_channel_id: Mutex::new(None) };
		path.advance_path_by_one(&lsp_keys, &lookup, &secp_ctx).unwrap();
		assert_eq!(*lookup.short_channel_id.lock().unwrap(), Some(intercept_scid));
	}

	#[test]
	fn includes_inner_router_paths_alongside_jit_channel_paths() {
		let (router, client) = setup_test_router();
		let secp_ctx = Secp256k1::new();
		let recipient = pubkey(10);

		// Pre-create a blinded path as if the inner router built it from an existing channel.
		let existing_path = BlindedPaymentPath::new(
			&[],
			recipient,
			ReceiveAuthKey([3; 32]),
			bolt12_offer_tlvs(),
			u64::MAX,
			MIN_FINAL_CLTV_EXPIRY_DELTA,
			&UniqueTestEntropy { counter: AtomicU64::new(2) },
			&secp_ctx,
		)
		.unwrap();
		*router.inner_router.paths_to_return.lock().unwrap() = Some(vec![existing_path]);

		negotiate_invoice_params(&client, pubkey(11), 42, 48, "2035-05-20T08:30:45Z");

		let paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs(),
				Some(5_000),
				&secp_ctx,
			)
			.unwrap();

		// Should contain both the inner router's existing channel path and the JIT-channel path,
		// in that order, as BOLT12 orders paths by preference.
		assert_eq!(paths.len(), 2);
		assert_eq!(paths[1].introduction_node(), &IntroductionNode::NodeId(pubkey(11)));
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn skips_params_when_amount_is_out_of_bounds() {
		let (router, client) = setup_test_router();
		let secp_ctx = Secp256k1::new();

		// The dummy opening fee params allow payment sizes within [1_000, 100_000_000] msat.
		negotiate_invoice_params(&client, pubkey(11), 42, 48, "2035-05-20T08:30:45Z");

		for amount_msats in [Some(999), Some(100_000_001)] {
			let res = router.create_blinded_payment_paths(
				pubkey(10),
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs(),
				amount_msats,
				&secp_ctx,
			);
			assert!(res.is_err());
		}

		// Amounts within bounds and unknown amounts are fine.
		for amount_msats in [Some(1_000), Some(100_000_000), None] {
			let paths = router
				.create_blinded_payment_paths(
					pubkey(10),
					ReceiveAuthKey([3; 32]),
					Vec::new(),
					bolt12_offer_tlvs(),
					amount_msats,
					&secp_ctx,
				)
				.unwrap();
			assert_eq!(paths.len(), 1);
		}
	}

	#[test]
	#[cfg(feature = "time")]
	fn skips_expired_params() {
		let (router, client) = setup_test_router();
		let secp_ctx = Secp256k1::new();

		negotiate_invoice_params(&client, pubkey(11), 42, 48, "2023-05-20T08:30:45Z");

		let res = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(),
			Some(5_000),
			&secp_ctx,
		);
		assert!(res.is_err());
	}

	#[test]
	fn skips_params_with_bogus_cltv_expiry_delta() {
		let (router, client) = setup_test_router();
		let secp_ctx = Secp256k1::new();

		negotiate_invoice_params(
			&client,
			pubkey(11),
			42,
			u16::MAX as u32 + 1,
			"2035-05-20T08:30:45Z",
		);

		let res = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(),
			Some(5_000),
			&secp_ctx,
		);
		assert!(res.is_err());
	}

	#[test]
	fn injects_params_into_payment_metadata() {
		let invoice_params = LSPS2InvoiceParameters {
			counterparty_node_id: pubkey(11),
			intercept_scid: 42,
			cltv_expiry_delta: 48,
			opening_fee_params: dummy_opening_fee_params("2035-05-20T08:30:45Z"),
		};

		let mut tlvs = bolt12_offer_tlvs();
		inject_payment_metadata(&mut tlvs, &invoice_params);

		let payment_metadata = match &tlvs.payment_context {
			PaymentContext::Bolt12Offer(context) => context.payment_metadata.as_ref().unwrap(),
			_ => panic!("Unexpected payment context"),
		};
		let encoded_params = payment_metadata.get(&LSPS2_PAYMENT_METADATA_KEY).unwrap();
		let mut reader = &encoded_params[..];
		let decoded_params = LSPS2InvoiceParameters::read(&mut reader).unwrap();
		assert_eq!(decoded_params, invoice_params);

		// Injecting into pre-existing metadata leaves other entries untouched.
		let mut tlvs = bolt12_offer_tlvs();
		match &mut tlvs.payment_context {
			PaymentContext::Bolt12Offer(context) => {
				let mut metadata = BTreeMap::new();
				metadata.insert(42, alloc::vec![0xff]);
				context.payment_metadata = Some(metadata);
			},
			_ => panic!("Unexpected payment context"),
		}
		inject_payment_metadata(&mut tlvs, &invoice_params);
		let payment_metadata = match &tlvs.payment_context {
			PaymentContext::Bolt12Offer(context) => context.payment_metadata.as_ref().unwrap(),
			_ => panic!("Unexpected payment context"),
		};
		assert_eq!(payment_metadata.len(), 2);
		assert_eq!(payment_metadata.get(&42).unwrap(), &alloc::vec![0xff]);
	}
}
