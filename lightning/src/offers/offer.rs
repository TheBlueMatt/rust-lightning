// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `offer` messages.
//!
//! An [`Offer`] represents an "offer to be paid." It is typically constructed by a merchant and
//! published as a QR code to be scanned by a customer. The customer uses the offer to request an
//! invoice from the merchant to be paid.
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::num::NonZeroU64;
//! use core::time::Duration;
//!
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::offer::{Amount, OfferBuilder};
//!
//! # use bitcoin::secp256k1;
//! # use lightning::onion_message::BlindedPath;
//! # #[cfg(feature = "std")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedPath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedPath { unimplemented!() }
//! #
//! # #[cfg(feature = "std")]
//! # fn build() -> Result<(), secp256k1::Error> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//!
//! let one_item = NonZeroU64::new(1).unwrap();
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let offer = OfferBuilder::new("coffee, large".to_string(), pubkey)
//!     .amount(Amount::Bitcoin { amount_msats: 20_000 })
//!     .quantity_range(one_item..)
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer("Foo Bar".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .build()
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use core::num::NonZeroU64;
use core::ops::{Bound, RangeBounds};
use core::time::Duration;
use io;
use ln::features::OfferFeatures;
use ln::msgs::MAX_VALUE_MSAT;
use onion_message::BlindedPath;
use util::ser::{Writeable, Writer};

use prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

/// Builds an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
pub struct OfferBuilder {
	offer: OfferContents,
}

impl OfferBuilder {
	/// Creates a new builder for an offer setting the [`Offer::description`] and using the
	/// [`Offer::signing_pubkey`] for signing invoices. The associated secret key must be remembered
	/// while the offer is valid.
	///
	/// Use a different pubkey per offer to avoid correlating offers.
	pub fn new(description: String, signing_pubkey: PublicKey) -> Self {
		let offer = OfferContents {
			chains: None, metadata: None, amount: None, description,
			features: OfferFeatures::empty(), absolute_expiry: None, issuer: None, paths: None,
			quantity_min: None, quantity_max: None, signing_pubkey: Some(signing_pubkey),
		};
		OfferBuilder { offer }
	}

	/// Adds the chain hash of the given [`Network`] to [`Offer::chains`]. If not called,
	/// the chain hash of [`Network::Bitcoin`] is assumed to be the only one supported.
	///
	/// Successive calls to this method will add another chain hash.
	pub fn chain(mut self, network: Network) -> Self {
		let chains = self.offer.chains.get_or_insert_with(Vec::new);
		let chain = ChainHash::using_genesis_block(network);
		if !chains.contains(&chain) {
			chains.push(chain);
		}

		self
	}

	/// Sets the [`Offer::metadata`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn metadata(mut self, metadata: Vec<u8>) -> Self {
		self.offer.metadata = Some(metadata);
		self
	}

	/// Sets the [`Offer::amount`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn amount(mut self, amount: Amount) -> Self {
		self.offer.amount = Some(amount);
		self
	}

	/// Sets the [`Offer::features`].
	///
	/// Successive calls to this method will override the previous setting.
	#[cfg(test)]
	pub fn features(mut self, features: OfferFeatures) -> Self {
		self.offer.features = features;
		self
	}

	/// Sets the [`Offer::absolute_expiry`] as seconds since the Unix epoch. Any expiry that has
	/// already passed is valid and can be checked for using [`Offer::is_expired`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn absolute_expiry(mut self, absolute_expiry: Duration) -> Self {
		self.offer.absolute_expiry = Some(absolute_expiry);
		self
	}

	/// Sets the [`Offer::issuer`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn issuer(mut self, issuer: String) -> Self {
		self.offer.issuer = Some(issuer);
		self
	}

	/// Adds a blinded path to [`Offer::paths`].
	///
	/// Successive calls to this method will add another blinded path. Caller is responsible for not
	/// adding duplicate paths.
	pub fn path(mut self, path: BlindedPath) -> Self {
		self.offer.paths.get_or_insert_with(Vec::new).push(path);
		self
	}

	/// Sets a fixed quantity of items for [`Offer::quantity_min`] and [`Offer::quantity_max`]. If
	/// not set, `1` is assumed.
	///
	/// Successive calls to this method or [`quantity_range`] will override the previous setting.
	///
	/// [`quantity_range`]: Self::quantity_range
	pub fn quantity_fixed(mut self, quantity: NonZeroU64) -> Self {
		let quantity = Some(quantity.get()).filter(|quantity| *quantity != 1);
		self.offer.quantity_min = quantity;
		self.offer.quantity_max = quantity;
		self
	}

	/// Sets a quantity range of items for [`Offer::quantity_min`] and [`Offer::quantity_max`]. If
	/// not set, `1` is assumed.
	///
	/// Successive calls to this method or [`quantity_fixed`] will override the previous setting.
	///
	/// [`quantity_fixed`]: Self::quantity_fixed
	pub fn quantity_range<R: RangeBounds<NonZeroU64>>(mut self, quantity: R) -> Self {
		self.offer.quantity_min = match quantity.start_bound() {
			Bound::Included(n) => Some(n.get()),
			Bound::Excluded(_) => panic!("Bound::Excluded not supported for start_bound"),
			Bound::Unbounded => Some(1),
		};
		self.offer.quantity_max = match quantity.end_bound() {
			Bound::Included(n) => Some(n.get()),
			Bound::Excluded(n) => Some(n.get() - 1),
			Bound::Unbounded => None,
		};

		// Use a minimal encoding whenever 1 can be inferred.
		if let Some(1) = self.offer.quantity_min {
			match self.offer.quantity_max {
				Some(1) => {
					self.offer.quantity_min = None;
					self.offer.quantity_max = None;
				},
				Some(_) => {
					self.offer.quantity_min = None;
				},
				None => {},
			}
		}

		self
	}

	/// Builds an [`Offer`] from the builder's settings.
	pub fn build(self) -> Result<Offer, ()> {
		if let Some(Amount::Currency { .. }) = self.offer.amount {
			return Err(());
		}

		if self.offer.amount_msats() > MAX_VALUE_MSAT {
			return Err(());
		}

		if self.offer.quantity_min() > self.offer.quantity_max() {
			return Err(());
		}

		let mut bytes = Vec::new();
		self.offer.write(&mut bytes).unwrap();

		Ok(Offer {
			bytes,
			contents: self.offer,
		})
	}
}

/// An `Offer` is a potentially long-lived proposal for payment of a good or service.
///
/// An offer is precursor to an `InvoiceRequest`. A merchant publishes an offer from which a
/// customer may request an `Invoice` for a specific quantity and using an amount enough to cover
/// that quantity (i.e., at least `quantity * amount`). See [`Offer::amount`].
///
/// Offers may be denominated in currency other than bitcoin but are ultimately paid using the
/// latter.
///
/// Through the use of [`BlindedPath`]s, offers provide recipient privacy.
#[derive(Clone, Debug)]
pub struct Offer {
	// The serialized offer. Needed when creating an `InvoiceRequest` if the offer contains unknown
	// fields.
	bytes: Vec<u8>,
	contents: OfferContents,
}

/// The contents of an [`Offer`], which may be shared with an `InvoiceRequest` or an `Invoice`.
#[derive(Clone, Debug)]
pub(crate) struct OfferContents {
	chains: Option<Vec<ChainHash>>,
	metadata: Option<Vec<u8>>,
	amount: Option<Amount>,
	description: String,
	features: OfferFeatures,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedPath>>,
	quantity_min: Option<u64>,
	quantity_max: Option<u64>,
	signing_pubkey: Option<PublicKey>,
}

impl Offer {
	// TODO: Return a slice once ChainHash has constants.
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1283
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1286
	/// The chains that may be used when paying a requested invoice.
	pub fn chains(&self) -> Vec<ChainHash> {
		self.contents.chains
			.as_ref()
			.cloned()
			.unwrap_or_else(|| vec![ChainHash::using_genesis_block(Network::Bitcoin)])
	}

	// TODO: Link to corresponding method in `InvoiceRequest`.
	/// Metadata set by the originator. Useful for authentication and validating fields since it is
	/// reflected in `invoice_request` messages along with all the other fields from the `offer`.
	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.contents.metadata.as_ref()
	}

	/// The minimum amount required for a successful payment of a single item.
	pub fn amount(&self) -> Option<&Amount> {
		self.contents.amount.as_ref()
	}

	/// A complete description of the purpose of the payment.
	pub fn description(&self) -> &str {
		&self.contents.description
	}

	/// Features pertaining to the offer.
	pub fn features(&self) -> &OfferFeatures {
		&self.contents.features
	}

	/// Duration since the Unix epoch when an invoice should no longer be requested.
	///
	/// If `None`, the offer does not expire.
	pub fn absolute_expiry(&self) -> Option<Duration> {
		self.contents.absolute_expiry
	}

	/// Whether the offer has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		match self.absolute_expiry() {
			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
				Ok(elapsed) => elapsed > seconds_from_epoch,
				Err(_) => false,
			},
			None => false,
		}
	}

	/// The issuer of the offer, possibly beginning with `user@domain` or `domain`. Intended to be
	/// displayed to the user, so should be human-readable.
	pub fn issuer(&self) -> Option<&str> {
		self.contents.issuer.as_ref().map(|issuer| issuer.as_str())
	}

	/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
	/// recipient privacy by obfuscating its node id.
	pub fn paths(&self) -> &[BlindedPath] {
		self.contents.paths.as_ref().map(|paths| paths.as_slice()).unwrap_or(&[])
	}

	/// The minimum quantity of items supported.
	pub fn quantity_min(&self) -> u64 {
		self.contents.quantity_min()
	}

	/// The maximum quantity of items supported.
	pub fn quantity_max(&self) -> u64 {
		self.contents.quantity_max()
	}

	/// The public key used by the recipient to sign invoices.
	pub fn signing_pubkey(&self) -> PublicKey {
		self.contents.signing_pubkey.unwrap()
	}

	#[cfg(test)]
	fn as_tlv_stream(&self) -> OfferTlvStreamRef {
		self.contents.as_tlv_stream()
	}
}

impl OfferContents {
	pub fn amount_msats(&self) -> u64 {
		self.amount.as_ref().map(Amount::as_msats).unwrap_or(0)
	}

	pub fn quantity_min(&self) -> u64 {
		self.quantity_min.unwrap_or(1)
	}

	pub fn quantity_max(&self) -> u64 {
		self.quantity_max.unwrap_or_else(||
			self.quantity_min.map_or(1, |_| u64::max_value()))
	}

	fn as_tlv_stream(&self) -> OfferTlvStreamRef {
		let (currency, amount) = match &self.amount {
			None => (None, None),
			Some(Amount::Bitcoin { amount_msats }) => (None, Some(*amount_msats)),
			Some(Amount::Currency { iso4217_code, amount }) => (
				Some(iso4217_code), Some(*amount)
			),
		};

		let features = {
			if self.features == OfferFeatures::empty() { None } else { Some(&self.features) }
		};

		OfferTlvStreamRef {
			chains: self.chains.as_ref(),
			metadata: self.metadata.as_ref(),
			currency,
			amount,
			description: Some(&self.description),
			features,
			absolute_expiry: self.absolute_expiry.map(|duration| duration.as_secs()),
			paths: self.paths.as_ref(),
			issuer: self.issuer.as_ref(),
			quantity_min: self.quantity_min,
			quantity_max: self.quantity_max,
			node_id: self.signing_pubkey.as_ref(),
		}
	}
}

impl Writeable for OfferContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

/// The minimum amount required for an item in an [`Offer`], denominated in either bitcoin or
/// another currency.
#[derive(Clone, Debug, PartialEq)]
pub enum Amount {
	/// An amount of bitcoin.
	Bitcoin {
		/// The amount in millisatoshi.
		amount_msats: u64,
	},
	/// An amount of currency specified using ISO 4712.
	Currency {
		/// The currency that the amount is denominated in.
		iso4217_code: CurrencyCode,
		/// The amount in the currency unit adjusted by the ISO 4712 exponent (e.g., USD cents).
		amount: u64,
	},
}

impl Amount {
	/// Returns the amount in millisatoshi.
	pub fn as_msats(&self) -> u64 {
		match self {
			Amount::Currency { .. } => unimplemented!(),
			Amount::Bitcoin { amount_msats } => *amount_msats,
		}
	}
}

/// An ISO 4712 three-letter currency code (e.g., USD).
pub type CurrencyCode = [u8; 3];

tlv_stream!(OfferTlvStream, OfferTlvStreamRef, {
	(2, chains: Vec<ChainHash>),
	(4, metadata: Vec<u8>),
	(6, currency: CurrencyCode),
	(8, amount: u64),
	(10, description: String),
	(12, features: OfferFeatures),
	(14, absolute_expiry: u64),
	(16, paths: Vec<BlindedPath>),
	(18, issuer: String),
	(20, quantity_min: u64),
	(22, quantity_max: u64),
	(24, node_id: PublicKey),
});

#[cfg(test)]
mod tests {
	use super::{Amount, OfferBuilder};

	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::num::NonZeroU64;
	use core::time::Duration;
	use ln::features::OfferFeatures;
	use ln::msgs::MAX_VALUE_MSAT;
	use onion_message::{BlindedHop, BlindedPath};
	use util::ser::Writeable;

	fn pubkey(byte: u8) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
	}

	fn privkey(byte: u8) -> SecretKey {
		SecretKey::from_slice(&[byte; 32]).unwrap()
	}

	#[test]
	fn builds_offer_with_defaults() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42)).build().unwrap();
		let tlv_stream = offer.as_tlv_stream();
		let mut buffer = Vec::new();
		offer.contents.write(&mut buffer).unwrap();

		assert_eq!(offer.bytes, buffer.as_slice());
		assert_eq!(offer.chains(), vec![ChainHash::using_genesis_block(Network::Bitcoin)]);
		assert_eq!(offer.metadata(), None);
		assert_eq!(offer.amount(), None);
		assert_eq!(offer.description(), "foo");
		assert_eq!(offer.features(), &OfferFeatures::empty());
		assert_eq!(offer.absolute_expiry(), None);
		#[cfg(feature = "std")]
		assert!(!offer.is_expired());
		assert_eq!(offer.paths(), &[]);
		assert_eq!(offer.issuer(), None);
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(offer.signing_pubkey(), pubkey(42));

		assert_eq!(tlv_stream.chains, None);
		assert_eq!(tlv_stream.metadata, None);
		assert_eq!(tlv_stream.currency, None);
		assert_eq!(tlv_stream.amount, None);
		assert_eq!(tlv_stream.description, Some(&String::from("foo")));
		assert_eq!(tlv_stream.features, None);
		assert_eq!(tlv_stream.absolute_expiry, None);
		assert_eq!(tlv_stream.paths, None);
		assert_eq!(tlv_stream.issuer, None);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);
		assert_eq!(tlv_stream.node_id, Some(&pubkey(42)));
	}

	#[test]
	fn builds_offer_with_chains() {
		let chain = ChainHash::using_genesis_block(Network::Bitcoin);
		let chains = vec![
			ChainHash::using_genesis_block(Network::Bitcoin),
			ChainHash::using_genesis_block(Network::Testnet),
		];

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.chain(Network::Bitcoin)
			.build()
			.unwrap();
		assert_eq!(offer.chains(), vec![chain]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![chain]));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.chain(Network::Bitcoin)
			.chain(Network::Bitcoin)
			.build()
			.unwrap();
		assert_eq!(offer.chains(), vec![chain]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![chain]));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build()
			.unwrap();
		assert_eq!(offer.chains(), chains);
		assert_eq!(offer.as_tlv_stream().chains, Some(&chains));
	}

	#[test]
	fn builds_offer_with_metadata() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.metadata(vec![42; 32])
			.build()
			.unwrap();
		assert_eq!(offer.metadata(), Some(&vec![42; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some(&vec![42; 32]));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.metadata(vec![42; 32])
			.metadata(vec![43; 32])
			.build()
			.unwrap();
		assert_eq!(offer.metadata(), Some(&vec![43; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some(&vec![43; 32]));
	}

	#[test]
	fn builds_offer_with_amount() {
		let bitcoin_amount = Amount::Bitcoin { amount_msats: 1000 };
		let currency_amount = Amount::Currency { iso4217_code: *b"USD", amount: 10 };

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.amount(bitcoin_amount.clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.amount(), Some(&bitcoin_amount));
		assert_eq!(tlv_stream.amount, Some(1000));
		assert_eq!(tlv_stream.currency, None);

		let builder = OfferBuilder::new("foo".into(), pubkey(42))
			.amount(currency_amount.clone());
		let tlv_stream = builder.offer.as_tlv_stream();
		assert_eq!(builder.offer.amount.as_ref(), Some(&currency_amount));
		assert_eq!(tlv_stream.amount, Some(10));
		assert_eq!(tlv_stream.currency, Some(b"USD"));
		match builder.build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ()),
		}

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.amount(currency_amount.clone())
			.amount(bitcoin_amount.clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(tlv_stream.amount, Some(1000));
		assert_eq!(tlv_stream.currency, None);

		let invalid_amount = Amount::Bitcoin { amount_msats: MAX_VALUE_MSAT + 1 };
		match OfferBuilder::new("foo".into(), pubkey(42)).amount(invalid_amount).build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ()),
		}
	}

	#[test]
	fn builds_offer_with_features() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.features(OfferFeatures::unknown())
			.build()
			.unwrap();
		assert_eq!(offer.features(), &OfferFeatures::unknown());
		assert_eq!(offer.as_tlv_stream().features, Some(&OfferFeatures::unknown()));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.features(OfferFeatures::unknown())
			.features(OfferFeatures::empty())
			.build()
			.unwrap();
		assert_eq!(offer.features(), &OfferFeatures::empty());
		assert_eq!(offer.as_tlv_stream().features, None);
	}

	#[test]
	fn builds_offer_with_absolute_expiry() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.absolute_expiry(future_expiry)
			.build()
			.unwrap();
		#[cfg(feature = "std")]
		assert!(!offer.is_expired());
		assert_eq!(offer.absolute_expiry(), Some(future_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(future_expiry.as_secs()));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.absolute_expiry(future_expiry)
			.absolute_expiry(past_expiry)
			.build()
			.unwrap();
		#[cfg(feature = "std")]
		assert!(offer.is_expired());
		assert_eq!(offer.absolute_expiry(), Some(past_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(past_expiry.as_secs()));
	}

	#[test]
	fn builds_offer_with_paths() {
		let paths = vec![
			BlindedPath {
				introduction_node_id: pubkey(40),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				],
			},
			BlindedPath {
				introduction_node_id: pubkey(40),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				],
			},
		];

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.paths(), paths.as_slice());
		assert_eq!(offer.signing_pubkey(), pubkey(42));
		assert_ne!(pubkey(42), pubkey(44));
		assert_eq!(tlv_stream.paths, Some(&paths));
		assert_eq!(tlv_stream.node_id, Some(&pubkey(42)));
	}

	#[test]
	fn builds_offer_with_issuer() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.issuer("bar".into())
			.build()
			.unwrap();
		assert_eq!(offer.issuer(), Some("bar"));
		assert_eq!(offer.as_tlv_stream().issuer, Some(&String::from("bar")));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.issuer("bar".into())
			.issuer("baz".into())
			.build()
			.unwrap();
		assert_eq!(offer.issuer(), Some("baz"));
		assert_eq!(offer.as_tlv_stream().issuer, Some(&String::from("baz")));
	}

	#[test]
	fn builds_offer_with_fixed_quantity() {
		let one = NonZeroU64::new(1).unwrap();
		let five = NonZeroU64::new(5).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_fixed(one)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_fixed(ten)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 10);
		assert_eq!(offer.quantity_max(), 10);
		assert_eq!(tlv_stream.quantity_min, Some(10));
		assert_eq!(tlv_stream.quantity_max, Some(10));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_fixed(ten)
			.quantity_fixed(five)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 5);
		assert_eq!(tlv_stream.quantity_min, Some(5));
		assert_eq!(tlv_stream.quantity_max, Some(5));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(..ten)
			.quantity_fixed(five)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 5);
		assert_eq!(tlv_stream.quantity_min, Some(5));
		assert_eq!(tlv_stream.quantity_max, Some(5));
	}

	#[test]
	fn builds_offer_with_quantity_range() {
		let one = NonZeroU64::new(1).unwrap();
		let five = NonZeroU64::new(5).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(..)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), u64::max_value());
		assert_eq!(tlv_stream.quantity_min, Some(1));
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(..ten)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 9);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, Some(9));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(one..ten)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 9);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, Some(9));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(five..=ten)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 10);
		assert_eq!(tlv_stream.quantity_min, Some(5));
		assert_eq!(tlv_stream.quantity_max, Some(10));

		let one = NonZeroU64::new(1).unwrap();
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(one..=one)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 1);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(five..=five)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 5);
		assert_eq!(offer.quantity_max(), 5);
		assert_eq!(tlv_stream.quantity_min, Some(5));
		assert_eq!(tlv_stream.quantity_max, Some(5));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_fixed(five)
			.quantity_range(..ten)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.quantity_min(), 1);
		assert_eq!(offer.quantity_max(), 9);
		assert_eq!(tlv_stream.quantity_min, None);
		assert_eq!(tlv_stream.quantity_max, Some(9));

		assert!(OfferBuilder::new("foo".into(), pubkey(42))
			.quantity_range(ten..five)
			.build()
			.is_err()
		);
	}
}
