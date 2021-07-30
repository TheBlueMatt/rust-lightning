//! Abstractions for scripts used in the Lightning Network.

use bitcoin::bech32::u5;
use bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0 as SEGWIT_V0;
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::Hash;
use bitcoin::hash_types::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
use bitcoin::secp256k1::key::PublicKey;

use ln::features::InitFeatures;

use std::convert::TryFrom;
use core::num::NonZeroU8;

/// A script pubkey for shutting down a channel as defined by [BOLT #2].
///
/// [BOLT #2]: https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md
pub struct ShutdownScript(ShutdownScriptImpl);

/// An error occurring when converting from [`Script`] to [`ShutdownScript`].
#[derive(Debug)]
pub struct InvalidShutdownScript(Script);

enum ShutdownScriptImpl {
	/// [`PublicKey`] used to form a P2WPKH script pubkey. Used to support backward-compatible
	/// serialization.
	Legacy(PublicKey),

	/// [`Script`] adhering to a script pubkey format specified in BOLT #2.
	Bolt2(Script),
}

impl ShutdownScript {
	/// Generates a P2WPKH script pubkey from the given [`PublicKey`].
	pub fn new_p2wpkh_from_pubkey(pubkey: PublicKey) -> Self {
		Self(ShutdownScriptImpl::Legacy(pubkey))
	}

	/// Generates a P2PKH script pubkey from the given [`PubkeyHash`].
	pub fn new_p2pkh(pubkey_hash: &PubkeyHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(Script::new_p2pkh(pubkey_hash)))
	}

	/// Generates a P2SH script pubkey from the given [`ScriptHash`].
	pub fn new_p2sh(script_hash: &ScriptHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(Script::new_p2sh(script_hash)))
	}

	/// Generates a P2WPKH script pubkey from the given [`WPubkeyHash`].
	pub fn new_p2wpkh(pubkey_hash: &WPubkeyHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(Script::new_v0_wpkh(pubkey_hash)))
	}

	/// Generates a P2WSH script pubkey from the given [`WScriptHash`].
	pub fn new_p2wsh(script_hash: &WScriptHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(Script::new_v0_wsh(script_hash)))
	}

	/// Generates a P2WSH script pubkey from the given segwit version and program.
	///
	/// # Panics
	///
	/// This function may panic if given a segwit program with an invalid length.
	pub fn new_witness_program(version: NonZeroU8, program: &[u8]) -> Self {
		let version = u5::try_from_u8(version.get()).expect("Invalid segwit version");
		let script = Script::new_witness_program(version, program);
		Self::try_from(script).expect("Invalid segwit program")
	}

	/// Converts the shutdown script into the underlying [`Script`].
	pub fn into_inner(self) -> Script {
		self.into()
	}
}

impl TryFrom<Script> for ShutdownScript {
	type Error = InvalidShutdownScript;

	fn try_from(script: Script) -> Result<Self, Self::Error> {
		Self::try_from((script, &InitFeatures::known()))
	}
}

impl TryFrom<(Script, &InitFeatures)> for ShutdownScript {
	type Error = InvalidShutdownScript;

	fn try_from((script, features): (Script, &InitFeatures)) -> Result<Self, Self::Error> {
		if script.is_p2pkh() || script.is_p2sh() || script.is_v0_p2wpkh() || script.is_v0_p2wsh() {
			Ok(Self(ShutdownScriptImpl::Bolt2(script)))
		} else if features.supports_shutdown_anysegwit() && script.is_witness_program() && script.as_bytes()[0] != SEGWIT_V0.into_u8() {
			Ok(Self(ShutdownScriptImpl::Bolt2(script)))  // option_shutdown_anysegwit
		} else {
			Err(InvalidShutdownScript(script))
		}
	}
}

impl Into<Script> for ShutdownScript {
	fn into(self) -> Script {
		match self.0 {
			ShutdownScriptImpl::Legacy(pubkey) =>
				Script::new_v0_wpkh(&WPubkeyHash::hash(&pubkey.serialize())),
			ShutdownScriptImpl::Bolt2(script_pubkey) => script_pubkey,
		}
	}
}

#[cfg(test)]
mod shutdown_script_tests {
	use super::ShutdownScript;
	use bitcoin::bech32::u5;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::script::{Builder, Script};
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::key::{PublicKey, SecretKey};
	use std::convert::TryFrom;

	fn pubkey() -> bitcoin::util::ecdsa::PublicKey {
		let secp_ctx = Secp256k1::signing_only();
		let secret_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
		bitcoin::util::ecdsa::PublicKey::new(PublicKey::from_secret_key(&secp_ctx, &secret_key))
	}

	fn redeem_script() -> Script {
		let pubkey = pubkey();
		Builder::new()
			.push_opcode(opcodes::all::OP_PUSHNUM_2)
			.push_key(&pubkey)
			.push_key(&pubkey)
			.push_opcode(opcodes::all::OP_PUSHNUM_2)
			.push_opcode(opcodes::all::OP_CHECKMULTISIG)
			.into_script()
	}

	#[test]
	fn generates_p2wpkh_from_pubkey() {
		let pubkey = pubkey();
		let pubkey_hash = pubkey.wpubkey_hash().unwrap();
		let p2wpkh_script = Script::new_v0_wpkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2wpkh_from_pubkey(pubkey.key);
		assert_eq!(shutdown_script.into_inner(), p2wpkh_script);
	}

	#[test]
	fn generates_p2pkh_from_pubkey_hash() {
		let pubkey_hash = pubkey().pubkey_hash();
		let p2pkh_script = Script::new_p2pkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2pkh(&pubkey_hash);
		assert_eq!(shutdown_script.into_inner(), p2pkh_script);
		assert!(ShutdownScript::try_from(p2pkh_script).is_ok());
	}

	#[test]
	fn generates_p2sh_from_script_hash() {
		let script_hash = redeem_script().script_hash();
		let p2sh_script = Script::new_p2sh(&script_hash);

		let shutdown_script = ShutdownScript::new_p2sh(&script_hash);
		assert_eq!(shutdown_script.into_inner(), p2sh_script);
		assert!(ShutdownScript::try_from(p2sh_script).is_ok());
	}

	#[test]
	fn generates_p2wpkh_from_pubkey_hash() {
		let pubkey_hash = pubkey().wpubkey_hash().unwrap();
		let p2wpkh_script = Script::new_v0_wpkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2wpkh(&pubkey_hash);
		assert_eq!(shutdown_script.into_inner(), p2wpkh_script);
		assert!(ShutdownScript::try_from(p2wpkh_script).is_ok());
	}

	#[test]
	fn generates_p2wsh_from_script_hash() {
		let script_hash = redeem_script().wscript_hash();
		let p2wsh_script = Script::new_v0_wsh(&script_hash);

		let shutdown_script = ShutdownScript::new_p2wsh(&script_hash);
		assert_eq!(shutdown_script.into_inner(), p2wsh_script);
		assert!(ShutdownScript::try_from(p2wsh_script).is_ok());
	}

	#[test]
	fn fails_from_unsupported_script() {
		let op_return = Script::new_op_return(&[0; 42]);
		assert!(ShutdownScript::try_from(op_return).is_err());
	}

	#[test]
	fn fails_from_invalid_segwit_v0_program() {
		let witness_program = Script::new_witness_program(u5::try_from_u8(0).unwrap(), &[0; 2]);
		assert!(ShutdownScript::try_from(witness_program).is_err());
	}
}
