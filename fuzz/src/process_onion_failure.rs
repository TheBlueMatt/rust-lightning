use std::sync::Arc;

use bitcoin::{
	key::Secp256k1,
	secp256k1::{PublicKey, SecretKey},
};
use lightning::{
	blinded_path::BlindedHop,
	ln::{
		channelmanager::{HTLCSource, PaymentId},
		msgs::OnionErrorPacket,
	},
	routing::router::{BlindedTail, Path, RouteHop, TrampolineHop},
	types::features::{ChannelFeatures, NodeFeatures},
	util::logger::Logger,
};

// Imports that need to be added manually
use crate::utils::test_logger::{self};

/// Actual fuzz test, method signature and name are fixed
fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let mut read_pos = 0;
	macro_rules! get_slice {
		($len: expr) => {{
			let slice_len = $len as usize;
			if data.len() < read_pos + slice_len {
				return;
			}
			read_pos += slice_len;
			&data[read_pos - slice_len..read_pos]
		}};
	}

	macro_rules! get_u8 {
		() => {
			get_slice!(1)[0]
		};
	}

	macro_rules! get_u16 {
		() => {
			match get_slice!(2).try_into() {
				Ok(val) => u16::from_be_bytes(val),
				Err(_) => return,
			}
		};
	}

	macro_rules! get_u32 {
		() => {
			match get_slice!(4).try_into() {
				Ok(val) => u32::from_be_bytes(val),
				Err(_) => return,
			}
		};
	}

	macro_rules! get_u64 {
		() => {
			match get_slice!(8).try_into() {
				Ok(val) => u64::from_be_bytes(val),
				Err(_) => return,
			}
		};
	}

	macro_rules! get_bool {
		() => {
			get_slice!(1)[0] != 0
		};
	}

	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(get_slice!(33)) {
				Ok(val) => val,
				Err(_) => return,
			}
		};
	}

	let secp_ctx = Secp256k1::new();
	let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new("".to_owned(), out));

	let session_priv = match SecretKey::from_slice(get_slice!(32)) {
		Ok(val) => val,
		Err(_) => return,
	};

	let payment_id = match get_slice!(32).try_into() {
		Ok(val) => PaymentId(val),
		Err(_) => return,
	};

	let mut hops = Vec::<RouteHop>::new();
	let hop_count = get_slice!(1)[0] as usize;
	for _ in 0..hop_count {
		hops.push(RouteHop {
			pubkey: get_pubkey!(),
			node_features: NodeFeatures::empty(),
			short_channel_id: get_u64!(),
			channel_features: ChannelFeatures::empty(),
			fee_msat: get_u64!(),
			cltv_expiry_delta: get_u32!(),
			maybe_announced_channel: get_bool!(),
		});
	}

	let blinded_tail = match get_bool!() {
		true => {
			let mut trampoline_hops = Vec::<TrampolineHop>::new();
			let trampoline_hop_count = get_slice!(1)[0] as usize;
			for _ in 0..trampoline_hop_count {
				trampoline_hops.push(TrampolineHop {
					pubkey: get_pubkey!(),
					node_features: NodeFeatures::empty(),
					fee_msat: get_u64!(),
					cltv_expiry_delta: get_u32!(),
				});
			}
			let mut blinded_hops = Vec::<BlindedHop>::new();
			let blinded_hop_count = get_slice!(1)[0] as usize;
			for _ in 0..blinded_hop_count {
				blinded_hops.push(BlindedHop {
					blinded_node_id: get_pubkey!(),
					encrypted_payload: get_slice!(get_u8!()).to_vec(),
				});
			}
			Some(BlindedTail {
				trampoline_hops,
				hops: blinded_hops,
				blinding_point: get_pubkey!(),
				excess_final_cltv_expiry_delta: get_u32!(),
				final_value_msat: get_u64!(),
			})
		},
		false => None,
	};

	let path = Path { hops, blinded_tail };

	let htlc_source = HTLCSource::OutboundRoute {
		path,
		session_priv,
		first_hop_htlc_msat: get_u64!(),
		payment_id,
	};

	let failure_len = get_u16!();
	let encrypted_packet = OnionErrorPacket { data: get_slice!(failure_len).into() };

	lightning::ln::process_onion_failure(&secp_ctx, &logger, &htlc_source, encrypted_packet);
}

/// Method that needs to be added manually, {name}_test
pub fn process_onion_failure_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

/// Method that needs to be added manually, {name}_run
#[no_mangle]
pub extern "C" fn process_onion_failure_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
