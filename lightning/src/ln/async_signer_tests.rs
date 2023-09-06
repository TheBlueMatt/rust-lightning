// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for asynchronous signing. These tests verify that the channel state machine behaves
//! properly with a signer implementation that asynchronously derives signatures.

use crate::events::{MessageSendEvent, MessageSendEventsProvider};
use crate::ln::msgs::ChannelMessageHandler;

use crate::ln::functional_test_utils::*;

#[test]
fn test_async_commitment_signature_for_funding_created() {
	// Simulate acquiring the signature for `funding_created` asynchronously.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	
	// nodes[0] --- open_channel --> nodes[1]
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);

	// nodes[0] <-- accept_channel --- nodes[1]
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	// nodes[0] --- funding_created --> nodes[1]
	//
	// But! Let's make node[0]'s signer be unavailable: we should *not* broadcast a funding_created
	// message...
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);
	nodes[0].set_channel_signer_available(&nodes[1].node.get_our_node_id(), &temporary_channel_id, false);
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	{
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		let n = events.len();
		assert_eq!(n, 0, "expected no events generated from nodes[0], found {}", n);
	}

	// Now re-enable the signer and simulate a retry. The temporary_channel_id won't work anymore so
	// we have to dig out the real channel ID.
	let chan_id = {
		let channels = nodes[0].node.list_channels();
		assert_eq!(channels.len(), 1, "expected one channel, not {}", channels.len());
		channels[0].channel_id
	};
	
	nodes[0].set_channel_signer_available(&nodes[1].node.get_our_node_id(), &chan_id, true);
	nodes[0].node.signer_unblocked(Some((nodes[1].node.get_our_node_id(), chan_id)));

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// nodes[0] <-- funding_signed --- nodes[1]
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
}

#[test]
fn test_async_commitment_signature_for_funding_signed() {
	// Simulate acquiring the signature for `funding_signed` asynchronously.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	
	// nodes[0] --- open_channel --> nodes[1]
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);

	// nodes[0] <-- accept_channel --- nodes[1]
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	// nodes[0] --- funding_created --> nodes[1]
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	// Now let's make node[1]'s signer be unavailable while handling the `funding_created`. It should
	// *not* broadcast a `funding_signed`...
	nodes[1].set_channel_signer_available(&nodes[0].node.get_our_node_id(), &temporary_channel_id, false);
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors(&nodes[1], 1);

	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		let n = events.len();
		assert_eq!(n, 0, "expected no events generated from nodes[1], found {}", n);
	}

	// Now re-enable the signer and simulate a retry. The temporary_channel_id won't work anymore so
	// we have to dig out the real channel ID.
	let chan_id = {
		let channels = nodes[0].node.list_channels();
		assert_eq!(channels.len(), 1, "expected one channel, not {}", channels.len());
		channels[0].channel_id
	};
	nodes[1].set_channel_signer_available(&nodes[0].node.get_our_node_id(), &chan_id, true);
	nodes[1].node.signer_unblocked(Some((nodes[0].node.get_our_node_id(), chan_id)));
	
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// nodes[0] <-- funding_signed --- nodes[1]
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
}
