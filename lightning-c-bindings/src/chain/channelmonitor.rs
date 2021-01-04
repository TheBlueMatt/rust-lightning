//! The logic to monitor for on-chain transactions and create the relevant claim responses lives
//! here.
//!
//! ChannelMonitor objects are generated by ChannelManager in response to relevant
//! messages/actions, and MUST be persisted to disk (and, preferably, remotely) before progress can
//! be made in responding to certain messages, see [`chain::Watch`] for more.
//!
//! Note that ChannelMonitors are an important part of the lightning trust model and a copy of the
//! latest ChannelMonitor must always be actively monitoring for chain updates (and no out-of-date
//! ChannelMonitors should do so). Thus, if you're building rust-lightning into an HSM or other
//! security-domain-separated system design, you should consider having multiple paths for
//! ChannelMonitors to get out of the HSM and onto monitoring devices.
//!
//! [`chain::Watch`]: ../trait.Watch.html

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::chain::channelmonitor::ChannelMonitorUpdate as nativeChannelMonitorUpdateImport;
type nativeChannelMonitorUpdate = nativeChannelMonitorUpdateImport;

/// An update generated by the underlying Channel itself which contains some new information the
/// ChannelMonitor should be made aware of.
#[must_use]
#[repr(C)]
pub struct ChannelMonitorUpdate {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelMonitorUpdate,
	pub is_owned: bool,
}

impl Drop for ChannelMonitorUpdate {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_free(this_ptr: ChannelMonitorUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelMonitorUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelMonitorUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelMonitorUpdate {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelMonitorUpdate {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelMonitorUpdate {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelMonitorUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelMonitorUpdate)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_clone(orig: &ChannelMonitorUpdate) -> ChannelMonitorUpdate {
	ChannelMonitorUpdate { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// The sequence number of this update. Updates *must* be replayed in-order according to this
/// sequence number (and updates may panic if they are not). The update_id values are strictly
/// increasing and increase by one for each new update, with one exception specified below.
///
/// This sequence number is also used to track up to which points updates which returned
/// ChannelMonitorUpdateErr::TemporaryFailure have been applied to all copies of a given
/// ChannelMonitor when ChannelManager::channel_monitor_updated is called.
///
/// The only instance where update_id values are not strictly increasing is the case where we
/// allow post-force-close updates with a special update ID of [`CLOSED_CHANNEL_UPDATE_ID`]. See
/// its docs for more details.
///
/// [`CLOSED_CHANNEL_UPDATE_ID`]: constant.CLOSED_CHANNEL_UPDATE_ID.html
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_get_update_id(this_ptr: &ChannelMonitorUpdate) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.update_id;
	(*inner_val)
}
/// The sequence number of this update. Updates *must* be replayed in-order according to this
/// sequence number (and updates may panic if they are not). The update_id values are strictly
/// increasing and increase by one for each new update, with one exception specified below.
///
/// This sequence number is also used to track up to which points updates which returned
/// ChannelMonitorUpdateErr::TemporaryFailure have been applied to all copies of a given
/// ChannelMonitor when ChannelManager::channel_monitor_updated is called.
///
/// The only instance where update_id values are not strictly increasing is the case where we
/// allow post-force-close updates with a special update ID of [`CLOSED_CHANNEL_UPDATE_ID`]. See
/// its docs for more details.
///
/// [`CLOSED_CHANNEL_UPDATE_ID`]: constant.CLOSED_CHANNEL_UPDATE_ID.html
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_set_update_id(this_ptr: &mut ChannelMonitorUpdate, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.update_id = val;
}

#[no_mangle]
pub static CLOSED_CHANNEL_UPDATE_ID: u64 = lightning::chain::channelmonitor::CLOSED_CHANNEL_UPDATE_ID;
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_write(obj: *const ChannelMonitorUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelMonitorUpdate_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelMonitorUpdate) })
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelMonitorUpdateDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::chain::channelmonitor::ChannelMonitorUpdate { inner: Box::into_raw(Box::new(o)), is_owned: true } }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }) };
	local_res
}
/// An error enum representing a failure to persist a channel monitor update.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ChannelMonitorUpdateErr {
	/// Used to indicate a temporary failure (eg connection to a watchtower or remote backup of
	/// our state failed, but is expected to succeed at some point in the future).
	///
	/// Such a failure will \"freeze\" a channel, preventing us from revoking old states or
	/// submitting new commitment transactions to the counterparty. Once the update(s) which failed
	/// have been successfully applied, ChannelManager::channel_monitor_updated can be used to
	/// restore the channel to an operational state.
	///
	/// Note that a given ChannelManager will *never* re-generate a given ChannelMonitorUpdate. If
	/// you return a TemporaryFailure you must ensure that it is written to disk safely before
	/// writing out the latest ChannelManager state.
	///
	/// Even when a channel has been \"frozen\" updates to the ChannelMonitor can continue to occur
	/// (eg if an inbound HTLC which we forwarded was claimed upstream resulting in us attempting
	/// to claim it on this channel) and those updates must be applied wherever they can be. At
	/// least one such updated ChannelMonitor must be persisted otherwise PermanentFailure should
	/// be returned to get things on-chain ASAP using only the in-memory copy. Obviously updates to
	/// the channel which would invalidate previous ChannelMonitors are not made when a channel has
	/// been \"frozen\".
	///
	/// Note that even if updates made after TemporaryFailure succeed you must still call
	/// channel_monitor_updated to ensure you have the latest monitor and re-enable normal channel
	/// operation.
	///
	/// Note that the update being processed here will not be replayed for you when you call
	/// ChannelManager::channel_monitor_updated, so you must store the update itself along
	/// with the persisted ChannelMonitor on your own local disk prior to returning a
	/// TemporaryFailure. You may, of course, employ a journaling approach, storing only the
	/// ChannelMonitorUpdate on disk without updating the monitor itself, replaying the journal at
	/// reload-time.
	///
	/// For deployments where a copy of ChannelMonitors and other local state are backed up in a
	/// remote location (with local copies persisted immediately), it is anticipated that all
	/// updates will return TemporaryFailure until the remote copies could be updated.
	TemporaryFailure,
	/// Used to indicate no further channel monitor updates will be allowed (eg we've moved on to a
	/// different watchtower and cannot update with all watchtowers that were previously informed
	/// of this channel).
	///
	/// At reception of this error, ChannelManager will force-close the channel and return at
	/// least a final ChannelMonitorUpdate::ChannelForceClosed which must be delivered to at
	/// least one ChannelMonitor copy. Revocation secret MUST NOT be released and offchain channel
	/// update must be rejected.
	///
	/// This failure may also signal a failure to update the local persisted copy of one of
	/// the channel monitor instance.
	///
	/// Note that even when you fail a holder commitment transaction update, you must store the
	/// update to ensure you can claim from it in case of a duplicate copy of this ChannelMonitor
	/// broadcasts it (e.g distributed channel-monitor deployment)
	///
	/// In case of distributed watchtowers deployment, the new version must be written to disk, as
	/// state may have been stored but rejected due to a block forcing a commitment broadcast. This
	/// storage is used to claim outputs of rejected state confirmed onchain by another watchtower,
	/// lagging behind on block processing.
	PermanentFailure,
}
use lightning::chain::channelmonitor::ChannelMonitorUpdateErr as nativeChannelMonitorUpdateErr;
impl ChannelMonitorUpdateErr {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeChannelMonitorUpdateErr {
		match self {
			ChannelMonitorUpdateErr::TemporaryFailure => nativeChannelMonitorUpdateErr::TemporaryFailure,
			ChannelMonitorUpdateErr::PermanentFailure => nativeChannelMonitorUpdateErr::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeChannelMonitorUpdateErr {
		match self {
			ChannelMonitorUpdateErr::TemporaryFailure => nativeChannelMonitorUpdateErr::TemporaryFailure,
			ChannelMonitorUpdateErr::PermanentFailure => nativeChannelMonitorUpdateErr::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeChannelMonitorUpdateErr) -> Self {
		match native {
			nativeChannelMonitorUpdateErr::TemporaryFailure => ChannelMonitorUpdateErr::TemporaryFailure,
			nativeChannelMonitorUpdateErr::PermanentFailure => ChannelMonitorUpdateErr::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeChannelMonitorUpdateErr) -> Self {
		match native {
			nativeChannelMonitorUpdateErr::TemporaryFailure => ChannelMonitorUpdateErr::TemporaryFailure,
			nativeChannelMonitorUpdateErr::PermanentFailure => ChannelMonitorUpdateErr::PermanentFailure,
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdateErr_clone(orig: &ChannelMonitorUpdateErr) -> ChannelMonitorUpdateErr {
	orig.clone()
}

use lightning::chain::channelmonitor::MonitorUpdateError as nativeMonitorUpdateErrorImport;
type nativeMonitorUpdateError = nativeMonitorUpdateErrorImport;

/// General Err type for ChannelMonitor actions. Generally, this implies that the data provided is
/// inconsistent with the ChannelMonitor being called. eg for ChannelMonitor::update_monitor this
/// means you tried to update a monitor for a different channel or the ChannelMonitorUpdate was
/// corrupted.
/// Contains a developer-readable error message.
#[must_use]
#[repr(C)]
pub struct MonitorUpdateError {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorUpdateError,
	pub is_owned: bool,
}

impl Drop for MonitorUpdateError {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn MonitorUpdateError_free(this_ptr: MonitorUpdateError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MonitorUpdateError_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMonitorUpdateError); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MonitorUpdateError {
	pub(crate) fn take_inner(mut self) -> *mut nativeMonitorUpdateError {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::chain::channelmonitor::MonitorEvent as nativeMonitorEventImport;
type nativeMonitorEvent = nativeMonitorEventImport;

/// An event to be processed by the ChannelManager.
#[must_use]
#[repr(C)]
pub struct MonitorEvent {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorEvent,
	pub is_owned: bool,
}

impl Drop for MonitorEvent {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn MonitorEvent_free(this_ptr: MonitorEvent) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MonitorEvent_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMonitorEvent); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MonitorEvent {
	pub(crate) fn take_inner(mut self) -> *mut nativeMonitorEvent {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for MonitorEvent {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeMonitorEvent)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn MonitorEvent_clone(orig: &MonitorEvent) -> MonitorEvent {
	MonitorEvent { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}

use lightning::chain::channelmonitor::HTLCUpdate as nativeHTLCUpdateImport;
type nativeHTLCUpdate = nativeHTLCUpdateImport;

/// Simple structure sent back by `chain::Watch` when an HTLC from a forward channel is detected on
/// chain. Used to update the corresponding HTLC in the backward channel. Failing to pass the
/// preimage claim backward will lead to loss of funds.
///
/// [`chain::Watch`]: ../trait.Watch.html
#[must_use]
#[repr(C)]
pub struct HTLCUpdate {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHTLCUpdate,
	pub is_owned: bool,
}

impl Drop for HTLCUpdate {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_free(this_ptr: HTLCUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn HTLCUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeHTLCUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl HTLCUpdate {
	pub(crate) fn take_inner(mut self) -> *mut nativeHTLCUpdate {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for HTLCUpdate {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHTLCUpdate)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_clone(orig: &HTLCUpdate) -> HTLCUpdate {
	HTLCUpdate { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_write(obj: *const HTLCUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn HTLCUpdate_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHTLCUpdate) })
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_read(ser: crate::c_types::u8slice) -> HTLCUpdate {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		HTLCUpdate { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		HTLCUpdate { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::chain::channelmonitor::ChannelMonitor as nativeChannelMonitorImport;
type nativeChannelMonitor = nativeChannelMonitorImport<crate::chain::keysinterface::ChannelKeys>;

/// A ChannelMonitor handles chain events (blocks connected and disconnected) and generates
/// on-chain transactions to ensure no loss of funds occurs.
///
/// You MUST ensure that no ChannelMonitors for a given channel anywhere contain out-of-date
/// information and are actively monitoring the chain.
///
/// Pending Events or updated HTLCs which have not yet been read out by
/// get_and_clear_pending_monitor_events or get_and_clear_pending_events are serialized to disk and
/// reloaded at deserialize-time. Thus, you must ensure that, when handling events, all events
/// gotten are fully handled before re-serializing the new state.
///
/// Note that the deserializer is only implemented for (Sha256dHash, ChannelMonitor), which
/// tells you the last block hash which was block_connect()ed. You MUST rescan any blocks along
/// the \"reorg path\" (ie disconnecting blocks until you find a common ancestor from both the
/// returned block hash and the the current chain and then reconnecting blocks to get to the
/// best chain) upon deserializing the object!
#[must_use]
#[repr(C)]
pub struct ChannelMonitor {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelMonitor,
	pub is_owned: bool,
}

impl Drop for ChannelMonitor {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelMonitor_free(this_ptr: ChannelMonitor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelMonitor_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelMonitor); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelMonitor {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelMonitor {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Updates a ChannelMonitor on the basis of some new information provided by the Channel
/// itself.
///
/// panics if the given update is not the next update by update_id.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_update_monitor(this_arg: &mut ChannelMonitor, updates: &crate::chain::channelmonitor::ChannelMonitorUpdate, broadcaster: &crate::chain::chaininterface::BroadcasterInterface, fee_estimator: &crate::chain::chaininterface::FeeEstimator, logger: &crate::util::logger::Logger) -> crate::c_types::derived::CResult_NoneMonitorUpdateErrorZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.update_monitor(unsafe { &*updates.inner }, broadcaster, fee_estimator, logger);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::chain::channelmonitor::MonitorUpdateError { inner: Box::into_raw(Box::new(e)), is_owned: true } }) };
	local_ret
}

/// Gets the update_id from the latest ChannelMonitorUpdate which was applied to this
/// ChannelMonitor.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_latest_update_id(this_arg: &ChannelMonitor) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.get_latest_update_id();
	ret
}

/// Gets the funding transaction outpoint of the channel this ChannelMonitor is monitoring for.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_funding_txo(this_arg: &ChannelMonitor) -> crate::c_types::derived::C2Tuple_OutPointScriptZ {
	let mut ret = unsafe { &*this_arg.inner }.get_funding_txo();
	let (ref orig_ret_0, ref orig_ret_1) = ret; let mut local_ret = (crate::chain::transaction::OutPoint { inner: unsafe { ( (&(*orig_ret_0) as *const _) as *mut _) }, is_owned: false }, orig_ret_1.clone().into_bytes().into()).into();
	local_ret
}

/// Get the list of HTLCs who's status has been updated on chain. This should be called by
/// ChannelManager via [`chain::Watch::release_pending_monitor_events`].
///
/// [`chain::Watch::release_pending_monitor_events`]: ../trait.Watch.html#tymethod.release_pending_monitor_events
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_and_clear_pending_monitor_events(this_arg: &mut ChannelMonitor) -> crate::c_types::derived::CVec_MonitorEventZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.get_and_clear_pending_monitor_events();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::chain::channelmonitor::MonitorEvent { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}

/// Gets the list of pending events which were generated by previous actions, clearing the list
/// in the process.
///
/// This is called by ChainMonitor::get_and_clear_pending_events() and is equivalent to
/// EventsProvider::get_and_clear_pending_events() except that it requires &mut self as we do
/// no internal locking in ChannelMonitors.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_and_clear_pending_events(this_arg: &mut ChannelMonitor) -> crate::c_types::derived::CVec_EventZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.get_and_clear_pending_events();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::util::events::Event::native_into(item) }); };
	local_ret.into()
}

/// Used by ChannelManager deserialization to broadcast the latest holder state if its copy of
/// the Channel was out-of-date. You may use it to get a broadcastable holder toxic tx in case of
/// fallen-behind, i.e when receiving a channel_reestablish with a proof that our counterparty side knows
/// a higher revocation secret than the holder commitment number we are aware of. Broadcasting these
/// transactions are UNSAFE, as they allow counterparty side to punish you. Nevertheless you may want to
/// broadcast them if counterparty don't close channel with his higher commitment transaction after a
/// substantial amount of time (a month or even a year) to get back funds. Best may be to contact
/// out-of-band the other node operator to coordinate with him if option is available to you.
/// In any-case, choice is up to the user.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_latest_holder_commitment_txn(this_arg: &mut ChannelMonitor, logger: &crate::util::logger::Logger) -> crate::c_types::derived::CVec_TransactionZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.get_latest_holder_commitment_txn(logger);
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { let mut local_ret_0 = ::bitcoin::consensus::encode::serialize(&item); crate::c_types::Transaction::from_vec(local_ret_0) }); };
	local_ret.into()
}

/// Processes transactions in a newly connected block, which may result in any of the following:
/// - update the monitor's state against resolved HTLCs
/// - punish the counterparty in the case of seeing a revoked commitment transaction
/// - force close the channel and claim/timeout incoming/outgoing HTLCs if near expiration
/// - detect settled outputs for later spending
/// - schedule and bump any in-flight claims
///
/// Returns any new outputs to watch from `txdata`; after called, these are also included in
/// [`get_outputs_to_watch`].
///
/// [`get_outputs_to_watch`]: #method.get_outputs_to_watch
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_block_connected(this_arg: &mut ChannelMonitor, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32, mut broadcaster: crate::chain::chaininterface::BroadcasterInterface, mut fee_estimator: crate::chain::chaininterface::FeeEstimator, mut logger: crate::util::logger::Logger) -> crate::c_types::derived::CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.block_connected(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height, broadcaster, fee_estimator, logger);
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_orig_ret_0_1 = Vec::new(); for item in orig_ret_0_1.drain(..) { local_orig_ret_0_1.push( { let (mut orig_orig_ret_0_1_0_0, mut orig_orig_ret_0_1_0_1) = item; let mut local_orig_ret_0_1_0 = (orig_orig_ret_0_1_0_0, crate::c_types::TxOut::from_rust(orig_orig_ret_0_1_0_1)).into(); local_orig_ret_0_1_0 }); }; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.into_inner() }, local_orig_ret_0_1.into()).into(); local_ret_0 }); };
	local_ret.into()
}

/// Determines if the disconnected block contained any transactions of interest and updates
/// appropriately.
#[no_mangle]
pub extern "C" fn ChannelMonitor_block_disconnected(this_arg: &mut ChannelMonitor, header: *const [u8; 80], mut height: u32, mut broadcaster: crate::chain::chaininterface::BroadcasterInterface, mut fee_estimator: crate::chain::chaininterface::FeeEstimator, mut logger: crate::util::logger::Logger) {
	unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.block_disconnected(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height, broadcaster, fee_estimator, logger)
}

/// `Persist` defines behavior for persisting channel monitors: this could mean
/// writing once to disk, and/or uploading to one or more backup services.
///
/// Note that for every new monitor, you **must** persist the new `ChannelMonitor`
/// to disk/backups. And, on every update, you **must** persist either the
/// `ChannelMonitorUpdate` or the updated monitor itself. Otherwise, there is risk
/// of situations such as revoking a transaction, then crashing before this
/// revocation can be persisted, then unintentionally broadcasting a revoked
/// transaction and losing money. This is a risk because previous channel states
/// are toxic, so it's important that whatever channel state is persisted is
/// kept up-to-date.
#[repr(C)]
pub struct Persist {
	pub this_arg: *mut c_void,
	/// Persist a new channel's data. The data can be stored any way you want, but
	/// the identifier provided by Rust-Lightning is the channel's outpoint (and
	/// it is up to you to maintain a correct mapping between the outpoint and the
	/// stored channel data). Note that you **must** persist every new monitor to
	/// disk. See the `Persist` trait documentation for more details.
	///
	/// See [`ChannelMonitor::serialize_for_disk`] for writing out a `ChannelMonitor`,
	/// and [`ChannelMonitorUpdateErr`] for requirements when returning errors.
	///
	/// [`ChannelMonitor::serialize_for_disk`]: struct.ChannelMonitor.html#method.serialize_for_disk
	/// [`ChannelMonitorUpdateErr`]: enum.ChannelMonitorUpdateErr.html
	#[must_use]
	pub persist_new_channel: extern "C" fn (this_arg: *const c_void, id: crate::chain::transaction::OutPoint, data: &crate::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ,
	/// Update one channel's data. The provided `ChannelMonitor` has already
	/// applied the given update.
	///
	/// Note that on every update, you **must** persist either the
	/// `ChannelMonitorUpdate` or the updated monitor itself to disk/backups. See
	/// the `Persist` trait documentation for more details.
	///
	/// If an implementer chooses to persist the updates only, they need to make
	/// sure that all the updates are applied to the `ChannelMonitors` *before*
	/// the set of channel monitors is given to the `ChannelManager`
	/// deserialization routine. See [`ChannelMonitor::update_monitor`] for
	/// applying a monitor update to a monitor. If full `ChannelMonitors` are
	/// persisted, then there is no need to persist individual updates.
	///
	/// Note that there could be a performance tradeoff between persisting complete
	/// channel monitors on every update vs. persisting only updates and applying
	/// them in batches. The size of each monitor grows `O(number of state updates)`
	/// whereas updates are small and `O(1)`.
	///
	/// See [`ChannelMonitor::serialize_for_disk`] for writing out a `ChannelMonitor`,
	/// [`ChannelMonitorUpdate::write`] for writing out an update, and
	/// [`ChannelMonitorUpdateErr`] for requirements when returning errors.
	///
	/// [`ChannelMonitor::update_monitor`]: struct.ChannelMonitor.html#impl-1
	/// [`ChannelMonitor::serialize_for_disk`]: struct.ChannelMonitor.html#method.serialize_for_disk
	/// [`ChannelMonitorUpdate::write`]: struct.ChannelMonitorUpdate.html#method.write
	/// [`ChannelMonitorUpdateErr`]: enum.ChannelMonitorUpdateErr.html
	#[must_use]
	pub update_persisted_channel: extern "C" fn (this_arg: *const c_void, id: crate::chain::transaction::OutPoint, update: &crate::chain::channelmonitor::ChannelMonitorUpdate, data: &crate::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Persist {}
unsafe impl Sync for Persist {}

use lightning::chain::channelmonitor::Persist as rustPersist;
impl rustPersist<crate::chain::keysinterface::ChannelKeys> for Persist {
	fn persist_new_channel(&self, id: lightning::chain::transaction::OutPoint, data: &lightning::chain::channelmonitor::ChannelMonitor<crate::chain::keysinterface::ChannelKeys>) -> Result<(), lightning::chain::channelmonitor::ChannelMonitorUpdateErr> {
		let mut ret = (self.persist_new_channel)(self.this_arg, crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(id)), is_owned: true }, &crate::chain::channelmonitor::ChannelMonitor { inner: unsafe { (data as *const _) as *mut _ }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn update_persisted_channel(&self, id: lightning::chain::transaction::OutPoint, update: &lightning::chain::channelmonitor::ChannelMonitorUpdate, data: &lightning::chain::channelmonitor::ChannelMonitor<crate::chain::keysinterface::ChannelKeys>) -> Result<(), lightning::chain::channelmonitor::ChannelMonitorUpdateErr> {
		let mut ret = (self.update_persisted_channel)(self.this_arg, crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(id)), is_owned: true }, &crate::chain::channelmonitor::ChannelMonitorUpdate { inner: unsafe { (update as *const _) as *mut _ }, is_owned: false }, &crate::chain::channelmonitor::ChannelMonitor { inner: unsafe { (data as *const _) as *mut _ }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Persist {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Persist_free(this_ptr: Persist) { }
impl Drop for Persist {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
