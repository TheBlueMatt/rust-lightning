// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![crate_name = "lightning"]

//! Rust-Lightning, not Rusty's Lightning!
//!
//! A full-featured but also flexible lightning implementation, in library form. This allows the
//! user (you) to decide how they wish to use it instead of being a fully self-contained daemon.
//! This means there is no built-in threading/execution environment and it's up to the user to
//! figure out how best to make networking happen/timers fire/things get written to disk/keys get
//! generated/etc. This makes it a good candidate for tight integration into an existing wallet
//! instead of having a rather-separate lightning appendage to a wallet.
//!
//! `default` features are:
//!
//! * `std` - enables functionalities which require `std`, including `std::io` trait implementations and things which utilize time
//! * `grind_signatures` - enables generation of [low-r bitcoin signatures](https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding),
//! which saves 1 byte per signature in 50% of the cases (see [bitcoin PR #13666](https://github.com/bitcoin/bitcoin/pull/13666))
//!
//! Available features are:
//!
//! * `std`
//! * `grind_signatures`
//! * `no-std ` - exposes write trait implementations from the `core2` crate (at least one of `no-std` or `std` are required)
//! * Skip logging of messages at levels below the given log level:
//!     * `max_level_off`
//!     * `max_level_error`
//!     * `max_level_warn`
//!     * `max_level_info`
//!     * `max_level_debug`
//!     * `max_level_trace`

#![cfg_attr(not(any(test, fuzzing, feature = "_test_utils")), deny(missing_docs))]
#![cfg_attr(not(any(test, feature = "_test_utils")), forbid(unsafe_code))]

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[cfg(all(fuzzing, test))]
compile_error!("Tests will always fail with cfg=fuzzing");

#[macro_use]
extern crate alloc;
pub extern crate bitcoin;
#[cfg(any(test, feature = "std"))]
extern crate core;

extern crate hex;
#[cfg(any(test, feature = "_test_utils"))] extern crate regex;

#[cfg(not(feature = "std"))] extern crate libm;

#[cfg(ldk_bench)] extern crate criterion;

#[macro_use]
pub mod util;
pub mod chain;
pub mod ln;
pub mod offers;
pub mod routing;
pub mod sign;
pub mod onion_message;
pub mod blinded_path;
pub mod events;

pub(crate) mod crypto;

/// Extension of the bitcoin::io module
pub mod io {
	pub use bitcoin::io::*;

	/// The `Seek` trait provides a cursor which can be moved within a stream of
	/// bytes.
	///
	/// The stream typically has a fixed size, allowing seeking relative to either
	/// end or the current offset.
	///
	/// # Examples
	///
	/// [`File`]s implement `Seek`:
	///
	/// [`File`]: crate::fs::File
	///
	/// ```no_run
	/// use std::io;
	/// use std::io::prelude::*;
	/// use std::fs::File;
	/// use std::io::SeekFrom;
	///
	/// fn main() -> io::Result<()> {
	///     let mut f = File::open("foo.txt")?;
	///
	///     // move the cursor 42 bytes from the start of the file
	///     f.seek(SeekFrom::Start(42))?;
	///     Ok(())
	/// }
	/// ```
	pub trait Seek {
		/// Seek to an offset, in bytes, in a stream.
		///
		/// A seek beyond the end of a stream is allowed, but behavior is defined
		/// by the implementation.
		///
		/// If the seek operation completed successfully,
		/// this method returns the new position from the start of the stream.
		/// That position can be used later with [`SeekFrom::Start`].
		///
		/// # Errors
		///
		/// Seeking to a negative offset is considered an error.
		fn seek(&mut self, pos: SeekFrom) -> Result<u64>;
	}

	/// Enumeration of possible methods to seek within an I/O object.
	///
	/// It is used by the [`Seek`] trait.
	#[derive(Copy, PartialEq, Eq, Clone, Debug)]
	pub enum SeekFrom {
		/// Sets the offset to the provided number of bytes.
		Start(u64),

		/// Sets the offset to the size of this object plus the specified number of
		/// bytes.
		///
		/// It is possible to seek beyond the end of an object, but it's an error to
		/// seek before byte 0.
		End(i64),

		/// Sets the offset to the current position plus the specified number of
		/// bytes.
		///
		/// It is possible to seek beyond the end of an object, but it's an error to
		/// seek before byte 0.
		Current(i64),
	}

	/// Adaptor to chain together two readers.
	///
	/// This struct is generally created by calling [`chain`] on a reader.
	/// Please see the documentation of [`chain`] for more details.
	///
	/// [`chain`]: Read::chain
	pub struct Chain<T, U> {
		first: T,
		second: U,
		done_first: bool,
	}

	impl<T: Read, U: Read> Read for Chain<T, U> {
		fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
			if !self.done_first {
				match self.first.read(buf)? {
					0 if !buf.is_empty() => self.done_first = true,
					n => return Ok(n),
				}
			}
			self.second.read(buf)
		}
	}

	/// Emulation of std::io::Cursor
	#[derive(Clone, Debug, Default, Eq, PartialEq)]
	pub struct Cursor<T> {
		inner: T,
		pos: u64,
	}

	impl<T> Cursor<T> {
		/// Creates a new cursor wrapping the provided underlying in-memory buffer.
		///
		/// Cursor initial position is `0` even if underlying buffer (e.g., [`Vec`])
		/// is not empty. So writing to cursor starts with overwriting [`Vec`]
		/// content, not with appending to it.
		///
		/// # Examples
		///
		/// ```
		/// use bitcoin::io::Cursor;
		///
		/// let buff = Cursor::new(Vec::new());
		/// # fn force_inference(_: &Cursor<Vec<u8>>) {}
		/// # force_inference(&buff);
		/// ```
		pub fn new(inner: T) -> Cursor<T> {
			Cursor { pos: 0, inner }
		}

		/// Consumes this cursor, returning the underlying value.
		///
		/// # Examples
		///
		/// ```
		/// use bitcoin::io::Cursor;
		///
		/// let buff = Cursor::new(Vec::new());
		/// # fn force_inference(_: &Cursor<Vec<u8>>) {}
		/// # force_inference(&buff);
		///
		/// let vec = buff.into_inner();
		/// ```
		pub fn into_inner(self) -> T {
			self.inner
		}

		/// Gets a reference to the underlying value in this cursor.
		///
		/// # Examples
		///
		/// ```
		/// use bitcoin::io::Cursor;
		///
		/// let buff = Cursor::new(Vec::new());
		/// # fn force_inference(_: &Cursor<Vec<u8>>) {}
		/// # force_inference(&buff);
		///
		/// let reference = buff.get_ref();
		/// ```
		pub fn get_ref(&self) -> &T {
			&self.inner
		}

		/// Gets a mutable reference to the underlying value in this cursor.
		///
		/// Care should be taken to avoid modifying the internal I/O state of the
		/// underlying value as it may corrupt this cursor's position.
		///
		/// # Examples
		///
		/// ```
		/// use bitcoin::io::Cursor;
		///
		/// let mut buff = Cursor::new(Vec::new());
		/// # fn force_inference(_: &Cursor<Vec<u8>>) {}
		/// # force_inference(&buff);
		///
		/// let reference = buff.get_mut();
		/// ```
		pub fn get_mut(&mut self) -> &mut T {
			&mut self.inner
		}

		/// Returns the current position of this cursor.
		///
		/// # Examples
		///
		/// ```
		/// use core2::io::{Cursor, Seek, SeekFrom};
		/// use std::io::prelude::*;
		///
		/// let mut buff = Cursor::new(vec![1, 2, 3, 4, 5]);
		///
		/// assert_eq!(buff.position(), 0);
		///
		/// buff.seek(SeekFrom::Current(2)).unwrap();
		/// assert_eq!(buff.position(), 2);
		///
		/// buff.seek(SeekFrom::Current(-1)).unwrap();
		/// assert_eq!(buff.position(), 1);
		/// ```
		pub fn position(&self) -> u64 {
			self.pos
		}

		/// Sets the position of this cursor.
		///
		/// # Examples
		///
		/// ```
		/// use core2::io::Cursor;
		///
		/// let mut buff = Cursor::new(vec![1, 2, 3, 4, 5]);
		///
		/// assert_eq!(buff.position(), 0);
		///
		/// buff.set_position(2);
		/// assert_eq!(buff.position(), 2);
		///
		/// buff.set_position(4);
		/// assert_eq!(buff.position(), 4);
		/// ```
		pub fn set_position(&mut self, pos: u64) {
			self.pos = pos;
		}
	}

	impl<T> Seek for Cursor<T>
	where
		T: AsRef<[u8]>,
	{
		fn seek(&mut self, style: SeekFrom) -> Result<u64> {
			let (base_pos, offset) = match style {
				SeekFrom::Start(n) => {
					self.pos = n;
					return Ok(n);
				}
				SeekFrom::End(n) => (self.inner.as_ref().len() as u64, n),
				SeekFrom::Current(n) => (self.pos, n),
			};
			let new_pos = if offset >= 0 {
				base_pos.checked_add(offset as u64)
			} else {
				base_pos.checked_sub((offset.wrapping_neg()) as u64)
			};
			match new_pos {
				Some(n) => {
					self.pos = n;
					Ok(self.pos)
				}
				None => Err(Error::new(
					ErrorKind::InvalidInput,
					"invalid seek to a negative or overflowing position",
				)),
			}
		}
	}

	impl<T> Read for Cursor<T>
	where
		T: AsRef<[u8]>,
	{
		fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
			let n = Read::read(&mut self.fill_buf()?, buf)?;
			self.pos += n as u64;
			Ok(n)
		}

		fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
			let n = buf.len();
			Read::read_exact(&mut self.fill_buf()?, buf)?;
			self.pos += n as u64;
			Ok(())
		}
	}

	impl<T> BufRead for Cursor<T>
	where
		T: AsRef<[u8]>,
	{
		fn fill_buf(&mut self) -> Result<&[u8]> {
			let amt = core::cmp::min(self.pos, self.inner.as_ref().len() as u64);
			Ok(&self.inner.as_ref()[(amt as usize)..])
		}
		fn consume(&mut self, amt: usize) {
			self.pos += amt as u64;
		}
	}
}

// #[cfg(feature = "std")]
// /// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
// // pub use bitcoin::io;
// #[cfg(not(feature = "std"))]
// /// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
// // pub use bitcoin::io;

#[doc(hidden)]
/// IO utilities public only for use by in-crate macros. These should not be used externally
///
/// This is not exported to bindings users as it is not intended for public consumption.
pub mod io_extras {
	use bitcoin::io::{self, Read, Write};

	/// Creates an instance of a writer which will successfully consume all data.
	pub use bitcoin::io::sink;

	pub fn copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64, io::Error>
		where
		R: Read,
		W: Write,
	{
		let mut count = 0;
		let mut buf = [0u8; 64];

		loop {
			match reader.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => { writer.write_all(&buf[0..n])?; count += n as u64; },
				Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
				Err(e) => return Err(e.into()),
			};
		}
		Ok(count)
	}

	pub fn read_to_end<D: Read>(mut d: &mut D) -> Result<alloc::vec::Vec<u8>, io::Error> {
		let mut result = vec![];
		let mut buf = [0u8; 64];
		loop {
			match d.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => result.extend_from_slice(&buf[0..n]),
				Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
				Err(e) => return Err(e.into()),
			};
		}
		Ok(result)
	}
}

// #[cfg(feature = "std")]
// #[doc(hidden)]
// /// IO utilities public only for use by in-crate macros. These should not be used externally
// ///
// /// This is not exported to bindings users as it is not intended for public consumption.
// mod io_extras {
// 	pub fn read_to_end<D: ::std::io::Read>(mut d: D) -> Result<Vec<u8>, ::std::io::Error> {
// 		let mut buf = Vec::new();
// 		d.read_to_end(&mut buf)?;
// 		Ok(buf)
// 	}
//
// 	pub use bitcoin::io::sink;
// 	pub use std::io::copy;
// }

mod prelude {
	#![allow(unused_imports)]

	pub use alloc::{vec, vec::Vec, string::String, collections::VecDeque, boxed::Box};

	pub use alloc::borrow::ToOwned;
	pub use alloc::string::ToString;

	pub use core::convert::{AsMut, AsRef, TryFrom, TryInto};
	pub use core::default::Default;
	pub use core::marker::Sized;

	pub(crate) use crate::util::hash_tables::*;
}

#[cfg(all(not(ldk_bench), feature = "backtrace", feature = "std", test))]
extern crate backtrace;

mod sync;
