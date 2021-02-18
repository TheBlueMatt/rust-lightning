
#[cfg(target_os = "windows")]
extern crate winapi;
#[cfg(target_os = "windows")]
use std::os::windows::io::IntoRawHandle;

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
	use {
		std::ffi::OsStr,
		std::os::windows::ffi::OsStrExt
		};
#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;

pub(crate) trait DiskWriteable {
	fn write_to_file(&self, writer: &mut fs::File) -> Result<(), std::io::Error>;
}

pub(crate) fn get_full_filepath(filepath: String, filename: String) -> String {
	let mut path = PathBuf::from(filepath);
	path.push(filename);
	path.to_str().unwrap().to_string()
}
#[cfg(target_os = "windows")]
macro_rules! call {
	($e: expr) => (
		if $e != 0 {
			return Ok(())
		} else {
			return Err(std::io::Error::last_os_error())
		}
	)
}

#[cfg(target_os = "windows")]
fn path_to_windows_str<T: AsRef<OsStr>>(x: T) -> Vec<winapi::shared::ntdef::WCHAR> {
	x.as_ref().encode_wide().chain(Some(0)).collect()
}

#[allow(bare_trait_objects)]
pub(crate) fn write_to_file<D: DiskWriteable>(path: String, filename: String, data: &D) -> std::io::Result<()> {
	println!("VMW: in write_to_file, filename: {}", filename);
	fs::create_dir(path.clone())?;
			/*call!(unsafe {winapi::um::winbase::MoveFileExW(
				path_to_windows_str(src).as_ptr(), path_to_windows_str(dst).as_ptr(),
				winapi::um::winbase::MOVEFILE_WRITE_THROUGH | winapi::um::winbase::MOVEFILE_REPLACE_EXISTING
			)});*/

	// Do a crazy dance with lots of fsync()s to be overly cautious here...
	// We never want to end up in a state where we've lost the old data, or end up using the
	// old data on power loss after we've returned.
	// The way to atomically write a file on Unix platforms is:
	// open(tmpname), write(tmpfile), fsync(tmpfile), close(tmpfile), rename(), fsync(dir)
	let filename_with_path = get_full_filepath(path.clone(), filename);
	let tmp_filename = format!("{}.tmp", filename_with_path);

	{
		// Note that going by rust-lang/rust@d602a6b, on MacOS it is only safe to use
		// rust stdlib 1.36 or higher.
		println!("VMW: about to create file");
		let mut f = fs::File::create(&tmp_filename)?;
		println!("VMW: created file");
		data.write_to_file(&mut f)?;
		println!("VMW: about to sync all");
		f.sync_all()?;
		println!("VMW: sync'd all");
	}
	// Fsync the parent directory on Unix.
	#[cfg(not(target_os = "windows"))]
	{
		fs::rename(&tmp_filename, &filename_with_path)?;
		let path = Path::new(&filename_with_path).parent().unwrap();
		let dir_file = fs::OpenOptions::new().read(true).open(path)?;
		unsafe { libc::fsync(dir_file.as_raw_fd()); }
	}
	// std::thread::sleep(std::time::Duration::new(60, 0));
	#[cfg(target_os = "windows")]
	{
		println!("VMW: entries in dir:");
		let dir_perms = fs::metadata(path.clone()).unwrap().permissions();
		println!("VMW: dir perms: {:?}, readonly: {}", dir_perms, dir_perms.readonly());
		let dir = PathBuf::from(path.clone());
		for entry in fs::read_dir(dir).unwrap() {
			let entry = entry.unwrap();
			let metadata = entry.metadata().unwrap();
			println!("VMW: entry in dir: {:?}, perms in entry: {:?}, readonly: {}", entry.path(), metadata.permissions(), metadata.permissions().readonly());
		}

		// let mut dir_perms = fs::metadata(path.clone()).unwrap().permissions();
		// dir_perms.set_readonly(false);
		// if let Ok(metadata) = fs::metadata(filename_with_path.clone()) {
		// 	let mut perms = metadata.permissions();
		// 	perms.set_readonly(false);
		// }
    // // let mut perms = fs::metadata(filename_with_path.clone())?.permissions();
    // let mut tmp_perms = fs::metadata(tmp_filename.clone())?.permissions();
		// tmp_perms.set_readonly(false);
		// println!("VMW: about to rename");
		let src = PathBuf::from(tmp_filename.clone());
		let dst = PathBuf::from(filename_with_path.clone());
		// fs::rename(&tmp_filename.clone(), &filename_with_path.clone())?;
		// call!(unsafe {winapi::um::winbase::MoveFileExW(
		// 	path_to_windows_str(src).as_ptr(), path_to_windows_str(dst).as_ptr(),
		// 	winapi::um::winbase::MOVEFILE_WRITE_THROUGH | winapi::um::winbase::MOVEFILE_REPLACE_EXISTING
		// )});
		// let backup_filepath = PathBuf::from(format!("{}.backup", filename_with_path.clone()));

		/*if Path::new(&filename_with_path.clone()).exists() {
			unsafe {winapi::um::winbase::ReplaceFileW(
				path_to_windows_str(dst).as_ptr(), path_to_windows_str(src).as_ptr(), std::ptr::null(),
				winapi::um::winbase::REPLACEFILE_IGNORE_MERGE_ERRORS, std::ptr::null_mut() as *mut winapi::ctypes::c_void, std::ptr::null_mut() as *mut winapi::ctypes::c_void
			)};
		} else {*/
			call!(unsafe {winapi::um::winbase::MoveFileExW(
				path_to_windows_str(src).as_ptr(), path_to_windows_str(dst).as_ptr(),
				winapi::um::winbase::MOVEFILE_WRITE_THROUGH | winapi::um::winbase::MOVEFILE_REPLACE_EXISTING
			)});
		//}
		let mut final_file = fs::File::open(filename_with_path.clone())?;
		let file_handle = final_file.into_raw_handle();
		unsafe{winapi::um::fileapi::FlushFileBuffers(file_handle);}
		// final_file.sync_all()?;
		println!("VMW: renamed");
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::{DiskWriteable, get_full_filepath, write_to_file};
	use std::fs;
	use std::io;
	use std::io::Write;

	struct TestWriteable{}
	impl DiskWriteable for TestWriteable {
		fn write_to_file(&self, writer: &mut fs::File) -> Result<(), io::Error> {
			writer.write_all(&[42; 1])
		}
	}

	// Test that if the persister's path to channel data is read-only, writing
	// data to it fails. Windows ignores the read-only flag for folders, so this
	// test is Unix-only.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_readonly_dir() {
		let test_writeable = TestWriteable{};
		let filename = "test_readonly_dir_persister_filename".to_string();
		let path = "test_readonly_dir_persister_dir";
		fs::create_dir_all(path.to_string()).unwrap();
		let mut perms = fs::metadata(path.to_string()).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path.to_string(), perms).unwrap();
		match write_to_file(path.to_string(), filename, &test_writeable) {
			Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
			_ => panic!("Unexpected error message")
		}
	}

	// Test failure to rename in the process of atomically creating a channel
	// monitor's file. We induce this failure by making the `tmp` file a
	// directory.
	// Explanation: given "from" = the file being renamed, "to" = the
	// renamee that already exists: Unix should fail because if "from" is a
	// file, then "to" is also required to be a file.
	#[test]
	#[cfg(not(target_os = "windows"))]
	fn test_rename_failure() {
		let test_writeable = TestWriteable{};
		let filename = "test_rename_failure_filename";
		let path = "test_rename_failure_dir";
		// Create the channel data file and make it a directory.
		fs::create_dir_all(get_full_filepath(path.to_string(), filename.to_string())).unwrap();
		match write_to_file(path.to_string(), filename.to_string(), &test_writeable) {
			Err(e) => {
				assert_eq!(e.kind(), io::ErrorKind::Other);
			}
			_ => panic!("Unexpected Ok(())")
		}
		fs::remove_dir_all(path).unwrap();
	}

	#[test]
	fn test_diskwriteable_failure() {
		struct FailingWriteable {}
		impl DiskWriteable for FailingWriteable {
			fn write_to_file(&self, _writer: &mut fs::File) -> Result<(), std::io::Error> {
				Err(std::io::Error::new(std::io::ErrorKind::Other, "expected failure"))
			}
		}

		let filename = "test_diskwriteable_failure";
		let path = "test_diskwriteable_failure_dir";
		let test_writeable = FailingWriteable{};
		match write_to_file(path.to_string(), filename.to_string(), &test_writeable) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected failure");
			},
			_ => panic!("unexpected result")
		}
		fs::remove_dir_all(path).unwrap();
	}

	// Test failure to create the temporary file in the persistence process.
	// We induce this failure by having the temp file already exist and be a
	// directory.
	#[test]
	fn test_tmp_file_creation_failure() {
		let test_writeable = TestWriteable{};
		let filename = "test_tmp_file_creation_failure_filename".to_string();
		let path = "test_tmp_file_creation_failure_dir".to_string();

		// Create the tmp file and make it a directory.
		let tmp_path = get_full_filepath(path.clone(), format!("{}.tmp", filename.clone()));
		fs::create_dir_all(tmp_path).unwrap();
		match write_to_file(path, filename, &test_writeable) {
			Err(e) => {
				#[cfg(not(target_os = "windows"))]
				assert_eq!(e.kind(), io::ErrorKind::Other);
				#[cfg(target_os = "windows")]
				assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
			}
			_ => panic!("Unexpected error message")
		}
	}
}
