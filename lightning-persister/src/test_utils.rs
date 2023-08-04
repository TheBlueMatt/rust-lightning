use lightning::util::persist::KVStore;

pub(crate) fn do_read_write_remove_list_persist<K: KVStore>(kv_store: &K) {
	use lightning::util::ser::Readable;

	let data = [42u8; 32];

	let namespace = "testspace";
	let key = "testkey";

	// Test the basic KVStore operations.
	kv_store.write(namespace, key, &data).unwrap();

	// Test empty namespace is allowed, but not empty key.
	kv_store.write("", key, &data).unwrap();
	assert!(kv_store.write(namespace, "", &data).is_err());

	let listed_keys = kv_store.list(namespace).unwrap();
	assert_eq!(listed_keys.len(), 1);
	assert_eq!(listed_keys[0], key);

	let mut reader = kv_store.read(namespace, key).unwrap();
	let read_data: [u8; 32] = Readable::read(&mut reader).unwrap();
	assert_eq!(data, read_data);

	kv_store.remove(namespace, key).unwrap();

	let listed_keys = kv_store.list(namespace).unwrap();
	assert_eq!(listed_keys.len(), 0);
}
