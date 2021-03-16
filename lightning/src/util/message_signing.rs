use crate::util::zbase32;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey};

static LN_MESSAGE_PREFIX: &[u8] = "Lightning Signed Message:".as_bytes();


fn sigrec_encode(sig_rec: RecoverableSignature) -> Vec<u8> {
    let (rid, rsig) = sig_rec.serialize_compact();
    let prefix = rid.to_i32() as u8 + 31;

    [&[prefix], &rsig[..]].concat()
}


fn sigrec_decode(sig_rec: Vec<u8>) -> Result<RecoverableSignature, Error> {
    let rsig = &sig_rec[1..];
    let rid = sig_rec[0] as i32 - 31;
    
    match RecoveryId::from_i32(rid) {
        Ok(x) => RecoverableSignature::from_compact(rsig, x),
        Err(e) => Err(e)
    }
}


pub fn sign(msg: &[u8], sk: SecretKey) -> Result<String, Error> {
    let secp_ctx = Secp256k1::signing_only();
    let msg_hash = sha256d::Hash::hash(&[LN_MESSAGE_PREFIX, msg].concat());

    let sig = secp_ctx.sign_recoverable(&Message::from_slice(&msg_hash)?, &sk);
    Ok(zbase32::encode(&sigrec_encode(sig)))
}

pub fn recover_pk(msg: &[u8], sig: String) ->  Result<PublicKey, Error>{
    let secp_ctx = Secp256k1::verification_only();
    let msg_hash = sha256d::Hash::hash(&[LN_MESSAGE_PREFIX, msg].concat());

    match zbase32::decode(&sig) {
        Ok(sig_rec) => {
            match sigrec_decode(sig_rec) {
                Ok(sig) => secp_ctx.recover(&Message::from_slice(&msg_hash)?, &sig),
                Err(e) => Err(e)
            }
        },
        Err(_) => Err(Error::InvalidSignature)
    }
    
}

pub fn verify(msg: &[u8], sig: String, pk: PublicKey) -> bool {
    match recover_pk(msg, sig) {
        Ok(x) => x == pk,
        Err(_) => false
    }
}

#[cfg(test)]
mod test {
    use util::message_signing::{sign, recover_pk, verify};
    use bitcoin::secp256k1::key::ONE_KEY;
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    
    #[test]
    fn test_sign() {
        let message = "test message";
        let zbase32_sig = sign(message.as_bytes(), ONE_KEY);

        assert_eq!(zbase32_sig.unwrap(), "d9tibmnic9t5y41hg7hkakdcra94akas9ku3rmmj4ag9mritc8ok4p5qzefs78c9pqfhpuftqqzhydbdwfg7u6w6wdxcqpqn4sj4e73e")
    }

    #[test]
    fn test_recover_pk() {
        let message = "test message";
        let sig = "d9tibmnic9t5y41hg7hkakdcra94akas9ku3rmmj4ag9mritc8ok4p5qzefs78c9pqfhpuftqqzhydbdwfg7u6w6wdxcqpqn4sj4e73e";
        let pk = recover_pk(message.as_bytes(), String::from(sig));

        assert_eq!(pk.unwrap(), PublicKey::from_secret_key(&Secp256k1::signing_only(), &ONE_KEY))
    }

    #[test]
    fn test_verify() {
        let message = "another message";
        let sig = sign(message.as_bytes(), ONE_KEY).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::signing_only(), &ONE_KEY);

        assert!(verify(message.as_bytes(), String::from(sig), pk))
    }
}
