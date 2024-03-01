use crate::{binder::*, param::*};
use libc::c_void;
use zeroize::Zeroize;

use super::{PublicKey, SecretKey};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    pub fn keygen() -> Self {
        let mut shake256_context = shake256_context::init();
        let mut pk = [0u8; PK_LEN];
        let mut sk = [0u8; SK_LEN];
        let mut buf = vec![0u8; KEYGEN_BUF_LEN];

        unsafe {
            assert!(
                falcon_keygen_make(
                    &mut shake256_context as *mut shake256_context,
                    LOG_N as u32,
                    sk.as_mut_ptr() as *mut c_void,
                    (SK_LEN as u64).try_into().unwrap(),
                    pk.as_mut_ptr() as *mut c_void,
                    (PK_LEN as u64).try_into().unwrap(),
                    buf.as_mut_ptr() as *mut c_void,
                    (KEYGEN_BUF_LEN as u64).try_into().unwrap()
                ) == 0
            );
        }
        buf.zeroize();

        Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        }
    }
}
