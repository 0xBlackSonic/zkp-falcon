use crate::{binder::*, param::*};
use libc::c_void;
use zeroize::Zeroize;

use super::{PublicKey, Signature};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecretKey(pub(crate) [u8; SK_LEN]);

impl SecretKey {
    pub fn make_public_key(&self) -> PublicKey {
        let mut pk = [0u8; PK_LEN];
        let mut buf = [0u8; MAKE_PK_BUF_LEN];

        unsafe {
            assert!(
                falcon_make_public(
                    pk.as_mut_ptr() as *mut c_void,
                    (PK_LEN as u64).try_into().unwrap(),
                    self.0.as_ptr() as *const c_void,
                    (SK_LEN as u64).try_into().unwrap(),
                    buf.as_mut_ptr() as *mut c_void,
                    (MAKE_PK_BUF_LEN as u64).try_into().unwrap()
                ) == 0
            )
        }
        buf.zeroize();
        PublicKey(pk)
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut shake256_context = shake256_context::init();
        let mut sig = [0u8; SIG_LEN];
        let sig_len = &mut (SIG_LEN as u64);
        let sig_type = 2;
        let mut buf = [0u8; SIGN_BUF_LEN];

        unsafe {
            assert!(
                falcon_sign_dyn(
                    &mut shake256_context as *mut shake256_context,
                    sig.as_mut_ptr() as *mut c_void,
                    (sig_len as *mut u64) as *mut usize,
                    sig_type,
                    self.0.as_ptr() as *const c_void,
                    (SK_LEN as u64).try_into().unwrap(),
                    message.as_ptr() as *const c_void,
                    (message.len() as u64).try_into().unwrap(),
                    buf.as_mut_ptr() as *mut c_void,
                    (SIGN_BUF_LEN as u64).try_into().unwrap()
                ) == 0
            )
        }
        buf.zeroize();
        Signature(sig)
    }
}
