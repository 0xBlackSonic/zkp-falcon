pub use crate::binder::shake256_context;
use crate::binder::*;
use libc::c_void;

impl shake256_context {
  pub fn init() -> Self {
    let mut ctx = shake256_context {
      opaque_contents: [0u64; 26],
    };
    unsafe {
      shake256_init(&mut ctx as *mut shake256_context);
    }
    ctx
  }

  pub fn inject(&mut self, data: &[u8]) {
    unsafe {
      shake256_inject(
        self as *mut shake256_context,
        data.as_ptr() as *const c_void,
        (data.len() as u64).try_into().unwrap(),
      )
    }
  }

  pub fn finalize(&mut self) {
    unsafe { shake256_flip(self as *mut shake256_context) }
  }

  pub fn extract(&mut self, len: usize) -> Vec<u8> {
    let data = vec![0u8; len];
    unsafe {
      shake256_extract(
        self as *mut shake256_context,
        data.as_ptr() as *mut c_void,
        (len as u64).try_into().unwrap(),
      );
    }
    data
  }
}

#[cfg(test)]
mod test {
  use super::*;
  #[test]
  fn test_prng() {
    let _rng1 = shake256_context::init();
  }
}