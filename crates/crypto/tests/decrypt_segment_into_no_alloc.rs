//! Proves `TdfEncryption::decrypt_segment_into` performs no heap allocation.
//!
//! This lives in its own integration-test binary (rather than the crate's
//! `#[cfg(test)]` module) because `#[global_allocator]` is process-wide: an
//! allocator installed here counts only allocations made by this binary,
//! without perturbing the crate's unit tests.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

#[test]
fn decrypt_segment_into_does_not_allocate() {
    use opentdf_crypto::TdfEncryption;

    let enc = TdfEncryption::new().unwrap();
    let plaintext = vec![0x42u8; 4 * 1024 * 1024]; // one GGUF-sized 4 MiB segment
    let seg = enc.encrypt_segment(&plaintext).unwrap();

    let mut dest = vec![0u8; plaintext.len()];

    let before = ALLOC_COUNT.load(Ordering::SeqCst);
    let tag = enc.decrypt_segment_into(&seg.bytes, &mut dest).unwrap();
    let after = ALLOC_COUNT.load(Ordering::SeqCst);

    assert_eq!(dest, plaintext);
    assert_eq!(tag, seg.tag);
    assert_eq!(
        before,
        after,
        "decrypt_segment_into must not allocate: {} allocation(s) observed",
        after - before
    );
}
