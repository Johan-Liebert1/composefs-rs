#![deny(missing_debug_implementations)]

pub mod bootloader;
pub mod cmdline;
pub mod dumpfile;
pub mod dumpfile_parse;
pub mod erofs;
pub mod filesystem_ops;
pub mod fs;
pub mod fsverity;
pub mod mount;
pub mod mountcompat;
pub mod oci;
pub mod os_release;
pub mod repository;
pub mod selabel;
pub mod splitstream;
pub mod tree;
pub mod uki;
pub mod util;
pub mod write_boot;

#[cfg(test)]
pub(crate) mod test;

/// All files that contain 64 or fewer bytes (size <= INLINE_CONTENT_MAX) should be stored inline
/// in the erofs image (and also in splitstreams).  All files with 65 or more bytes (size > MAX)
/// should be written to the object storage and referred to from the image (and splitstreams).
pub const INLINE_CONTENT_MAX: usize = 64;
