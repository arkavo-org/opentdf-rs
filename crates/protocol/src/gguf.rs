//! `gguf-tdf/1` hybrid index (profile spec §9).
//!
//! Plaintext index carried on the OpenTDF manifest so a reader can map
//! `read_at(offset, len)` to zip members without decrypting the header first.
//! The index is redundant with "decrypt the header and parse GGUF" plus a
//! prefix sum of segment sizes; it exists to make random access a
//! central-directory lookup.

use serde::{Deserialize, Serialize};

/// Profile identifier for the index version defined by draft-00.
pub const GGUF_TDF_PROFILE_V1: &str = "gguf-tdf/1";

/// Top-level `gguf` object on a `gguf-tdf/1` manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GgufIndex {
    pub profile: String,
    /// GGUF `ALIGN`: `general.alignment` if present, else 32.
    pub alignment: u64,
    /// Virtual offset of GGUF `tensor_data` (`gguf_get_data_offset`).
    #[serde(rename = "headerBytes")]
    pub header_bytes: u64,
    /// Source GGUF file length in bytes.
    #[serde(rename = "virtualSize")]
    pub virtual_size: u64,
    /// Maximum plaintext size of a non-header segment.
    #[serde(rename = "maxSegment")]
    pub max_segment: u64,
    /// One entry per GGUF tensor, in GGUF file order.
    pub tensors: Vec<GgufTensor>,
    /// One entry per encrypted zip member; index 0 is the header.
    pub segments: Vec<GgufSegment>,
}

/// One GGUF tensor located in the virtual file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GgufTensor {
    pub name: String,
    /// Virtual file offset: `headerBytes + GGUF tensor offset`.
    pub offset: u64,
    /// Tensor data size in bytes, excluding trailing alignment padding.
    pub size: u64,
    /// Half-open `[start, end)` index range into [`GgufIndex::segments`].
    pub segments: [u64; 2],
}

/// One encrypted zip member and its plaintext length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GgufSegment {
    /// Equals the array index. Header is 0.
    pub id: u64,
    pub kind: GgufSegmentKind,
    /// Plaintext size; equals `integrityInformation.segments[id].segmentSize`.
    pub plain: u64,
    /// Zip member name: `header` or `s/{id}`.
    pub entry: String,
}

/// What a segment's plaintext covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GgufSegmentKind {
    /// Virtual `[0, headerBytes)`. Exactly one, at index 0.
    Header,
    /// Intersects exactly one tensor.
    Tensor,
    /// Intersects two or more tensors, or is padding only.
    Pack,
}
