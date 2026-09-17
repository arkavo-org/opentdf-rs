// Allow deprecated warnings for Nonce::from_slice() which is the correct API for aes-gcm 0.10.x
// This will be resolved when aes-gcm updates to generic-array 1.x
#![allow(deprecated)]

use crate::manifest::TdfManifest;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

#[cfg(feature = "kas-client")]
use opentdf_protocol::KasError;

#[cfg(feature = "kas-client")]
use crate::kas::KasClient;

#[cfg(feature = "kas-client")]
use crate::TdfEncryption;

#[cfg(feature = "kas-client")]
use crate::manifest::IntegrityInformationExt;

#[derive(Debug)]
pub struct TdfArchive<R: Read + Seek> {
    zip_archive: ZipArchive<R>,
}

/// Spec (opentdf/spec schema/OpenTDF/README.md): the manifest entry MUST be
/// `manifest.json` at the archive root.
pub const TDF_MANIFEST_FILE_NAME: &str = "manifest.json";
/// Name every SDK wrote before spec compliance; accepted on read forever.
pub const LEGACY_TDF_MANIFEST_FILE_NAME: &str = "0.manifest.json";
/// Default payload entry name. Written into `manifest.payload.url` by callers
/// of `TdfManifest::new`; on read it is only a fallback for an empty url.
pub const TDF_PAYLOAD_FILE_NAME: &str = "0.payload";

fn manifest_entry_name_for_index(index: usize) -> (String, Option<String>) {
    if index == 0 {
        (
            TDF_MANIFEST_FILE_NAME.to_string(),
            Some(LEGACY_TDF_MANIFEST_FILE_NAME.to_string()),
        )
    } else {
        (format!("{}.manifest.json", index), None)
    }
}

fn is_safe_entry_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.split('/').any(|seg| seg == "..")
}

fn is_manifest_entry_name(name: &str) -> bool {
    if name == TDF_MANIFEST_FILE_NAME {
        return true;
    }
    match name.strip_suffix(".manifest.json") {
        Some(prefix) => !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

fn payload_entry_name_for(manifest: &TdfManifest, index: usize) -> Result<String, TdfError> {
    let url = manifest.payload.url.as_str();
    if url.is_empty() {
        return Ok(if index == 0 {
            TDF_PAYLOAD_FILE_NAME.to_string()
        } else {
            format!("{}.payload", index)
        });
    }
    if !is_safe_entry_name(url) {
        return Err(TdfError::InvalidStructure {
            reason: format!("unsafe payload url in manifest: {url:?}"),
            expected: Some("a relative zip member name without '..' or leading '/'".to_string()),
        });
    }
    if is_manifest_entry_name(url) {
        return Err(TdfError::InvalidStructure {
            reason: format!("payload url collides with the manifest entry name: {url:?}"),
            expected: Some("a member name that is not shaped like a manifest entry".to_string()),
        });
    }
    Ok(url.to_string())
}

#[derive(Debug)]
pub struct TdfEntry<'a> {
    pub manifest: TdfManifest,
    pub payload: Vec<u8>,
    /// The index of this entry within the TDF archive
    pub index: usize,
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> TdfEntry<'a> {
    /// Decrypt the payload using KAS to unwrap the key
    ///
    /// This method:
    /// 1. Calls KAS to unwrap the payload key
    /// 2. Decrypts the payload using the unwrapped key
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use opentdf::{TdfArchive, kas::KasClient};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(
    ///     "https://kas.example.com",
    /// );
    /// let kas_client = KasClient::new(&config, "token")?;
    /// let mut archive = TdfArchive::open("example.tdf")?;
    /// let entry = archive.by_index()?;
    /// let plaintext = entry.decrypt_with_kas(&kas_client).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "kas-client")]
    pub async fn decrypt_with_kas(&self, kas_client: &KasClient) -> Result<Vec<u8>, TdfError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        // Unwrap the payload key using KAS
        // KasClient handles JWT signing internally
        let payload_key = kas_client.rewrap_standard_tdf(&self.manifest).await?;

        // Create TDF encryption instance with the unwrapped payload key from KAS
        // IMPORTANT: Use with_payload_key() not with_policy_key()!
        // The key from KAS IS the payload key, not a policy key
        let tdf_encryption =
            TdfEncryption::with_payload_key(&payload_key).map_err(|e| TdfError::CryptoError {
                algorithm: "AES-256-GCM".to_string(),
                reason: "Invalid key from KAS".to_string(),
                source: Some(Box::new(e)),
            })?;

        // Check if this is a segmented TDF (modern format) or legacy (single block)
        let segments = &self
            .manifest
            .encryption_information
            .integrity_information
            .segments;

        if !segments.is_empty() {
            // Modern segmented format
            // Convert Segment structs to (plaintext_size, encrypted_size) tuples
            let segment_sizes: Vec<(u64, u64)> = segments
                .iter()
                .map(|s| {
                    (
                        s.segment_size.unwrap_or(0),
                        s.encrypted_segment_size.unwrap_or(0),
                    )
                })
                .collect();

            let (plaintext, gmac_tags) = tdf_encryption
                .decrypt_with_segments(&self.payload, &segment_sizes)
                .map_err(|e| TdfError::CryptoError {
                    algorithm: "AES-256-GCM-segments".to_string(),
                    reason: "Segment decryption failed".to_string(),
                    source: Some(Box::new(e)),
                })?;

            // Verify root signature for integrity
            self.manifest
                .encryption_information
                .integrity_information
                .verify_root_signature(&gmac_tags, &payload_key)
                .map_err(|e| TdfError::CryptoError {
                    algorithm: "GMAC-SHA256".to_string(),
                    reason: format!("Root signature verification failed: {}", e),
                    source: None,
                })?;

            Ok(plaintext)
        } else {
            // Legacy single-block format
            let iv_b64 = &self.manifest.encryption_information.method.iv;
            let iv = BASE64
                .decode(iv_b64)
                .map_err(|e| TdfError::DecryptionFailed {
                    reason: format!("Invalid IV encoding: {}", e),
                    algorithm: Some("Base64".to_string()),
                })?;

            // Create decryption cipher
            use aes_gcm::{
                Aes256Gcm, Nonce,
                aead::{Aead, KeyInit},
            };

            let cipher = Aes256Gcm::new_from_slice(&payload_key).map_err(|_| {
                TdfError::DecryptionFailed {
                    reason: "Invalid key length".to_string(),
                    algorithm: Some("AES-256-GCM".to_string()),
                }
            })?;
            let nonce = Nonce::from_slice(&iv);

            // Decrypt the payload
            let plaintext = cipher.decrypt(nonce, self.payload.as_ref()).map_err(|e| {
                TdfError::DecryptionFailed {
                    reason: format!("AES-GCM decryption failed: {}", e),
                    algorithm: Some("AES-256-GCM".to_string()),
                }
            })?;

            Ok(plaintext)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TdfError {
    #[error("ZIP error: {0}")]
    ZipError(#[from] zip::result::ZipError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Invalid manifest: field '{field}' - {reason}")]
    InvalidManifest {
        field: String,
        reason: String,
        suggestion: Option<String>,
    },

    #[error("Invalid TDF structure: {reason}")]
    InvalidStructure {
        reason: String,
        expected: Option<String>,
    },

    #[error("Missing required field: {field}")]
    MissingRequiredField { field: &'static str },

    #[error("Invalid KAS URL: {url} - {reason}")]
    InvalidKasUrl { url: String, reason: KasUrlError },

    #[error("Cryptographic operation failed: {algorithm} - {reason}")]
    CryptoError {
        algorithm: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[cfg(feature = "kas-client")]
    #[error("KAS error: {0}")]
    KasError(#[from] KasError),

    #[cfg(feature = "kas-client")]
    #[error("Decryption failed: {reason}")]
    DecryptionFailed {
        reason: String,
        algorithm: Option<String>,
    },

    #[error("Policy validation failed for policy '{policy_id}': {errors:?}")]
    PolicyValidationFailed {
        policy_id: String,
        errors: Vec<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum KasUrlError {
    #[error("URL must use HTTPS scheme, not HTTP")]
    NotHttps,

    #[error("Invalid URL scheme: {0}")]
    InvalidScheme(String),

    #[error("Malformed URL: {0}")]
    MalformedUrl(String),

    #[error("Missing host in URL")]
    MissingHost,
}

impl TdfError {
    /// Returns true if this error might be resolved by retrying the operation
    pub fn is_retryable(&self) -> bool {
        match self {
            TdfError::IoError(_) => true,
            #[cfg(feature = "kas-client")]
            TdfError::KasError(kas_err) => kas_err.is_retryable(),
            _ => false,
        }
    }

    /// Returns a suggestion for how to fix this error, if available
    pub fn suggestion(&self) -> Option<&str> {
        match self {
            TdfError::InvalidManifest { suggestion, .. } => suggestion.as_deref(),
            TdfError::InvalidKasUrl {
                reason: KasUrlError::NotHttps,
                ..
            } => Some("Use HTTPS URLs for KAS endpoints (e.g., https://kas.example.com)"),
            TdfError::MissingRequiredField { field } if *field == "kas_url" => {
                Some("Provide a KAS URL using .kas_url() on the builder")
            }
            _ => None,
        }
    }

    /// Returns a stable error code for programmatic error handling
    ///
    /// Error codes follow the format: `OPENTDF_E_<CATEGORY>_<SPECIFIC>`
    /// These codes are stable across versions and safe for:
    /// - Cross-language bindings (FFI, WASM, etc.)
    /// - Programmatic error handling
    /// - Error telemetry and monitoring
    ///
    /// # Example
    /// ```
    /// # use opentdf::TdfError;
    /// # fn handle_error(err: TdfError) {
    /// match err.error_code() {
    ///     "OPENTDF_E_FIELD_REQUIRED" => { /* handle missing field */ }
    ///     "OPENTDF_E_KAS" => { /* handle KAS error */ }
    ///     _ => { /* handle unknown error */ }
    /// }
    /// # }
    /// ```
    pub fn error_code(&self) -> &'static str {
        match self {
            TdfError::ZipError(_) => "OPENTDF_E_ARCHIVE_ZIP",
            TdfError::JsonError(_) => "OPENTDF_E_ARCHIVE_JSON",
            TdfError::IoError(_) => "OPENTDF_E_IO",
            TdfError::InvalidManifest { .. } => "OPENTDF_E_MANIFEST_INVALID",
            TdfError::InvalidStructure { .. } => "OPENTDF_E_STRUCTURE_INVALID",
            TdfError::MissingRequiredField { .. } => "OPENTDF_E_FIELD_REQUIRED",
            TdfError::InvalidKasUrl { .. } => "OPENTDF_E_KAS_URL_INVALID",
            TdfError::CryptoError { .. } => "OPENTDF_E_CRYPTO",
            #[cfg(feature = "kas-client")]
            TdfError::KasError(_) => "OPENTDF_E_KAS",
            #[cfg(feature = "kas-client")]
            TdfError::DecryptionFailed { .. } => "OPENTDF_E_DECRYPTION_FAILED",
            TdfError::PolicyValidationFailed { .. } => "OPENTDF_E_POLICY_VALIDATION",
        }
    }
}

impl TdfArchive<File> {
    /// Opens a TDF archive from a file path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, TdfError> {
        let file = File::open(path)?;
        let zip_archive = ZipArchive::new(file)?;
        Ok(Self { zip_archive })
    }

    /// Open a TDF archive and decrypt its contents using KAS
    ///
    /// This is a convenience method that:
    /// 1. Opens the TDF archive
    /// 2. Reads the first entry
    /// 3. Decrypts the payload using KAS
    ///
    /// Returns the decrypted plaintext directly.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use opentdf::{TdfArchive, kas::KasClient};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(
    ///     "https://kas.example.com",
    /// );
    /// let kas_client = KasClient::new(&config, "token")?;
    /// let plaintext = TdfArchive::open_and_decrypt("example.tdf", &kas_client).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "kas-client")]
    pub async fn open_and_decrypt<P: AsRef<Path>>(
        path: P,
        kas_client: &KasClient,
    ) -> Result<Vec<u8>, TdfError> {
        let mut archive = Self::open(path)?;
        let entry = archive.by_index()?;
        entry.decrypt_with_kas(kas_client).await
    }
}

impl<R: Read + Seek> TdfArchive<R> {
    /// Creates a new TDF archive from a reader that implements Read + Seek
    pub fn new(reader: R) -> Result<Self, TdfError> {
        let zip_archive = ZipArchive::new(reader)?;
        Ok(Self { zip_archive })
    }

    /// Returns the number of TDF entries in the archive (one per manifest member).
    pub fn len(&self) -> usize {
        let mut count = 0;
        let mut saw_index0 = false;
        for name in self.zip_archive.file_names() {
            if name == TDF_MANIFEST_FILE_NAME || name == LEGACY_TDF_MANIFEST_FILE_NAME {
                if !saw_index0 {
                    saw_index0 = true;
                    count += 1;
                }
            } else if is_manifest_entry_name(name) {
                count += 1;
            }
        }
        count
    }

    /// Returns whether the archive is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets a TDF entry by index
    pub fn by_index(&mut self) -> Result<TdfEntry<'_>, TdfError> {
        self.get_entry(0)
    }

    fn has_member(&self, name: &str) -> bool {
        self.zip_archive.index_for_name(name).is_some()
    }

    /// Gets a specific TDF entry by index
    pub fn get_entry(&mut self, index: usize) -> Result<TdfEntry<'_>, TdfError> {
        let (primary, legacy) = manifest_entry_name_for_index(index);
        let manifest_name = if self.has_member(&primary) {
            primary.clone()
        } else if let Some(l) = legacy.filter(|l| self.has_member(l)) {
            l
        } else {
            return Err(TdfError::InvalidStructure {
                reason: format!("Missing manifest file: {}", primary),
                expected: Some(format!(
                    "TDF archive should contain {} (or legacy {})",
                    TDF_MANIFEST_FILE_NAME, LEGACY_TDF_MANIFEST_FILE_NAME
                )),
            });
        };

        // Read manifest
        let manifest = {
            let mut manifest_file = self.zip_archive.by_name(&manifest_name)?;
            let mut manifest_contents = String::new();
            manifest_file.read_to_string(&mut manifest_contents)?;
            TdfManifest::from_json(&manifest_contents)?
        };

        // Read payload, named by manifest.payload.url
        let payload_name = payload_entry_name_for(&manifest, index)?;
        let payload = {
            let mut payload_file = self.zip_archive.by_name(&payload_name).map_err(|_| {
                TdfError::InvalidStructure {
                    reason: format!("Missing payload file: {payload_name:?}"),
                    expected: Some(
                        "TDF archive should contain the member named by manifest.payload.url"
                            .to_string(),
                    ),
                }
            })?;
            let mut payload = Vec::new();
            payload_file.read_to_end(&mut payload)?;
            payload
        };

        Ok(TdfEntry {
            manifest,
            payload,
            index,
            _lifetime: std::marker::PhantomData,
        })
    }

    /// Validates the structure of the TDF archive
    pub fn validate(&mut self) -> Result<(), TdfError> {
        for i in 0..self.len() {
            // Attempt to read each entry
            self.get_entry(i)?;
        }
        Ok(())
    }
}

pub struct TdfArchiveBuilder {
    writer: ZipWriter<File>,
}

impl TdfArchiveBuilder {
    /// Creates a new TDF archive builder
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            writer: ZipWriter::new(file),
        })
    }

    /// Adds a TDF entry to the archive
    pub fn add_entry(
        &mut self,
        manifest: &TdfManifest,
        payload: &[u8],
        index: usize,
    ) -> Result<(), TdfError> {
        let manifest_json = manifest.to_json()?;
        let (manifest_name, _) = manifest_entry_name_for_index(index);
        let payload_name = payload_entry_name_for(manifest, index)?;

        // Write manifest
        self.writer.start_file::<_, ()>(
            manifest_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(manifest_json.as_bytes())?;

        // Write payload with explicit type parameters
        self.writer.start_file::<_, ()>(
            payload_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(payload)?;

        Ok(())
    }

    /// Adds a TDF entry with segmented payload to the archive
    ///
    /// This method supports segment-based encryption by writing segments sequentially
    pub fn add_entry_with_segments(
        &mut self,
        manifest: &TdfManifest,
        segments: &[Vec<u8>],
        index: usize,
    ) -> Result<(), TdfError> {
        let manifest_json = manifest.to_json()?;
        let (manifest_name, _) = manifest_entry_name_for_index(index);
        let payload_name = payload_entry_name_for(manifest, index)?;

        // Write manifest
        self.writer.start_file::<_, ()>(
            manifest_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(manifest_json.as_bytes())?;

        // Write payload - concatenate all segments
        self.writer.start_file::<_, ()>(
            payload_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;

        for segment in segments {
            self.writer.write_all(segment)?;
        }

        Ok(())
    }

    /// Finalizes the archive and returns the number of bytes written
    pub fn finish(self) -> Result<u64, TdfError> {
        let result = self.writer.finish()?;
        Ok(result.metadata()?.len())
    }
}

/// In-memory TDF archive builder for WASM compatibility
///
/// This builder creates TDF archives entirely in memory without requiring filesystem access,
/// making it suitable for WebAssembly environments.
pub struct TdfArchiveMemoryBuilder {
    writer: ZipWriter<io::Cursor<Vec<u8>>>,
}

impl TdfArchiveMemoryBuilder {
    /// Creates a new in-memory TDF archive builder
    pub fn new() -> Self {
        Self {
            writer: ZipWriter::new(io::Cursor::new(Vec::new())),
        }
    }

    /// Adds a TDF entry to the archive
    pub fn add_entry(
        &mut self,
        manifest: &TdfManifest,
        payload: &[u8],
        index: usize,
    ) -> Result<(), TdfError> {
        let manifest_json = manifest.to_json()?;
        let (manifest_name, _) = manifest_entry_name_for_index(index);
        let payload_name = payload_entry_name_for(manifest, index)?;

        // Write manifest
        self.writer.start_file::<_, ()>(
            manifest_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(manifest_json.as_bytes())?;

        // Write payload
        self.writer.start_file::<_, ()>(
            payload_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(payload)?;

        Ok(())
    }

    /// Adds a TDF entry with segmented payload to the archive
    pub fn add_entry_with_segments(
        &mut self,
        manifest: &TdfManifest,
        segments: &[Vec<u8>],
        index: usize,
    ) -> Result<(), TdfError> {
        let manifest_json = manifest.to_json()?;
        let (manifest_name, _) = manifest_entry_name_for_index(index);
        let payload_name = payload_entry_name_for(manifest, index)?;

        // Write manifest
        self.writer.start_file::<_, ()>(
            manifest_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(manifest_json.as_bytes())?;

        // Write payload - concatenate all segments
        self.writer.start_file::<_, ()>(
            payload_name,
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;

        for segment in segments {
            self.writer.write_all(segment)?;
        }

        Ok(())
    }

    /// Finalizes the archive and returns the bytes
    pub fn finish(self) -> Result<Vec<u8>, TdfError> {
        let cursor = self.writer.finish()?;
        Ok(cursor.into_inner())
    }
}

impl Default for TdfArchiveMemoryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;
    use zip::write::FileOptions;

    fn manifest_with_url(url: &str) -> TdfManifest {
        TdfManifest::new(url.to_string(), "http://kas.example.com".to_string())
    }

    fn create_test_archive() -> Result<Vec<u8>, TdfError> {
        let manifest = manifest_with_url("0.payload");
        let payload = b"test payload data".to_vec();
        let temp_file = NamedTempFile::new()?;
        let mut builder = TdfArchiveBuilder::new(temp_file.path())?;
        builder.add_entry(&manifest, &payload, 0)?;
        builder.finish()?;
        Ok(std::fs::read(temp_file.path())?)
    }

    /// Hand-build a zip with arbitrary member names, bypassing TdfArchiveBuilder.
    fn raw_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in members {
            w.start_file::<_, ()>(
                *name,
                FileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn names_of(bytes: &[u8]) -> Vec<String> {
        let mut z = ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
        (0..z.len())
            .map(|i| z.by_index(i).unwrap().name().to_string())
            .collect()
    }

    #[test]
    fn builder_writes_spec_manifest_name_and_payload_from_url() -> Result<(), TdfError> {
        let bytes = create_test_archive()?;
        let names = names_of(&bytes);
        assert!(names.contains(&"manifest.json".to_string()), "{names:?}");
        assert!(!names.contains(&"0.manifest.json".to_string()), "{names:?}");
        assert!(names.contains(&"0.payload".to_string()), "{names:?}");
        Ok(())
    }

    #[test]
    fn builder_payload_entry_follows_manifest_url() -> Result<(), TdfError> {
        let temp_file = NamedTempFile::new()?;
        let mut builder = TdfArchiveBuilder::new(temp_file.path())?;
        builder.add_entry(&manifest_with_url("data.bin"), b"abc", 0)?;
        builder.finish()?;
        let bytes = std::fs::read(temp_file.path())?;
        assert_eq!(names_of(&bytes), vec!["manifest.json", "data.bin"]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.by_index()?.payload, b"abc");
        Ok(())
    }

    #[test]
    fn memory_builder_matches_file_builder_names() -> Result<(), TdfError> {
        let mut b = TdfArchiveMemoryBuilder::new();
        b.add_entry(&manifest_with_url("0.payload"), b"x", 0)?;
        let bytes = b.finish()?;
        assert_eq!(names_of(&bytes), vec!["manifest.json", "0.payload"]);
        Ok(())
    }

    #[test]
    fn reader_accepts_legacy_manifest_name() -> Result<(), TdfError> {
        let m = manifest_with_url("0.payload").to_json()?;
        let bytes = raw_zip(&[("0.manifest.json", m.as_bytes()), ("0.payload", b"legacy")]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.len(), 1);
        assert_eq!(archive.by_index()?.payload, b"legacy");
        Ok(())
    }

    #[test]
    fn reader_prefers_spec_manifest_name_when_both_present() -> Result<(), TdfError> {
        let spec = manifest_with_url("a").to_json()?;
        let legacy = manifest_with_url("b").to_json()?;
        let bytes = raw_zip(&[
            ("0.manifest.json", legacy.as_bytes()),
            ("manifest.json", spec.as_bytes()),
            ("a", b"A"),
            ("b", b"B"),
        ]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.by_index()?.payload, b"A");
        Ok(())
    }

    #[test]
    fn reader_falls_back_to_0_payload_when_url_empty() -> Result<(), TdfError> {
        let m = manifest_with_url("").to_json()?;
        let bytes = raw_zip(&[("manifest.json", m.as_bytes()), ("0.payload", b"fb")]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.by_index()?.payload, b"fb");
        Ok(())
    }

    #[test]
    fn reader_errors_when_url_names_missing_entry() -> Result<(), TdfError> {
        let m = manifest_with_url("missing.bin").to_json()?;
        let bytes = raw_zip(&[("manifest.json", m.as_bytes()), ("0.payload", b"x")]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        let err = archive.by_index().unwrap_err();
        assert!(err.to_string().contains("missing.bin"), "{err}");
        Ok(())
    }

    #[test]
    fn reader_rejects_unsafe_payload_url() -> Result<(), TdfError> {
        for bad in ["../x", "/abs", "a\\b", "x/../y"] {
            let m = manifest_with_url(bad).to_json()?;
            // The safety check fires before any lookup, so no payload member is needed.
            let bytes = raw_zip(&[("manifest.json", m.as_bytes())]);
            let mut archive = TdfArchive::new(Cursor::new(bytes))?;
            let err = archive.by_index().unwrap_err();
            assert!(err.to_string().contains("unsafe"), "{bad}: {err}");
        }
        Ok(())
    }

    #[test]
    fn reader_rejects_payload_url_shaped_like_manifest_entry() -> Result<(), TdfError> {
        let m = manifest_with_url("2.manifest.json").to_json()?;
        // The collision check fires before any lookup, so no payload member is needed.
        let bytes = raw_zip(&[("manifest.json", m.as_bytes())]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        let err = archive.by_index().unwrap_err();
        assert!(err.to_string().contains("manifest"), "{err}");
        Ok(())
    }

    #[test]
    fn builder_rejects_payload_url_shaped_like_manifest_entry() -> Result<(), TdfError> {
        let temp_file = NamedTempFile::new()?;
        let mut builder = TdfArchiveBuilder::new(temp_file.path())?;
        let err = builder
            .add_entry(&manifest_with_url("2.manifest.json"), b"x", 0)
            .unwrap_err();
        assert!(err.to_string().contains("manifest"), "{err}");

        // Confirm the rejection happened before any member was written.
        let bytes = {
            builder.finish()?;
            std::fs::read(temp_file.path())?
        };
        assert!(names_of(&bytes).is_empty(), "{:?}", names_of(&bytes));
        Ok(())
    }

    #[test]
    fn len_counts_manifests_not_members() -> Result<(), TdfError> {
        let m = manifest_with_url("0.payload").to_json()?;
        let bytes = raw_zip(&[
            ("manifest.json", m.as_bytes()),
            ("0.payload", b"x"),
            ("extra.txt", b"y"),
        ]);
        let mut archive = TdfArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.len(), 1);
        archive.validate()?;
        Ok(())
    }

    #[test]
    fn test_tdf_archive_validation() -> Result<(), TdfError> {
        let mut archive = TdfArchive::new(Cursor::new(create_test_archive()?))?;
        archive.validate()?;
        Ok(())
    }

    #[test]
    fn test_get_entry_multi_index_keeps_indexed_names() -> Result<(), Box<dyn std::error::Error>> {
        let entries = [
            (
                manifest_with_url("0.payload"),
                b"first payload data".to_vec(),
            ),
            (
                manifest_with_url("1.payload"),
                b"second payload data".to_vec(),
            ),
        ];
        let temp_file = NamedTempFile::new()?;
        let temp_path = temp_file.path().to_owned();
        let mut builder = TdfArchiveBuilder::new(&temp_path)?;
        for (index, (manifest, payload)) in entries.iter().enumerate() {
            builder.add_entry(manifest, payload, index)?;
        }
        builder.finish()?;

        let bytes = std::fs::read(&temp_path)?;
        assert_eq!(
            names_of(&bytes),
            vec!["manifest.json", "0.payload", "1.manifest.json", "1.payload"]
        );

        let mut archive = TdfArchive::open(&temp_path)?;
        assert_eq!(archive.len(), 2);
        assert_eq!(archive.get_entry(0)?.payload, b"first payload data");
        assert_eq!(archive.get_entry(1)?.payload, b"second payload data");
        assert!(archive.get_entry(2).is_err());
        Ok(())
    }
}

/// Byte range of a Stored zip member's data, for `read_at`-style access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdfMemberLocation {
    /// Absolute offset of the member's first data byte in the archive.
    pub data_start: u64,
    /// Member length in bytes. Stored members are not compressed, so this is
    /// both the compressed and the uncompressed size.
    pub size: u64,
}

/// Writes a TDF whose payload is many Stored members rather than one
/// concatenated `0.payload`, with the manifest written **last**.
///
/// [`TdfArchiveBuilder`] writes the manifest first, which cannot express a
/// layout whose manifest carries a root signature over every segment tag.
pub struct TdfMultiEntryBuilder {
    writer: ZipWriter<File>,
}

impl TdfMultiEntryBuilder {
    /// Creates a builder writing to `path`.
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self {
            writer: ZipWriter::new(File::create(path)?),
        })
    }

    fn options(len: u64) -> FileOptions<'static, ()> {
        // `large_file` forces the ZIP64 extra field for a member's own sizes.
        // Local-header offsets past 4 GiB and a central directory past 4 GiB
        // are handled by the zip crate on their own: it adds the ZIP64
        // header-offset field whenever `header_start >= u32::MAX`, and writes
        // a ZIP64 EOCD whenever the directory offset or size crosses that
        // threshold. An archive of many sub-4 GiB members that together exceed
        // 4 GiB — the common shape for this layout — is therefore correct
        // without forcing the flag on every member.
        FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(len > u64::from(u32::MAX))
    }

    /// Adds one Stored member. `name` is used verbatim as the zip entry name,
    /// including any `/`, which this layout uses as part of a member name and
    /// not as a directory separator.
    pub fn add_member(&mut self, name: &str, bytes: &[u8]) -> Result<(), TdfError> {
        self.writer
            .start_file::<_, ()>(name, Self::options(bytes.len() as u64))?;
        self.writer.write_all(bytes)?;
        Ok(())
    }

    /// Writes the manifest as the final member and finalizes the archive.
    /// Returns the archive size in bytes.
    pub fn finish_with_manifest(
        mut self,
        name: &str,
        manifest: &TdfManifest,
    ) -> Result<u64, TdfError> {
        let json = manifest.to_json()?;
        self.writer
            .start_file::<_, ()>(name, Self::options(json.len() as u64))?;
        self.writer.write_all(json.as_bytes())?;
        let file = self.writer.finish()?;
        Ok(file.metadata()?.len())
    }
}

/// Central-directory map from member name to byte range, built once at open.
///
/// Random access is then a hash lookup plus a `seek`, with no scan of the
/// preceding members.
#[derive(Debug, Clone, Default)]
pub struct TdfMemberIndex {
    entries: std::collections::HashMap<String, TdfMemberLocation>,
}

impl TdfMemberIndex {
    /// Scans the central directory. Every member must be Stored, so a
    /// member's on-disk length equals its logical length.
    pub fn open<R: Read + Seek>(reader: R) -> Result<Self, TdfError> {
        let mut zip = ZipArchive::new(reader)?;
        let mut entries = std::collections::HashMap::with_capacity(zip.len());
        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            if entry.compression() != zip::CompressionMethod::Stored {
                return Err(TdfError::InvalidStructure {
                    reason: format!("member '{}' is not Stored", entry.name()),
                    expected: Some("compression method 0".to_string()),
                });
            }
            entries.insert(
                entry.name().to_string(),
                TdfMemberLocation {
                    data_start: entry.data_start(),
                    size: entry.size(),
                },
            );
        }
        Ok(Self { entries })
    }

    /// Looks up a member by its exact UTF-8 name.
    pub fn get(&self, name: &str) -> Option<TdfMemberLocation> {
        self.entries.get(name).copied()
    }

    /// Whether a member with this exact name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Number of members in the archive.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the archive has no members.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
