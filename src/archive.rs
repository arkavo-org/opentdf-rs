use crate::manifest::TdfManifest;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

#[cfg(feature = "kas")]
use crate::kas::{KasClient, KasError};

#[derive(Debug)]
pub struct TdfArchive<R: Read + Seek> {
    zip_archive: ZipArchive<R>,
}

#[derive(Debug)]
pub struct TdfEntry<'a> {
    pub manifest: TdfManifest,
    pub payload: Vec<u8>,
    #[allow(dead_code)]
    index: usize,
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
    /// let kas_client = KasClient::new("http://kas.example.com", "token")?;
    /// let mut archive = TdfArchive::open("example.tdf")?;
    /// let entry = archive.by_index()?;
    /// let plaintext = entry.decrypt_with_kas(&kas_client).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "kas")]
    pub async fn decrypt_with_kas(&self, kas_client: &KasClient) -> Result<Vec<u8>, TdfError> {
        use crate::crypto::TdfEncryption;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        // Unwrap the payload key using KAS
        let payload_key = kas_client.rewrap_standard_tdf(&self.manifest).await?;

        // Create TDF encryption instance with the unwrapped payload key from KAS
        // IMPORTANT: Use with_payload_key() not with_policy_key()!
        // The key from KAS IS the payload key, not a policy key
        let tdf_encryption = TdfEncryption::with_payload_key(&payload_key)
            .map_err(|e| TdfError::CryptoError("Invalid key from KAS".to_string(), Box::new(e)))?;

        // Check if this is a segmented TDF (modern format) or legacy (single block)
        let segments = &self
            .manifest
            .encryption_information
            .integrity_information
            .segments;

        if !segments.is_empty() {
            // Modern segmented format
            let (plaintext, gmac_tags) = tdf_encryption
                .decrypt_with_segments(&self.payload, segments)
                .map_err(|e| {
                    TdfError::CryptoError("Segment decryption failed".to_string(), Box::new(e))
                })?;

            // Verify root signature for integrity
            self.manifest
                .encryption_information
                .integrity_information
                .verify_root_signature(&gmac_tags, &payload_key)
                .map_err(|e| {
                    TdfError::CryptoError(
                        "Root signature verification failed".to_string(),
                        Box::new(e),
                    )
                })?;

            Ok(plaintext)
        } else {
            // Legacy single-block format
            let iv_b64 = &self.manifest.encryption_information.method.iv;
            let iv = BASE64
                .decode(iv_b64)
                .map_err(|e| TdfError::DecryptionError(format!("Invalid IV encoding: {}", e)))?;

            // Create decryption cipher
            use aes_gcm::{
                aead::{Aead, KeyInit},
                Aes256Gcm, Key, Nonce,
            };

            let key = Key::<Aes256Gcm>::from_slice(&payload_key);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&iv);

            // Decrypt the payload
            let plaintext = cipher.decrypt(nonce, self.payload.as_ref()).map_err(|e| {
                TdfError::DecryptionError(format!("AES-GCM decryption failed: {}", e))
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
    #[error("Invalid TDF structure: {0}")]
    Structure(String),
    #[cfg(feature = "kas")]
    #[error("KAS error: {0}")]
    KasError(#[from] KasError),
    #[cfg(feature = "kas")]
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[cfg(feature = "kas")]
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String, #[source] Box<dyn std::error::Error + Send + Sync>),
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
    /// let kas_client = KasClient::new("http://10.0.0.138:8080/kas", "token")?;
    /// let plaintext = TdfArchive::open_and_decrypt("example.tdf", &kas_client).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "kas")]
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

    /// Returns the number of TDF entries in the archive
    pub fn len(&self) -> usize {
        // Each TDF entry consists of a manifest and payload, so divide by 2
        self.zip_archive.len() / 2
    }

    /// Returns whether the archive is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets a TDF entry by index
    pub fn by_index(&mut self) -> Result<TdfEntry<'_>, TdfError> {
        self.get_entry(0)
    }

    /// Gets a specific TDF entry by index
    pub fn get_entry(&mut self, index: usize) -> Result<TdfEntry<'_>, TdfError> {
        let manifest_name = format!("{}.manifest.json", index);
        let payload_name = format!("{}.payload", index);

        // Read manifest
        let manifest = {
            let mut manifest_file = self.zip_archive.by_name(&manifest_name).map_err(|_| {
                TdfError::Structure(format!("Missing manifest file: {}", manifest_name))
            })?;
            let mut manifest_contents = String::new();
            manifest_file.read_to_string(&mut manifest_contents)?;
            TdfManifest::from_json(&manifest_contents)?
        };

        // Read payload
        let payload = {
            let mut payload_file = self.zip_archive.by_name(&payload_name).map_err(|_| {
                TdfError::Structure(format!("Missing payload file: {}", payload_name))
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

        // Write manifest
        self.writer.start_file::<_, ()>(
            format!("{}.manifest.json", index),
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(manifest_json.as_bytes())?;

        // Write payload with explicit type parameters
        self.writer.start_file::<_, ()>(
            format!("{}.payload", index),
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

        // Write manifest
        self.writer.start_file::<_, ()>(
            format!("{}.manifest.json", index),
            FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        self.writer.write_all(manifest_json.as_bytes())?;

        // Write payload - concatenate all segments
        self.writer.start_file::<_, ()>(
            format!("{}.payload", index),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    fn create_test_archive() -> Result<Vec<u8>, TdfError> {
        let manifest = TdfManifest::new(
            "0.payload".to_string(),
            "http://kas.example.com".to_string(),
        );
        let payload = b"test payload data".to_vec();

        let temp_file = NamedTempFile::new()?;
        let mut builder = TdfArchiveBuilder::new(temp_file.path())?;
        builder.add_entry(&manifest, &payload, 0)?;
        builder.finish()?;

        Ok(std::fs::read(temp_file.path())?)
    }

    #[test]
    fn test_tdf_archive_creation_and_reading() -> Result<(), TdfError> {
        let archive_data = create_test_archive()?;
        let cursor = Cursor::new(archive_data);
        let mut archive = TdfArchive::new(cursor)?;

        assert_eq!(archive.len(), 1);

        let entry = archive.by_index()?;
        assert_eq!(entry.payload, b"test payload data");
        assert_eq!(entry.manifest.payload.url, "0.payload");

        Ok(())
    }

    #[test]
    fn test_tdf_archive_validation() -> Result<(), TdfError> {
        let archive_data = create_test_archive()?;
        let cursor = Cursor::new(archive_data);
        let mut archive = TdfArchive::new(cursor)?;

        archive.validate()?;
        Ok(())
    }

    #[test]
    fn test_get_entry() -> Result<(), Box<dyn std::error::Error>> {
        use tempfile::NamedTempFile;

        // Create test data for multiple entries
        let entries = vec![
            (
                TdfManifest::new(
                    "0.payload".to_string(),
                    "https://kas1.example.com".to_string(),
                ),
                b"first payload data".to_vec(),
            ),
            (
                TdfManifest::new(
                    "1.payload".to_string(),
                    "https://kas2.example.com".to_string(),
                ),
                b"second payload data".to_vec(),
            ),
        ];

        // Create archive with multiple entries
        let temp_file = NamedTempFile::new()?;
        let temp_path = temp_file.path().to_owned();

        let mut builder = TdfArchiveBuilder::new(&temp_path)?;
        for (index, (manifest, payload)) in entries.iter().enumerate() {
            builder.add_entry(manifest, payload, index)?;
        }
        builder.finish()?;

        // Read it back using get_entry
        let mut archive = TdfArchive::open(&temp_path)?;

        // Verify correct number of entries
        assert_eq!(archive.len(), 2);

        // Verify first entry
        let entry0 = archive.get_entry(0)?;
        assert_eq!(entry0.payload, b"first payload data");
        assert_eq!(entry0.index, 0);
        assert_eq!(entry0.manifest.payload.url, "0.payload");
        assert_eq!(
            entry0.manifest.encryption_information.key_access[0].url,
            "https://kas1.example.com"
        );

        // Verify second entry
        let entry1 = archive.get_entry(1)?;
        assert_eq!(entry1.payload, b"second payload data");
        assert_eq!(entry1.index, 1);
        assert_eq!(entry1.manifest.payload.url, "1.payload");
        assert_eq!(
            entry1.manifest.encryption_information.key_access[0].url,
            "https://kas2.example.com"
        );

        // Verify error on invalid index
        let invalid_entry = archive.get_entry(2);
        assert!(invalid_entry.is_err());

        Ok(())
    }
}
