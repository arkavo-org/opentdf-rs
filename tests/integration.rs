use opentdf::{TdfArchive, TdfArchiveBuilder, TdfManifest};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use zip::ZipArchive;

#[test]
fn test_tdf_archive_structure_valid() -> Result<(), Box<dyn std::error::Error>> {
    let test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("sensitive.txt.tdf");

    let mut archive: TdfArchive<File> = TdfArchive::open(test_path)?;

    // Dump archive information
    println!("\n=== TDF Archive Information ===");
    println!("Total entries: {}", archive.len());

    // Read first entry
    let entry = archive.by_index()?;
    println!("\nEntry 0:");
    println!("  Manifest URL: {}", entry.manifest.payload.url);
    println!("  Payload Size: {} bytes", entry.payload.len());
    println!(
        "  Encryption Type: {}",
        entry.manifest.encryption_information.encryption_type
    );
    println!(
        "  Algorithm: {}",
        entry.manifest.encryption_information.method.algorithm
    );
    println!(
        "  Is Streamable: {}",
        entry.manifest.encryption_information.method.is_streamable
    );
    println!(
        "  Number of Key Access Entries: {}",
        entry.manifest.encryption_information.key_access.len()
    );
    println!("  Policy: {}", entry.manifest.get_policy()?);
    println!("===========================\n");

    // Validate structure
    archive.validate()?;

    Ok(())
}

#[test]
fn test_tdf_archive_structure() -> Result<(), Box<dyn std::error::Error>> {
    let test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("sensitive.txt.tdf");

    let file = std::fs::File::open(test_path)?;
    let mut archive = ZipArchive::new(file)?;

    // Dump all zip information
    println!("\n=== ZIP Archive Information ===");
    println!("Total files: {}", archive.len());

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        println!("\nFile Entry {}:", i);
        println!("  Name: {}", file.name());
        println!("  Size: {} bytes", file.size());
        println!("  Compressed Size: {} bytes", file.compressed_size());
        println!("  Compression Method: {:?}", file.compression());
        println!("  Comment: {}", file.comment());
        println!("  CRC32: {:X}", file.crc32());
        println!("  Modified: {:?}", file.last_modified());
        println!("  Is Directory: {}", file.is_dir());
        println!("  Is File: {}", file.is_file());
    }
    println!("===========================\n");

    // First, verify all required files exist
    let required_files = [
        "0.manifest.json",
        "0.payload",
        // "0.c2pa",
    ];

    for required_file in required_files {
        assert!(
            archive.by_name(required_file).is_ok(),
            "Missing required file: {}",
            required_file
        );
    }

    // Read all contents at once to avoid multiple mutable borrows
    let mut manifest_contents = String::new();
    archive
        .by_name("0.manifest.json")?
        .read_to_string(&mut manifest_contents)?;
    println!("Manifest Contents:\n{}", manifest_contents);
    let mut payload = Vec::new();
    archive.by_name("0.payload")?.read_to_end(&mut payload)?;

    // Now validate the contents
    // let manifest: serde_json::Value = serde_json::from_str(&manifest_contents)?;
    // TODO file bug with opentdf
    // assert!(manifest.get("version").is_some(), "Manifest missing version");
    TdfManifest::from_json(&manifest_contents)?;

    assert!(!payload.is_empty(), "Payload file is empty");

    Ok(())
}

#[test]
fn test_create_and_read_archive() -> Result<(), Box<dyn std::error::Error>> {
    use tempfile::NamedTempFile;

    // Create test data
    let manifest = TdfManifest::new(
        "0.payload".to_string(),
        "http://kas.example.com:4000".to_string(),
    );
    let payload = b"test payload data".to_vec();

    // Create archive
    let temp_file = NamedTempFile::new()?;
    let temp_path = temp_file.path().to_owned();

    let mut builder = TdfArchiveBuilder::new(&temp_path)?;
    builder.add_entry(&manifest, &payload, 0)?;
    builder.finish()?;

    // Read it back
    let mut archive = TdfArchive::open(&temp_path)?;
    let entry = archive.by_index()?;

    assert_eq!(entry.payload, payload);
    assert_eq!(entry.manifest.payload.url, "0.payload");

    Ok(())
}
