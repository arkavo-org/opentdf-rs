// tests/integration/tdf_archive.rs
use std::path::PathBuf;
use std::io::Read;
use zip::ZipArchive;
use opentdf_rs::TdfManifest;

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
            "Missing required file: {}", required_file
        );
    }

    // Read all contents at once to avoid multiple mutable borrows
    let mut manifest_contents = String::new();
    archive.by_name("0.manifest.json")?.read_to_string(&mut manifest_contents)?;
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
