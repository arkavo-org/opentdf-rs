//! Multi-entry TDF archive layout: Stored members, manifest last, and
//! central-directory random access by exact member name.

use opentdf::{TdfManifest, TdfMemberIndex, TdfMultiEntryBuilder};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

fn manifest() -> TdfManifest {
    let mut m = TdfManifest::new("header".to_string(), "https://kas.example.com".to_string());
    m.tdf_spec_version = Some("4.3.0".to_string());
    m
}

#[test]
fn multi_entry_archive_writes_manifest_last_and_indexes_members() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("model.gguf.tdf");

    let header_bytes = vec![7u8; 92];
    let seg1 = vec![9u8; 156];

    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    builder.add_member("header", &header_bytes).unwrap();
    builder.add_member("s/1", &seg1).unwrap();
    let size = builder
        .finish_with_manifest("0.manifest.json", &manifest())
        .unwrap();
    assert!(size > 0);

    // Central-directory order: the manifest is written after every segment,
    // because it carries a root signature over all of their tags.
    let mut file = File::open(&path).unwrap();
    let mut zip = zip::ZipArchive::new(&mut file).unwrap();
    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    assert_eq!(names, vec!["header", "s/1", "0.manifest.json"]);

    for i in 0..zip.len() {
        let entry = zip.by_index(i).unwrap();
        assert_eq!(entry.compression(), zip::CompressionMethod::Stored);
        assert_eq!(entry.compressed_size(), entry.size());
    }
    drop(zip);

    // Random access by exact name, including the forward slash.
    let mut file = File::open(&path).unwrap();
    let index = TdfMemberIndex::open(&mut file).unwrap();
    assert_eq!(index.len(), 3);

    let loc = index
        .get("s/1")
        .expect("s/1 must be addressable by its exact name");
    assert_eq!(loc.size, seg1.len() as u64);
    assert!(
        index.get("s").is_none(),
        "must not expose a synthetic directory entry for the s/ prefix"
    );
    assert!(index.get("1").is_none());

    let mut got = vec![0u8; loc.size as usize];
    file.seek(SeekFrom::Start(loc.data_start)).unwrap();
    file.read_exact(&mut got).unwrap();
    assert_eq!(got, seg1);

    // The header member is reachable the same way.
    let hloc = index.get("header").unwrap();
    let mut hgot = vec![0u8; hloc.size as usize];
    file.seek(SeekFrom::Start(hloc.data_start)).unwrap();
    file.read_exact(&mut hgot).unwrap();
    assert_eq!(hgot, header_bytes);
}

#[test]
fn manifest_member_round_trips_through_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.gguf.tdf");

    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    builder.add_member("header", &[1u8; 40]).unwrap();
    builder
        .finish_with_manifest("0.manifest.json", &manifest())
        .unwrap();

    let mut file = File::open(&path).unwrap();
    let index = TdfMemberIndex::open(&mut file).unwrap();
    let loc = index.get("0.manifest.json").unwrap();

    let mut json = vec![0u8; loc.size as usize];
    file.seek(SeekFrom::Start(loc.data_start)).unwrap();
    file.read_exact(&mut json).unwrap();

    let parsed = TdfManifest::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
    assert_eq!(parsed.payload.url, "header");
    assert_eq!(parsed.tdf_spec_version.as_deref(), Some("4.3.0"));
}

#[test]
fn member_index_rejects_a_deflated_archive() {
    // A Stored-only index must refuse compression, so a member's on-disk
    // length always equals its logical length.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deflated.zip");
    {
        let file = File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file::<_, ()>(
            "header",
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        std::io::Write::write_all(&mut zip, &[0u8; 512]).unwrap();
        zip.finish().unwrap();
    }

    let file = File::open(&path).unwrap();
    assert!(TdfMemberIndex::open(file).is_err());
}
