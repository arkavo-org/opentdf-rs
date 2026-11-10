//! Multi-entry TDF archive layout: Stored members, manifest last, and
//! central-directory random access by exact member name.

use opentdf::{
    DEFAULT_MAX_MANIFEST_SIZE, DEFAULT_MAX_PAYLOAD_SIZE, TdfError, TdfManifest, TdfMemberIndex,
    TdfMultiEntryBuilder,
};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};

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
        .map(|i| zip.by_index(i).unwrap().name().unwrap().into_owned())
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

/// Writes `header`, `s/1` and a manifest named `manifest_name`, returning
/// the archive bytes with the two members' contents.
fn archive_with_manifest_named(manifest_name: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("model.gguf.tdf");
    let header = vec![7u8; 92];
    let segment: Vec<u8> = (0..156u32).map(|i| i as u8).collect();

    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    builder.add_member("header", &header).unwrap();
    builder.add_member("s/1", &segment).unwrap();
    builder
        .finish_with_manifest(manifest_name, &manifest())
        .unwrap();
    (std::fs::read(&path).unwrap(), header, segment)
}

#[test]
fn read_member_and_read_into_return_the_member_bytes() {
    let (bytes, header, segment) = archive_with_manifest_named("0.manifest.json");
    let mut reader = Cursor::new(bytes);
    let index = TdfMemberIndex::open(&mut reader).unwrap();
    assert_eq!(index.max_member_size(), DEFAULT_MAX_PAYLOAD_SIZE);
    assert_eq!(index.max_manifest_size(), DEFAULT_MAX_MANIFEST_SIZE);

    // In any order, by exact name, including the forward slash.
    assert_eq!(index.read_member(&mut reader, "s/1").unwrap(), segment);
    assert_eq!(index.read_member(&mut reader, "header").unwrap(), header);

    // `read_into` replaces whatever the buffer held, longer or shorter.
    let mut buf = vec![0xEEu8; 4096];
    index.read_into(&mut reader, "header", &mut buf).unwrap();
    assert_eq!(buf, header);
    index.read_into(&mut reader, "s/1", &mut buf).unwrap();
    assert_eq!(buf, segment);

    // A name that is not a member, including a prefix of one.
    for missing in ["s", "s/2", ""] {
        let err = index.read_into(&mut reader, missing, &mut buf).unwrap_err();
        assert!(
            matches!(err, TdfError::InvalidStructure { .. }),
            "{missing:?}: {err:?}"
        );
        assert!(buf.is_empty(), "a failed read must not leave stale bytes");
    }

    // The same helpers work on a `File`, the reader the profile uses.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("on-disk.tdf");
    std::fs::write(&path, reader.into_inner()).unwrap();
    let mut file = File::open(&path).unwrap();
    assert_eq!(index.read_member(&mut file, "s/1").unwrap(), segment);
}

#[test]
fn read_member_enforces_the_member_size_limit() {
    let (bytes, header, segment) = archive_with_manifest_named("0.manifest.json");
    let mut reader = Cursor::new(bytes);
    let exact = segment.len() as u64;

    // Exactly at the limit is read; the smaller member is unaffected.
    let index = TdfMemberIndex::open(&mut reader)
        .unwrap()
        .with_max_member_size(exact);
    assert_eq!(index.max_member_size(), exact);
    assert_eq!(index.read_member(&mut reader, "s/1").unwrap(), segment);
    assert_eq!(index.read_member(&mut reader, "header").unwrap(), header);

    // One byte under the member's size refuses it and empties the buffer.
    let index = index.with_max_member_size(exact - 1);
    let mut buf = vec![0xEEu8; 16];
    let err = index.read_into(&mut reader, "s/1", &mut buf).unwrap_err();
    assert!(
        matches!(
            &err,
            TdfError::MemberTooLarge { member, limit } if member == "s/1" && *limit == exact - 1
        ),
        "{err:?}"
    );
    assert!(buf.is_empty());
    assert_eq!(index.read_member(&mut reader, "header").unwrap(), header);

    // The manifest has its own limit, so a tight member limit does not
    // stop it from being read.
    let index = index.with_max_member_size(1);
    assert_eq!(
        index.read_manifest(&mut reader).unwrap().payload.url,
        "header"
    );
}

#[test]
fn read_manifest_accepts_both_manifest_names_and_prefers_the_spec_one() {
    for name in ["0.manifest.json", "manifest.json"] {
        let (bytes, _, _) = archive_with_manifest_named(name);
        let mut reader = Cursor::new(bytes);
        let index = TdfMemberIndex::open(&mut reader).unwrap();
        let parsed = index.read_manifest(&mut reader).unwrap();
        assert_eq!(parsed.payload.url, "header", "{name}");
        assert_eq!(parsed.tdf_spec_version.as_deref(), Some("4.3.0"), "{name}");
    }

    // Both present: `manifest.json` wins, as it does for `TdfArchive`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("both.tdf");
    let legacy = TdfManifest::new("legacy".to_string(), "https://kas.example.com".to_string());
    let spec = TdfManifest::new("spec".to_string(), "https://kas.example.com".to_string());
    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    builder
        .add_member("0.manifest.json", legacy.to_json().unwrap().as_bytes())
        .unwrap();
    builder
        .finish_with_manifest("manifest.json", &spec)
        .unwrap();
    let mut file = File::open(&path).unwrap();
    let index = TdfMemberIndex::open(&mut file).unwrap();
    assert_eq!(index.read_manifest(&mut file).unwrap().payload.url, "spec");

    // Neither present.
    let path = dir.path().join("none.tdf");
    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    builder.add_member("header", &[1u8; 8]).unwrap();
    builder
        .finish_with_manifest("1.manifest.json", &manifest())
        .unwrap();
    let mut file = File::open(&path).unwrap();
    let index = TdfMemberIndex::open(&mut file).unwrap();
    let err = index.read_manifest(&mut file).unwrap_err();
    assert!(matches!(err, TdfError::InvalidStructure { .. }), "{err:?}");
}

#[test]
fn read_manifest_enforces_the_manifest_size_limit_and_reports_bad_json() {
    let (bytes, _, _) = archive_with_manifest_named("0.manifest.json");
    let mut reader = Cursor::new(bytes);
    let index = TdfMemberIndex::open(&mut reader).unwrap();
    let exact = index.get("0.manifest.json").unwrap().size;

    let index = index.with_max_manifest_size(exact);
    assert_eq!(index.max_manifest_size(), exact);
    index.read_manifest(&mut reader).unwrap();

    let index = index.with_max_manifest_size(exact - 1);
    let err = index.read_manifest(&mut reader).unwrap_err();
    assert!(
        matches!(
            &err,
            TdfError::MemberTooLarge { member, limit }
                if member == "0.manifest.json" && *limit == exact - 1
        ),
        "{err:?}"
    );

    // A manifest member that is not a manifest is a JSON error.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.tdf");
    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    builder.add_member("manifest.json", b"{ not json").unwrap();
    builder
        .finish_with_manifest("1.manifest.json", &manifest())
        .unwrap();
    let mut file = File::open(&path).unwrap();
    let index = TdfMemberIndex::open(&mut file).unwrap();
    let err = index.read_manifest(&mut file).unwrap_err();
    assert!(matches!(err, TdfError::JsonError(_)), "{err:?}");
}

/// The index describes the archive it was opened from. Reading through it
/// from a shorter one is an I/O error, not a short or stale buffer.
#[test]
fn read_member_from_a_truncated_archive_is_an_io_error() {
    let (bytes, _, _) = archive_with_manifest_named("0.manifest.json");
    let index = TdfMemberIndex::open(Cursor::new(bytes.clone())).unwrap();
    let location = index.get("s/1").unwrap();

    let cut = (location.data_start + location.size - 1) as usize;
    let mut truncated = Cursor::new(bytes[..cut].to_vec());
    let mut buf = vec![0xEEu8; 8];
    let err = index
        .read_into(&mut truncated, "s/1", &mut buf)
        .unwrap_err();
    assert!(matches!(err, TdfError::IoError(_)), "{err:?}");
    assert!(buf.is_empty());
}

#[test]
fn default_member_index_is_empty_with_the_default_limits() {
    let index = TdfMemberIndex::default();
    assert!(index.is_empty());
    assert_eq!(index.max_member_size(), DEFAULT_MAX_PAYLOAD_SIZE);
    assert_eq!(index.max_manifest_size(), DEFAULT_MAX_MANIFEST_SIZE);
}

/// The read path of the multi-entry layout, end to end: index the archive,
/// read the manifest, verify the root signature from its rows, then read
/// and decrypt each segment against its row.
#[test]
fn segments_verify_against_signed_manifest_rows_end_to_end() {
    use opentdf::TdfEncryption;
    use opentdf::manifest::{IntegrityError, IntegrityInformationExt};

    // Variable-length segments, one member each.
    let plaintexts: [&[u8]; 3] = [&[0x10; 92], &[0x20; 4096], &[0x30; 17]];
    let enc = TdfEncryption::new().unwrap();
    let key = enc.payload_key().to_vec();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("model.gguf.tdf");
    let mut builder = TdfMultiEntryBuilder::new(&path).unwrap();
    let mut written = manifest();
    let mut tags = Vec::new();
    let mut encrypted_sizes = Vec::new();
    for (i, plaintext) in plaintexts.iter().enumerate() {
        let segment = enc.encrypt_segment(plaintext).unwrap();
        builder
            .add_member(&format!("s/{i}"), &segment.bytes)
            .unwrap();
        written.add_segment(
            base64_tag(&segment.tag),
            Some(plaintext.len() as u64),
            Some(segment.bytes.len() as u64),
        );
        tags.push(segment.tag.to_vec());
        encrypted_sizes.push(segment.bytes.len() as u64);
    }
    written
        .encryption_information
        .integrity_information
        .generate_root_signature(&tags, &key)
        .unwrap();
    builder
        .finish_with_manifest("0.manifest.json", &written)
        .unwrap();

    // Reader: a member limit sized to the largest segment it expects.
    let mut file = File::open(&path).unwrap();
    let largest = encrypted_sizes.iter().copied().max().unwrap();
    let index = TdfMemberIndex::open(&mut file)
        .unwrap()
        .with_max_member_size(largest);
    let read = index.read_manifest(&mut file).unwrap();
    let integrity = &read.encryption_information.integrity_information;
    integrity.verify_root_signature_from_rows(&key).unwrap();

    let reader = TdfEncryption::with_payload_key(&key).unwrap();
    let mut member = Vec::new();
    for (i, plaintext) in plaintexts.iter().enumerate() {
        index
            .read_into(&mut file, &format!("s/{i}"), &mut member)
            .unwrap();
        let mut dest = vec![0u8; plaintext.len()];
        reader
            .decrypt_segment_into_verified(&member, &mut dest, &integrity.segments[i].hash)
            .unwrap();
        assert_eq!(dest, *plaintext);
    }

    // Member 2 presented as segment 0: it passes GCM under the same key and
    // is refused on the manifest row.
    index.read_into(&mut file, "s/2", &mut member).unwrap();
    let mut dest = vec![0xAAu8; plaintexts[2].len()];
    let err = reader
        .decrypt_segment_into_verified(&member, &mut dest, &integrity.segments[0].hash)
        .unwrap_err();
    assert!(
        matches!(err, opentdf::EncryptionError::SegmentHashMismatch),
        "{err:?}"
    );
    assert!(dest.iter().all(|b| *b == 0));

    // Rows swapped in the manifest no longer match the root signature.
    let mut swapped = integrity.clone();
    swapped.segments.swap(0, 2);
    let err = swapped.verify_root_signature_from_rows(&key).unwrap_err();
    assert!(matches!(err, IntegrityError::RootSignature(_)), "{err:?}");
}

fn base64_tag(tag: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(tag)
}
