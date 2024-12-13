// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Seek, Write},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{Context, Result};
use avbroot::{
    cli::ota::ExtractCli,
    crypto::{self, RsaSigningKey},
    format::{
        ota::{self, SigningWriter, ZipEntry, ZipMode},
        payload::PayloadHeader,
    },
    protobuf::build::tools::releasetools::OtaMetadata,
    stream::CountingWriter,
};
use tracing::info;
use x509_cert::Certificate;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

pub const APEX_INFO: &str = "apex_info.pb";

/// Parse OTA metadata and payload header from a full OTA zip.
pub fn parse_metadata(path: &Path) -> Result<(OtaMetadata, PayloadHeader)> {
    let mut reader = File::open(path)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open for reading: {path:?}"))?;

    let (metadata, _, header, _) = ota::parse_zip_ota_info(&mut reader)
        .with_context(|| format!("Failed to parse OTA info from zip: {path:?}"))?;

    Ok((metadata, header))
}

/// Defer to `avbroot ota extract` for simplicity.
pub fn extract_image(input: &Path, output: &Path) -> Result<()> {
    let cli = ExtractCli {
        input: input.to_owned(),
        directory: output.to_owned(),
        all: true,
        boot_only: false,
        boot_partition: None,
        fastboot: false,
    };

    avbroot::cli::ota::extract_subcommand(&cli, &Arc::new(AtomicBool::new(false)))
}

/// Extract the entire contents of a zip file to the output directory.
pub fn extract_zip(input: &Path, output: &Path) -> Result<()> {
    let raw_reader = File::open(input)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open file: {input:?}"))?;
    let mut zip_reader =
        ZipArchive::new(raw_reader).with_context(|| format!("Failed to open zip: {output:?}"))?;

    zip_reader
        .extract(output)
        .with_context(|| format!("Failed to extract zip: {input:?} -> {output:?}"))?;

    Ok(())
}

/// Extract a single zip entry to the output file.
pub fn extract_zip_entry(input: &Path, name: &str, output: &Path) -> Result<()> {
    let raw_reader = File::open(input)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open file: {input:?}"))?;
    let mut zip_reader =
        ZipArchive::new(raw_reader).with_context(|| format!("Failed to open zip: {output:?}"))?;
    let mut entry = zip_reader
        .by_name(name)
        .with_context(|| format!("Failed to find entry: {name:?}: {input:?}"))?;
    let mut writer =
        File::create(output).with_context(|| format!("Failed to open file: {output:?}"))?;

    io::copy(&mut entry, &mut writer)
        .with_context(|| format!("Failed to extract entry: {input:?} ({name:?}) -> {output:?}"))?;

    Ok(())
}

/// Create a signed OTA zip with a dynamically-generated payload.
pub fn build_ota_zip(
    output: &Path,
    apex_info: &Path,
    key: &RsaSigningKey,
    cert: &Certificate,
    metadata: &OtaMetadata,
    create_payload: impl FnOnce(&mut dyn Write, &RsaSigningKey) -> Result<(String, u64)>,
) -> Result<()> {
    let raw_writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output)
        .with_context(|| format!("Failed to open for writing: {output:?}"))?;
    let buffered_writer = BufWriter::new(raw_writer);
    let signing_writer = SigningWriter::new_streaming(buffered_writer);
    let mut zip_writer = ZipWriter::new_streaming(signing_writer);

    let mut create_payload = Some(create_payload);
    let mut properties = None;
    let mut payload_metadata_size = None;
    let mut entries = vec![];
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);

    for path in [
        ota::PATH_PAYLOAD,
        ota::PATH_PROPERTIES,
        ota::PATH_OTACERT,
        APEX_INFO,
    ] {
        info!("Creating {path:?}");

        zip_writer
            .start_file_with_extra_data(path, options)
            .with_context(|| format!("Failed to begin new zip entry: {path}"))?;
        let offset = zip_writer
            .end_extra_data()
            .with_context(|| format!("Failed to end new zip entry: {path}"))?;
        let mut writer = CountingWriter::new(&mut zip_writer);

        match path {
            ota::PATH_PAYLOAD => {
                let (p, m) = create_payload.take().unwrap()(&mut writer, key)?;

                properties = Some(p);
                payload_metadata_size = Some(m);
            }
            ota::PATH_PROPERTIES => {
                writer.write_all(properties.as_ref().unwrap().as_bytes())?;
            }
            ota::PATH_OTACERT => {
                crypto::write_pem_cert(&mut writer, cert)?;
            }
            APEX_INFO => {
                let mut reader = File::open(apex_info)?;
                io::copy(&mut reader, &mut writer)?;
            }
            _ => unreachable!(),
        }

        // Cannot fail.
        let size = writer.stream_position()?;

        entries.push(ZipEntry {
            name: path.to_owned(),
            offset,
            size,
        });
    }

    let data_descriptor_size = 16;
    let metadata = ota::add_metadata(
        &entries,
        &mut zip_writer,
        // Offset where next entry would begin.
        entries.last().map(|e| e.offset + e.size).unwrap() + data_descriptor_size,
        metadata,
        payload_metadata_size.unwrap(),
        ZipMode::Streaming,
    )
    .context("Failed to write new OTA metadata")?;

    let signing_writer = zip_writer
        .finish()
        .context("Failed to finalize output zip")?;
    let buffered_writer = signing_writer
        .finish(key, cert, &AtomicBool::new(false))
        .context("Failed to sign output zip")?;
    let mut raw_writer = buffered_writer
        .into_inner()
        .context("Failed to flush output zip")?;
    raw_writer.flush().context("Failed to flush output zip")?;

    info!("Verifying metadata offsets");
    raw_writer.rewind()?;
    ota::verify_metadata(
        BufReader::new(&mut raw_writer),
        &metadata,
        payload_metadata_size.unwrap(),
    )
    .context("Failed to verify OTA metadata offsets")?;

    Ok(())
}
