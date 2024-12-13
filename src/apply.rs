// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    crypto::RsaSigningKey,
    format::payload::{PayloadHeader, PayloadWriter},
    stream::{self, PSeekFile},
};
use clap::Parser;
use tempfile::TempDir;

use crate::{cli::KeyGroup, util};

/// Create empty sparse images for each partition.
fn create_sparse_images(header: &PayloadHeader, images: &Path) -> Result<()> {
    for partition in &header.manifest.partitions {
        let name = &partition.partition_name;
        let path = images.join(format!("{name}.img"));
        let size = partition
            .new_partition_info
            .as_ref()
            .and_then(|info| info.size)
            .ok_or_else(|| anyhow!("Size not found for partition: {name}"))?;

        let file =
            File::create(&path).with_context(|| format!("Failed to create file: {path:?}"))?;

        file.set_len(size)
            .with_context(|| format!("Failed to truncate file: {path:?}"))?;
    }

    Ok(())
}

/// Apply a delta payload reading from the old images directory and writing to
/// the new images directory.
fn apply_delta_payload(
    input: &Path,
    header: &PayloadHeader,
    old_images: &Path,
    new_images: &Path,
    delta_generator: &Path,
) -> Result<()> {
    let mut command = Command::new(delta_generator);

    {
        let mut value = OsString::new();
        value.push("--in_file=");
        value.push(input);
        command.arg(value);
    }

    let partition_names = header
        .manifest
        .partitions
        .iter()
        .map(|p| p.partition_name.as_str())
        .collect::<Vec<_>>();
    command.arg(format!("--partition_names={}", partition_names.join(":")));

    {
        let mut value = OsString::new();
        value.push("--old_partitions=");
        for (i, name) in partition_names.iter().enumerate() {
            if i > 0 {
                value.push(":");
            }
            value.push(old_images.join(format!("{name}.img")));
        }
        command.arg(value);
    }

    {
        let mut value = OsString::new();
        value.push("--new_partitions=");
        for (i, name) in partition_names.iter().enumerate() {
            if i > 0 {
                value.push(":");
            }
            value.push(new_images.join(format!("{name}.img")));
        }
        command.arg(value);
    }

    println!("Running: {command:?}");

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to run: {delta_generator:?}"))?;

    let status = child.wait()?;
    if !status.success() {
        bail!("delta_generator failed with status: {status}");
    }

    Ok(())
}

/// Create a signed payload from the specified header and directory of partition
/// images. The only fields that will be updated are the install operations.
fn create_payload(
    writer: impl Write,
    header: &PayloadHeader,
    images: &Path,
    key: &RsaSigningKey,
) -> Result<(String, u64)> {
    let mut header = header.clone();

    for p in &mut header.manifest.partitions {
        let name = &p.partition_name;

        if Path::new(name).file_name() != Some(OsStr::new(name)) {
            bail!("Unsafe partition name: {name}");
        }

        // Clear out incremental OTA remnants.
        p.old_partition_info = None;
        p.merge_operations.clear();

        // Clear all fields that require a non-zero minor version. AOSP only
        // uses higher minor versions for incremental OTAs.
        p.hash_tree_data_extent = None;
        p.hash_tree_extent = None;
        p.hash_tree_algorithm = None;
        p.hash_tree_salt = None;
        p.fec_data_extent = None;
        p.fec_extent = None;
        p.fec_roots = None;
    }

    header.manifest.minor_version = Some(0);

    // Pre-open all of the image files.
    let input_files = header
        .manifest
        .partitions
        .iter()
        .map(|p| {
            let path = images.join(format!("{}.img", p.partition_name));
            let file = File::open(&path)
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to open file: {path:?}"))?;

            Ok((p.partition_name.clone(), file))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    // Compress the images and compute the list of install operations for
    // insertion into the payload header. The compressed data is stored in new
    // temp files and the original input files are dropped.
    let mut compressed_files = input_files
        .into_iter()
        .map(|(name, mut input_file)| {
            avbroot::cli::ota::compress_image(
                &name,
                &mut input_file,
                &mut header,
                None,
                &AtomicBool::new(false),
            )
            .with_context(|| format!("Failed to compress image: {name}"))?;

            Ok((name, input_file))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    println!("Generating new OTA payload");

    let mut payload_writer = PayloadWriter::new(writer, header.clone(), key.clone())
        .context("Failed to write payload header")?;

    while payload_writer
        .begin_next_operation()
        .context("Failed to begin next payload blob entry")?
    {
        let name = payload_writer.partition().unwrap().partition_name.clone();
        let operation = payload_writer.operation().unwrap();

        let Some(data_length) = operation.data_length else {
            // Otherwise, this is a ZERO/DISCARD operation.
            continue;
        };

        let pi = payload_writer.partition_index().unwrap();
        let oi = payload_writer.operation_index().unwrap();
        let orig_partition = &header.manifest.partitions[pi];
        let orig_operation = &orig_partition.operations[oi];
        let data_offset = orig_operation
            .data_offset
            .ok_or_else(|| anyhow!("Missing data_offset in partition #{pi} operation #{oi}"))?;

        // The compressed chunks are laid out sequentially and data_offset is
        // set to the offset within that file.
        let Some(input_file) = compressed_files.get_mut(&name) else {
            unreachable!("Compressed data not found for image: {name}");
        };

        input_file
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek image: {name}"))?;

        stream::copy_n(
            input_file,
            &mut payload_writer,
            data_length,
            &AtomicBool::new(false),
        )
        .with_context(|| format!("Failed to copy from replacement image: {name}"))?;
    }

    let (_, _, p, m) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok((p, m))
}

pub fn apply_main(cli: &ApplyCli) -> Result<()> {
    let (key, cert) = cli.key.load_key()?;

    println!("Creating temporary directories");
    let old_temp_dir = TempDir::new()?;
    let new_temp_dir = TempDir::new()?;
    let inc_temp_dir = TempDir::new()?;

    println!("Extracting full OTA");
    util::extract_image(&cli.input_old, old_temp_dir.path())?;

    println!("Extracting incremental OTA");
    util::extract_zip(&cli.input_inc, inc_temp_dir.path())?;

    println!("Parsing full OTA metadata");
    let (old_metadata, _) = util::parse_metadata(&cli.input_old)?;

    println!("Parsing incremental OTA metadata");
    let (inc_metadata, inc_header) = util::parse_metadata(&cli.input_inc)?;

    let apex_info = inc_temp_dir.path().join(util::APEX_INFO);
    let inc_payload = inc_temp_dir.path().join("payload.bin");

    println!("Creating skeleton partition images");
    create_sparse_images(&inc_header, new_temp_dir.path())?;

    println!("Applying delta payload.bin");
    apply_delta_payload(
        &inc_payload,
        &inc_header,
        old_temp_dir.path(),
        new_temp_dir.path(),
        &cli.delta_generator,
    )?;

    // We don't need the source images anymore.
    drop(old_temp_dir);

    println!("Creating full OTA zip");

    // Use the new metadata, but with the old full OTA's preconditions, which
    // won't make any assertions about the currently installed OS.
    let mut new_metadata = inc_metadata.clone();
    new_metadata.precondition = old_metadata.precondition.clone();

    util::build_ota_zip(
        &cli.output_new,
        &apex_info,
        &key,
        &cert,
        &new_metadata,
        |writer, key| create_payload(writer, &inc_header, new_temp_dir.path(), key),
    )?;

    Ok(())
}

/// Generate a full OTA from a full OTA and an incremental OTA.
///
/// The delta `payload.bin` application requires the `delta_generator`
/// executable from AOSP.
///
/// The system temporary directory must have enough space to extract both the
/// full and incremental OTAs and store two additional copies of the full OTA's
/// partition images. To use a different temporary directory, set the TMPDIR
/// environment variable.
#[derive(Debug, Parser)]
pub struct ApplyCli {
    /// Path to old full OTA zip file.
    #[arg(long, value_name = "FILE", value_parser)]
    input_old: PathBuf,

    /// Path to incremental OTA zip file.
    #[arg(long, value_name = "FILE", value_parser)]
    input_inc: PathBuf,

    /// Path to output full OTA zip file.
    #[arg(long, value_name = "FILE", value_parser)]
    output_new: PathBuf,

    /// Path to delta_generator executable.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "delta_generator"
    )]
    delta_generator: PathBuf,

    #[command(flatten)]
    key: KeyGroup,
}
