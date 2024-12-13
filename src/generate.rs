// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    crypto::RsaSigningKey,
    format::payload::{PayloadHeader, PayloadWriter},
    stream::{self, FromReader},
};
use clap::Parser;
use itertools::Itertools;
use tempfile::TempDir;

use crate::{cli::KeyGroup, util};

/// Generate the subset of `dynamic_partitions_info.txt` information that can
/// be obtained from the header of `payload.bin`. This is all that is needed for
/// delta_generator.
fn generate_dynamic_partitions_info(header: &PayloadHeader) -> String {
    let mut data = String::new();

    if let Some(d) = &header.manifest.dynamic_partition_metadata {
        data.push_str(&format!(
            "super_partition_groups={}\n",
            d.groups.iter().map(|g| &g.name).join(" "),
        ));

        for group in &d.groups {
            if let Some(size) = group.size {
                data.push_str(&format!("super_{}_group_size={}\n", group.name, size));
                data.push_str(&format!(
                    "super_{}_partition_list={}\n",
                    group.name,
                    group.partition_names.join(" "),
                ));
            }
        }

        if d.vabc_enabled == Some(true) {
            data.push_str("virtual_ab=true\n");
        }
        if let Some(method) = &d.vabc_compression_param {
            data.push_str("virtual_ab_compression=true\n");
            data.push_str(&format!("virtual_ab_compression_method={}\n", method));
        }
    }

    data
}

/// Generate `postinstall_config.txt` information from the header of
/// `payload.bin`.
fn generate_postinstall_config(header: &PayloadHeader) -> String {
    let mut data = String::new();

    for partition in &header.manifest.partitions {
        if let Some(v) = partition.run_postinstall {
            data.push_str(&format!(
                "RUN_POSTINSTALL_{}={}\n",
                partition.partition_name, v,
            ));
        }
        if let Some(p) = &partition.postinstall_path {
            data.push_str(&format!(
                "POSTINSTALL_PATH_{}={}\n",
                partition.partition_name, p,
            ));
        }
        if let Some(t) = &partition.filesystem_type {
            data.push_str(&format!(
                "FILESYSTEM_TYPE_{}={}\n",
                partition.partition_name, t,
            ));
        }
        if let Some(v) = partition.postinstall_optional {
            data.push_str(&format!(
                "POSTINSTALL_OPTIONAL_{}={}\n",
                partition.partition_name, v,
            ));
        }
    }

    data
}

/// Generate an unsigned delta payload from two directories of complete
/// partition images.
#[allow(clippy::too_many_arguments)]
fn generate_delta_payload(
    output: &Path,
    new_header: &PayloadHeader,
    old_images: &Path,
    new_images: &Path,
    apex_info: &Path,
    dynamic_partitions_info: &Path,
    postinstall_config: &Path,
    delta_generator: &Path,
) -> Result<()> {
    let mut command = Command::new(delta_generator);

    {
        let mut value = OsString::new();
        value.push("--out_file=");
        value.push(output);
        command.arg(value);
    }

    let partition_names = new_header
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

    command.arg("--enable_zucchini=true");
    command.arg("--enable_lz4diff=false");
    command.arg("--enable_vabc_xor=true");
    command.arg("--major_version=2");
    command.arg("--minor_version=8");

    if let Some(t) = new_header.manifest.max_timestamp {
        command.arg(format!("--max_timestamp={t}"));
    }

    let timestamps = new_header
        .manifest
        .partitions
        .iter()
        .filter_map(|p| p.version.as_ref().map(|v| (&p.partition_name, v)))
        .map(|(n, v)| format!("{n}:{v}"))
        .join(",");
    command.arg(format!("--partition_timestamps={timestamps}"));

    {
        let mut value = OsString::new();
        value.push("--apex_info_file=");
        value.push(apex_info);
        command.arg(value);
    }

    {
        let mut value = OsString::new();
        value.push("--dynamic_partition_info_file=");
        value.push(dynamic_partitions_info);
        command.arg(value);
    }

    {
        let mut value = OsString::new();
        value.push("--new_postinstall_config_file=");
        value.push(postinstall_config);
        command.arg(value);
    }

    if let Some(level) = &new_header.manifest.security_patch_level {
        command.arg(format!("--security_patch_level={level}"));
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

/// Sign a (potentially unsigned) payload without making any other
/// modifications to it.
fn sign_payload(
    unsigned_payload: &Path,
    writer: impl Write,
    key: &RsaSigningKey,
) -> Result<(String, u64)> {
    let inc_raw_reader = File::open(unsigned_payload)
        .with_context(|| format!("Failed to open for reading: {unsigned_payload:?}"))?;
    let mut inc_reader = BufReader::new(inc_raw_reader);
    let inc_header = PayloadHeader::from_reader(&mut inc_reader)
        .with_context(|| format!("Failed to parse payload header: {unsigned_payload:?}"))?;

    let mut payload_writer = PayloadWriter::new(writer, inc_header.clone(), key.clone())
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

        // Copy from the original payload.
        let pi = payload_writer.partition_index().unwrap();
        let oi = payload_writer.operation_index().unwrap();
        let orig_partition = &inc_header.manifest.partitions[pi];
        let orig_operation = &orig_partition.operations[oi];

        let data_offset = orig_operation
            .data_offset
            .and_then(|o| o.checked_add(inc_header.blob_offset))
            .ok_or_else(|| anyhow!("Missing data_offset in partition #{pi} operation #{oi}"))?;

        inc_reader
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek original payload to {data_offset}"))?;

        stream::copy_n(
            &mut inc_reader,
            &mut payload_writer,
            data_length,
            &Arc::new(AtomicBool::new(false)),
        )
        .with_context(|| format!("Failed to copy from original payload: {name}"))?;
    }

    let (_, _, p, m) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok((p, m))
}

pub fn generate_main(cli: &GenerateCli) -> Result<()> {
    let (key, cert) = cli.key.load_key()?;

    println!("Creating temporary directories");
    let old_temp_dir = TempDir::new()?;
    let new_temp_dir = TempDir::new()?;
    let inc_temp_dir = TempDir::new()?;

    println!("Extracting old OTA");
    util::extract_image(&cli.input_old, old_temp_dir.path())?;

    println!("Extracting new OTA");
    util::extract_image(&cli.input_new, new_temp_dir.path())?;

    println!("Parsing old full OTA metadata");
    let (old_metadata, _) = util::parse_metadata(&cli.input_old)?;

    println!("Parsing new full OTA metadata");
    let (new_metadata, new_header) = util::parse_metadata(&cli.input_new)?;

    let apex_info = inc_temp_dir.path().join(util::APEX_INFO);
    let dynamic_partitions_info = inc_temp_dir.path().join("dynamic_partitions_info.txt");
    let postinstall_config = inc_temp_dir.path().join("postinstall_config.txt");
    let unsigned_payload = inc_temp_dir.path().join("payload.bin");

    println!("Extracting apex_info.pb from new OTA");
    util::extract_zip_entry(&cli.input_new, util::APEX_INFO, &apex_info)?;

    println!("Creating partial dynamic_partitions_info.txt");
    fs::write(
        &dynamic_partitions_info,
        generate_dynamic_partitions_info(&new_header),
    )?;

    println!("Creating postinstall_config.txt");
    fs::write(
        &postinstall_config,
        generate_postinstall_config(&new_header),
    )?;

    println!("Generating unsigned delta payload.bin");
    generate_delta_payload(
        &unsigned_payload,
        &new_header,
        old_temp_dir.path(),
        new_temp_dir.path(),
        &apex_info,
        &dynamic_partitions_info,
        &postinstall_config,
        &cli.delta_generator,
    )?;

    // We don't need the source images anymore.
    drop(old_temp_dir);
    drop(new_temp_dir);

    println!("Creating incremental OTA zip");

    // Set up preconditions checks to ensure that the incremental OTA can only
    // be applied on top of the correct source OS build.
    let mut inc_metadata = new_metadata.clone();
    let inc_precondition = inc_metadata
        .precondition
        .as_mut()
        .ok_or_else(|| anyhow!("New full OTA has no preconditions"))?;
    let old_postcondition = old_metadata
        .postcondition
        .as_ref()
        .ok_or_else(|| anyhow!("Old full OTA has no postconditions"))?;
    inc_precondition.build.clone_from(&old_postcondition.build);
    inc_precondition
        .build_incremental
        .clone_from(&old_postcondition.build_incremental);

    util::build_ota_zip(
        &cli.output_inc,
        &apex_info,
        &key,
        &cert,
        &inc_metadata,
        |writer, key| sign_payload(&unsigned_payload, writer, key),
    )?;

    Ok(())
}

/// Generate an incremental OTA from two full OTAs.
///
/// The delta `payload.bin` generation requires the `delta_generator` executable
/// from AOSP.
///
/// The system temporary directory must have enough space to extract both full
/// OTAs and store the delta payload. To use a different temporary directory,
/// set the TMPDIR environment variable.
#[derive(Debug, Parser)]
pub struct GenerateCli {
    /// Path to old full OTA zip file.
    #[arg(long, value_name = "FILE", value_parser)]
    input_old: PathBuf,

    /// Path to new full OTA zip file.
    #[arg(long, value_name = "FILE", value_parser)]
    input_new: PathBuf,

    /// Path to output incremental OTA zip file.
    #[arg(long, value_name = "FILE", value_parser)]
    output_inc: PathBuf,

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
