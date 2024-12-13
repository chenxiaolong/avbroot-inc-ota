// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context, Result};
use avbroot::crypto::{self, PassphraseSource, RsaSigningKey};
use clap::Args;
use x509_cert::Certificate;

#[derive(Debug, Args)]
pub struct KeyGroup {
    /// Private key for signing the OTA.
    ///
    /// This should normally be a private key. However, if --signing-helper is
    /// used, then it should be a public key instead.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub key: PathBuf,

    /// Certificate for OTA signing key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub cert: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_name = "ENV_VAR", value_parser, group = "pass")]
    pub pass_env_var: Option<OsString>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_name = "FILE", value_parser, group = "pass")]
    pub pass_file: Option<PathBuf>,

    /// External program for signing.
    ///
    /// If this option is specified, then --key must refer to a public key. The
    /// program will be invoked as:
    ///
    /// <program> <algo> <public key> [file <pass file>|env <pass env>]
    #[arg(long, value_name = "PROGRAM", value_parser)]
    pub signing_helper: Option<PathBuf>,
}

impl KeyGroup {
    pub fn load_key(&self) -> Result<(RsaSigningKey, Certificate)> {
        let passphrase_source = PassphraseSource::new(
            &self.key,
            self.pass_file.as_deref(),
            self.pass_env_var.as_deref(),
        );
        let key = if let Some(helper) = &self.signing_helper {
            let public_key = crypto::read_pem_public_key_file(&self.key)
                .with_context(|| format!("Failed to load public key: {:?}", self.key))?;

            RsaSigningKey::External {
                program: helper.clone(),
                public_key_file: self.key.clone(),
                public_key,
                passphrase_source,
            }
        } else {
            let private_key = crypto::read_pem_key_file(&self.key, &passphrase_source)
                .with_context(|| format!("Failed to load private key: {:?}", self.key))?;

            RsaSigningKey::Internal(private_key)
        };

        let cert = crypto::read_pem_cert_file(&self.cert)
            .with_context(|| format!("Failed to load certificate: {:?}", self.cert))?;

        Ok((key, cert))
    }
}
