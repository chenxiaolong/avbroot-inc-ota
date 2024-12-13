// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

mod apply;
mod cli;
mod generate;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Subcommand)]
pub enum Command {
    Apply(apply::ApplyCli),
    Generate(generate::GenerateCli),
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Apply(c) => apply::apply_main(&c),
        Command::Generate(c) => generate::generate_main(&c),
    }
}
