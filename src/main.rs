// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

mod apply;
mod cli;
mod generate;
mod util;

use anyhow::Result;
use avbroot::cli::args::LogFormat;
use clap::{Parser, Subcommand};
use tracing::Level;

#[derive(Debug, Subcommand)]
pub enum Command {
    Apply(apply::ApplyCli),
    Generate(generate::GenerateCli),
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Lowest log message severity to output.
    #[arg(long, global = true, value_name = "LEVEL", default_value_t = Level::INFO)]
    pub log_level: Level,

    /// Output format for log messages.
    #[arg(long, global = true, value_name = "FORMAT", default_value_t = LogFormat::Medium)]
    pub log_format: LogFormat,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    avbroot::cli::args::init_logging(cli.log_level, cli.log_format);

    match cli.command {
        Command::Apply(c) => apply::apply_main(&c),
        Command::Generate(c) => generate::generate_main(&c),
    }
}
