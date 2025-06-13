use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: CommandType,
}

#[derive(Debug, Parser)]
enum CommandType {
    Build(BuildOptions),
}

#[derive(Debug, Parser)]
pub struct BuildOptions {
    /// Target architecture
    #[clap(long, default_value = "bpfel-unknown-none")]
    target: String,
    /// Build profile (e.g., debug, release)
    #[clap(long, default_value = "release")]
    profile: String,
}

fn main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();

    match opts.command {
        CommandType::Build(build_opts) => build_ebpf(build_opts),
    }
}

fn build_ebpf(opts: BuildOptions) -> Result<(), anyhow::Error> {
    let target_arg = format!("--target={}", opts.target);
    let profile_arg = format!("--profile={}", opts.profile);

    let status = Command::new("cargo")
        .current_dir("..") // Run from the rust_bpf directory
        .arg("build")
        // .arg("--verbose") // Removed verbose flag
        .arg(target_arg)
        .arg(profile_arg)
        .arg("-Z") // Enable unstable features
        .arg("build-std=core,compiler_builtins") // Build core and compiler_builtins for BPF
        .status()
        .context("Failed to run cargo build")?;

    if !status.success() {
        anyhow::bail!("cargo build failed");
    }
    println!("eBPF program built successfully!");
    Ok(())
}
