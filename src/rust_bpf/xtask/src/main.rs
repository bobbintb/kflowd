use anyhow::{Context, Result}; // Ensure anyhow is used for error handling
use clap::Parser;
use std::process::Command;
use std::fs;
use std::path::{Path, PathBuf};

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
    #[clap(long, default_value = "release")]
    profile: String,
    // Example: Add a field for the eBPF crate name if it's not always 'rust_bpf'
    // #[clap(long, default_value = "rust_bpf")]
    // ebpf_crate_name: String,
}

fn main() -> Result<()> {
    let opts = Options::parse();

    // Ensure we are running from the `src/rust_bpf/` directory for xtask,
    // or adjust paths accordingly. For this script, assume xtask is run
    // from `src/rust_bpf/` (i.e. `cargo xtask build`) or that paths are relative to `src/rust_bpf/`.
    // The `cargo xtask` command is typically run from the workspace root that defines it,
    // which is `src/rust_bpf/` in this case as `src/rust_bpf/Cargo.toml` has `[workspace] members = ["xtask"]`.
    // So, current_dir for commands should be `src/rust_bpf/` or paths adjusted.

    match opts.command {
        CommandType::Build(build_opts) => {
            let profile = build_opts.profile; // "release" or "debug"
            let target_arch = "bpfel-unknown-none";
            let ebpf_crate_name = "rust_bpf"; // Assuming this is the crate name

            println!("Building eBPF program '{}' with profile '{}'...", ebpf_crate_name, profile);

            // Step 1: Compile the eBPF Rust code using cargo build
            let mut cargo_build_cmd = Command::new("cargo");
            cargo_build_cmd.arg("+nightly") // Ensure nightly is used for this cargo command
                .arg("build")
                .arg("-Z").arg("build-std=core,compiler_builtins") // Pass -Z build-std directly to cargo
                .arg("--target").arg(target_arch)
                .arg(format!("--profile={}", profile)) // Uses release or debug from BuildOptions
                .arg("--package").arg(ebpf_crate_name) // Build only the eBPF package
                   .env("RUSTFLAGS", "-C debuginfo=2"); // Keep other RUSTFLAGS if any, or set as needed

            // Set current directory for cargo build if xtask is not in src/rust_bpf/
            // If xtask is in src/rust_bpf/xtask, current_dir should be "..".
            // Since Cargo.toml for rust_bpf defines xtask as a workspace member,
            // `cargo xtask` is run from `src/rust_bpf/`. So, no current_dir change needed for cargo build.

            let status = cargo_build_cmd.status()
                .with_context(|| format!("Failed to execute cargo build for {}", ebpf_crate_name))?;
            if !status.success() {
                anyhow::bail!("cargo build for {} failed with status: {}", ebpf_crate_name, status);
            }
            println!("Successfully compiled eBPF program '{}'.", ebpf_crate_name);

            // Step 2: Determine paths
            // Path to the compiled rlib (adjust if cargo changes output naming)
            let rlib_name = format!("lib{}.rlib", ebpf_crate_name);
            let rlib_path = PathBuf::from("target")
                .join(target_arch)
                   .join(&profile) // Use borrow
                .join(rlib_name);

            if !rlib_path.exists() {
                 anyhow::bail!("Compiled rlib not found at {:?}. Check crate name and build output.", rlib_path);
            }

            // Define the output path for the linked BPF object
               // linked_bpf_object_dir is the directory, does not include the filename itself.
            let linked_bpf_object_dir = PathBuf::from("target")
                .join(target_arch)
                   .join(&profile); // Use borrow for profile string
            let linked_bpf_object_filename = format!("{}.o", ebpf_crate_name); // e.g., rust_bpf.o
            let linked_bpf_object_path = linked_bpf_object_dir.join(&linked_bpf_object_filename);


            // Step 3: Run bpf-linker
            println!("Running bpf-linker on {:?} -> {:?}", rlib_path, linked_bpf_object_path);
            let mut bpf_linker_cmd = Command::new("bpf-linker");
            bpf_linker_cmd.arg(rlib_path.to_str().unwrap()) // Input .rlib file
                .arg("-o").arg(linked_bpf_object_path.to_str().unwrap()); // Output linked ELF object

            let status_linker = bpf_linker_cmd.status()
                .with_context(|| format!("Failed to execute bpf-linker for {:?}", rlib_path))?;
            if !status_linker.success() {
                anyhow::bail!("bpf-linker for {:?} failed with status: {}", rlib_path, status_linker);
            }
            println!("Successfully linked BPF object to {:?}.", linked_bpf_object_path);

            // Step 4: Copy the linked BPF object to the location dirt_rs expects
            // Destination path is relative to `src/rust_bpf/`
            let dirt_rs_bpf_object_path = PathBuf::from("../dirt_rs/dirt.bpf.o");

               // Ensure the destination directory exists
               if let Some(parent_dir) = dirt_rs_bpf_object_path.parent() {
                   if !parent_dir.exists() {
                       println!("Creating destination directory {:?}...", parent_dir);
                       fs::create_dir_all(parent_dir)
                           .with_context(|| format!("Failed to create destination directory {:?}", parent_dir))?;
                   }
               }

            println!("Copying {:?} to {:?}...", linked_bpf_object_path, dirt_rs_bpf_object_path);
            fs::copy(&linked_bpf_object_path, &dirt_rs_bpf_object_path)
                .with_context(|| format!("Failed to copy BPF object from {:?} to {:?}", linked_bpf_object_path, dirt_rs_bpf_object_path))?;
            println!("Successfully copied BPF object for dirt_rs.");
        }
    }
    Ok(())
}
