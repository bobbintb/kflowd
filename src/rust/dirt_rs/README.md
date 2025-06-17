# dirt_rs: Filesystem Event Monitor with eBPF

`dirt_rs` is a filesystem event monitoring tool that uses eBPF (Extended Berkeley Packet Filter) to trace kernel functions and capture real-time data about file operations. It is a Rust port and enhancement of an original C-based `dirt` project.

It provides insights into process activities related to file creation, modification, deletion, and renames. Events are aggregated in the kernel and then sent to a user-space application which formats them as JSON for output to the console or a Unix domain socket.

## Features

- Kernel-level filesystem event tracing via eBPF.
- Monitors file create, modify, delete, and rename operations.
- Aggregates events in the kernel to reduce data volume.
- User-space application for collecting and processing event data.
- JSON output, with options for pretty-printing or compact format.
- Output to stdout or a specified Unix domain socket.
- Daemon mode for background operation.
- Configurable event aggregation parameters.

## Prerequisites

Ensure you have the following installed:

1.  **Rust Toolchain**: Stable and Nightly (for `rust-src` used by some eBPF libraries).
    ```shell
    rustup toolchain install stable
    rustup toolchain install nightly --component rust-src
    ```
2.  **LLVM and Clang**: Required for eBPF code compilation (typically version 12+).
    ```shell
    # Example for Ubuntu/Debian
    sudo apt-get install llvm clang
    ```
3.  **Kernel Headers**: Usually available via packages like `linux-headers-$(uname -r)` on Debian/Ubuntu.
    ```shell
    # Example for Ubuntu/Debian
    sudo apt-get install linux-headers-$(uname -r)
    ```
4.  **`bpf-linker`**: Install with `cargo install bpf-linker`.
    ```shell
    cargo install bpf-linker
    ```
5.  **Development Libraries**: Libelf and zlib are often needed.
    ```shell
    # Example for Ubuntu/Debian
    sudo apt-get install libelf-dev zlib1g-dev
    ```

(For cross-compilation, you would need to set up the appropriate target toolchain and sysroot for the eBPF programs, typically `bpfel-unknown-none`.)

## Build

Navigate to the root of this repository (the directory containing this README if you are in `src/rust/dirt_rs`). The project uses a workspace structure.

To build the entire project, including the eBPF program and the user-space application:

```shell
# From the repository root (e.g., /path/to/your-repo/ containing src/ )
cargo build --release
# Or, if you are already in src/rust/dirt_rs:
# cd ../../..
# cargo build --release
```

This will produce the user-space executable at `target/release/dirt_rs`. The eBPF object file will be compiled and embedded within this executable.

If you are specifically in the `src/rust/dirt_rs` directory, you can build just the user-space application (assuming the eBPF program is already built and its path is correctly referenced, though the embedding typically handles this):
```shell
# If currently in src/rust/dirt_rs
cargo build --release
```

## Running `dirt_rs`

The program requires root privileges to load eBPF programs and attach kprobes.

**Basic Usage (output to stdout, pretty JSON):**

```shell
# Assuming you are in the repository root
sudo ./target/release/dirt_rs
```

**Key Command-Line Options:**

*   `-a, --agg-events <EVENTS>`: Max number of filesystem events per aggregated record until export (e.g., `1` for no aggregation, `0` or unset for time/type-based aggregation).
*   `-o, --output-format <FORMAT>`: Output format. Options: `json` (pretty-printed, default), `json-min` (compact).
*   `-x, --unix-socket <SOCKET_PATH>`: Unix domain socket path to send JSON output to.
*   `-q, --quiet`: Quiet mode. Suppresses output to stdout if a socket path is also specified.
*   `-d, --daemon`: Daemonize the program to run in the background (requires `-x` to be specified).
*   `-V, --verbose`: Verbose output from the user-space application. For eBPF CO-RE and loading messages from Aya, set `RUST_LOG=aya=debug` (or `trace`) as an environment variable.
*   `-T, --token <TOKEN>`: Token to be included in JSON output. (Note: The actual inclusion of this token in the `RecordFs` JSON structure needs to be implemented in `dirt_rs-common`'s `Serialize` impl for `RecordFs` if not already present).
*   `-l, --legend`: Show legend for JSON fields and event types, then exit.
*   `-D, --debug-process-filter <PROCESS_FILTER>`: Debug filter for eBPF kernel messages (e.g., `*` for all, or a process name). (Note: eBPF-side filtering logic for this value is not yet implemented in `EbpfSettings`).
*   `--help`: Show help information.
*   `--version`: Show version information.

**Example (daemon mode, output to socket, no event count aggregation):**

```shell
# Assuming you are in the repository root
sudo ./target/release/dirt_rs -d -x /tmp/dirt_rs.sock -a 1
```
To see the output sent to the socket, you can use `socat`:
```shell
socat UNIX-RECV:/tmp/dirt_rs.sock -
```

## Output Format

Events are output as JSON objects, one per line, separated by a Record Separator character (`\x1e`) when output to stdout. Refer to the legend (run with the `-l` or `--legend` option) for details on specific JSON fields and event types.

## License

This project is primarily licensed under the Apache License, Version 2.0.
The eBPF components located in `dirt_rs-ebpf` are licensed under the General Public License (GPL), Version 2.0.

Please see the `LICENSE-APACHE`, `LICENSE-GPL-2.0`, and individual file headers for full license details.
