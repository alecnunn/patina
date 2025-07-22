# Patina

A simple analysis tool for extracting metadata from Rust binaries. Patina helps researchers and analysts understand Rust
executables by identifying the compiler version, dependencies, and build characteristics - like the patina that forms on
oxidized metal reveals its history.

## Features

- Detects if a binary was compiled with Rust
- Extracts Rust compiler version information
- Identifies crate dependencies with version information
- Determines build profile (debug/release)
- Extracts project structure and source paths
- Detects panic handler and allocator types
- Works with both stripped and unstripped binaries
- Color-coded confidence levels for analysis results

## Installation

```bash
git clone https://github.com/alecnunn/patina
cd patina
cargo build --release
```

## Usage

```bash
./target/release/patina <path-to-binary>

# With verbose output
./target/release/patina <path-to-binary> -v

# Without colors (for piping or terminals without color support)
./target/release/patina <path-to-binary> --no-color
```

## Confidence Levels

Patina uses a three-tier confidence system:

- **High Confidence (Green)**: Exact matches such as version strings in .cargo/registry paths or explicit compiler version strings
- **Medium Confidence (Yellow)**: Heuristic matches with good context, such as version numbers near Rust-related strings
- **Low Confidence (Red/Dimmed)**: Basic pattern matching, especially common in stripped binaries

## Example Output

```
=== Patina Analysis Results ===
Binary: ./target/release/patina
Is Rust Binary: YES

Confidence Legend:
  ■ - High confidence (exact match)
  ■ - Medium confidence (heuristic)
  ■ - Low confidence (pattern match)

=== Compiler Information ===
Rust Version: 1.88.0
Compiler Info: rustc version 1.88.0 (6b00bc388 2025-06-23)
Panic Handler: std::panicking::rust_panic_with_hook
Allocator: System allocator
Build Profile: release
Target Triple: x86_64-pc-windows-msvc

=== Project Structure ===
Source Paths (10):
  /alloc/src/raw_vec/mod.rslibrary/alloc/src/string.rslibrary/alloc/src/ffi/c_str.rsa formatting trait implementation returned an error when the underlying stream did notlibrary/alloc/src/fmt.rslibrary/alloc/src/slice.rslibrary/alloc/src/sync.rs
  /core/src/char/methods.rsindex out of bounds: the len is library/core/src/fmt/builders.rslibrary/core/src/slice/memchr.rs
  /core/src/fmt/num.rs0x00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899library/core/src/fmt/mod.rsfalseuser-provided comparison function does not correctly implement a total orderlibrary/core/src/slice/sort/shared/smallsort.rsattempted to index slice from after maximum usizeattempted to index slice up to maximum usizelibrary/core/src/str/mod.rs
  /core/src/panicking.rs
  /core/src/str/pattern.rslibrary/core/src/str/lossy.rs
  /core/src/unicode/printable.rs
  /home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/collections/btree/map/entry.rs/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/collections/btree/node.rs
  /home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/collections/btree/navigate.rs/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/iter/traits/iterator.rs -> /home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/slice.rs
  /home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/raw_vec/mod.rs
  /home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/raw_vec/mod.rs/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/iter/traits/iterator.rsassertion failed: self.is_char_boundary(n)/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/string.rs/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/slice/index.rs/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/vec/mod.rs

Detected Crates (16):

  High Confidence:
    - aho-corasick v1.1.3
    - anstream v0.6.19
    - anstyle v1.0.11
    - anyhow v1.0.98
    - clap_builder v4.5.41
    - colored v3.0.0
    - goblin v0.10.0
    - memchr v2.7.5
    - regex v1.11.1
    - regex-automata v0.4.9
    - regex-syntax v0.8.5
    - strsim v0.11.1

  Medium Confidence:
    - addr2line v0.24.2
    - gimli v0.31.1
    - hashbrown v0.15.3
    - miniz_oxide v0.8.8
```

## How It Works

Patina analyzes binaries by:

1. Parsing the binary format (ELF, PE, Mach-O) using the `goblin` crate
2. Extracting ASCII strings from the binary data
3. Applying pattern matching to identify Rust-specific signatures
4. Categorizing findings by confidence level based on match quality

## Limitations

- Heavily obfuscated or packed binaries may not be detected correctly
- Some crate versions may only be detectable in unstripped binaries
- Detection accuracy decreases with aggressive optimization or stripping
- Custom panic handlers or allocators may not be recognized

## Use Cases

- Malware analysis and reverse engineering
- Security audits of Rust applications
- Dependency tracking in compiled binaries
- Build verification and forensics

## Why "Patina"?

Patina is the thin layer that forms on copper, bronze, and similar metals through oxidation. Just as patina on metal
reveals its age and history, this tool reveals the history and composition of Rust (oxidized iron) binaries.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests to improve detection patterns or add new features.
