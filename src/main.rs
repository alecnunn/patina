use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use goblin::Object;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "patina")]
#[command(about = "Analyze Rust binaries to extract metadata and crate information")]
struct Args {
    #[arg(help = "Path to the binary file to analyze")]
    binary_path: String,

    #[arg(short, long, help = "Verbose output")]
    verbose: bool,

    #[arg(short, long, help = "Disable colored output")]
    no_color: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Confidence {
    High,   // 100% accurate - exact matches, version strings
    Medium, // Heuristic - pattern matching with context
    Low,    // Pattern matched - basic string matching
}

#[derive(Debug)]
struct RustBinaryInfo {
    is_rust_binary: bool,
    rust_version: Option<(String, Confidence)>,
    crates: Vec<CrateInfo>,
    compiler_info: Option<(String, Confidence)>,
    is_stripped: bool,
    panic_handler: Option<(String, Confidence)>,
    allocator: Option<(String, Confidence)>,
    build_profile: Option<(String, Confidence)>,
    project_paths: Vec<(String, Confidence)>,
    target_triple: Option<(String, Confidence)>,
}

#[derive(Debug, Clone)]
struct CrateInfo {
    name: String,
    version: Option<String>,
    #[allow(dead_code)]
    path: Option<String>,
    confidence: Confidence,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    let binary_path = Path::new(&args.binary_path);
    if !binary_path.exists() {
        anyhow::bail!("Binary file does not exist: {}", args.binary_path);
    }

    let binary_data = fs::read(binary_path).context("Failed to read binary file")?;

    let info = analyze_rust_binary(&binary_data, args.verbose)?;

    print_analysis_results(&info, &args.binary_path);

    Ok(())
}

fn analyze_rust_binary(data: &[u8], verbose: bool) -> Result<RustBinaryInfo> {
    let mut info = RustBinaryInfo {
        is_rust_binary: false,
        rust_version: None,
        crates: Vec::new(),
        compiler_info: None,
        is_stripped: false,
        panic_handler: None,
        allocator: None,
        build_profile: None,
        project_paths: Vec::new(),
        target_triple: None,
    };

    // Check if it's a valid binary format and if it's stripped
    let obj = match Object::parse(data) {
        Ok(obj) => obj,
        Err(e) => {
            anyhow::bail!("Failed to parse binary: {}", e);
        }
    };

    info.is_stripped = is_binary_stripped(&obj);

    // Extract strings from the binary
    let strings = extract_strings(data, 6); // Lower threshold for stripped binaries

    // Look for Rust-specific patterns
    info.is_rust_binary = detect_rust_binary(&strings, info.is_stripped);

    if info.is_rust_binary {
        info.compiler_info = detect_compiler_info(&strings);
        info.rust_version = detect_rust_version(&strings);
        info.panic_handler = detect_panic_handler(&strings);
        info.allocator = detect_allocator(&strings);
        info.crates = detect_crates(&strings, info.is_stripped);
        info.build_profile = detect_build_profile(&strings);
        info.project_paths = detect_project_paths(&strings);
        info.target_triple = detect_target_triple(&strings);

        if verbose {
            println!("Found {} unique strings in binary", strings.len());
            println!("Binary is stripped: {}", info.is_stripped);
            println!("Detected as Rust binary: {}", info.is_rust_binary);
        }
    }

    Ok(info)
}

fn is_binary_stripped(obj: &Object) -> bool {
    match obj {
        Object::Elf(elf) => {
            // Check for symbol table
            elf.syms.is_empty()
        }
        Object::PE(pe) => {
            // Check for symbol table in PE
            pe.exports.is_empty()
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => macho.symbols.is_none(),
        Object::Mach(_) => false,
        _ => false,
    }
}

fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            if current.len() >= min_length {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_length {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    strings
}

fn detect_rust_binary(strings: &[String], is_stripped: bool) -> bool {
    // High confidence patterns
    let high_confidence_patterns = [
        "rust_begin_unwind",
        "rust_panic",
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "__rust_alloc_zeroed",
    ];

    // Medium confidence patterns
    let medium_confidence_patterns = [
        "core::panic",
        "std::panic",
        "alloc::vec",
        "core::result::Result",
        "core::option::Option",
        "std::thread",
        "std::sync",
    ];

    // Low confidence patterns (especially for stripped binaries)
    let low_confidence_patterns = [
        "rustc",
        ".rs:",
        "src/lib.rs",
        "src\\lib.rs",
        "src/main.rs",
        "src\\main.rs",
        "panic_bounds_check",
        "capacity overflow",
        "attempt to",
        "unwrap",
    ];

    let mut score = 0;

    for pattern in &high_confidence_patterns {
        if strings.iter().any(|s| s.contains(pattern)) {
            score += 10;
        }
    }

    for pattern in &medium_confidence_patterns {
        if strings.iter().any(|s| s.contains(pattern)) {
            score += 5;
        }
    }

    // Lower threshold for stripped binaries
    if is_stripped {
        for pattern in &low_confidence_patterns {
            if strings.iter().any(|s| s.contains(pattern)) {
                score += 2;
            }
        }
        score >= 10
    } else {
        score >= 15
    }
}

fn detect_rust_version(strings: &[String]) -> Option<(String, Confidence)> {
    // High confidence - explicit version string with "rustc" and version
    let version_regex = Regex::new(r"rustc\s+version\s+(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)").ok()?;
    for s in strings {
        if let Some(caps) = version_regex.captures(s) {
            return Some((caps[1].to_string(), Confidence::High));
        }
    }
    
    // High confidence - alternative rustc version format
    let alt_version_regex = Regex::new(r"rustc\s+(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)").ok()?;
    for s in strings {
        if let Some(caps) = alt_version_regex.captures(s) {
            let version = &caps[1];
            // Validate it's a reasonable Rust version (1.x.x)
            if version.starts_with("1.") {
                return Some((version.to_string(), Confidence::High));
            }
        }
    }

    // High confidence - extract from compiler info if we already have it
    if let Some(compiler_info) = detect_compiler_info(strings) {
        if let Some(caps) = alt_version_regex.captures(&compiler_info.0) {
            return Some((caps[1].to_string(), Confidence::High));
        }
    }

    // Medium confidence - version with commit hash
    let commit_version_regex =
        Regex::new(r"(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)\s*\([a-f0-9]{9,}\s+\d{4}-\d{2}-\d{2}\)")
            .ok()?;
    for s in strings {
        if let Some(caps) = commit_version_regex.captures(s) {
            let version = &caps[1];
            if version.starts_with("1.") {
                return Some((version.to_string(), Confidence::Medium));
            }
        }
    }

    // Medium confidence - version in rustc paths
    // Look for /rustc/HASH/library patterns
    let rustc_hash_regex = Regex::new(r"[/\\]rustc[/\\]([a-f0-9]{40})[/\\]").ok()?;
    let mut rustc_hash: Option<String> = None;
    
    // First find the rustc hash
    for s in strings {
        if let Some(caps) = rustc_hash_regex.captures(s) {
            rustc_hash = Some(caps[1].to_string());
            break;
        }
    }
    
    // If we found a rustc hash, look for version in strings containing "rustc version"
    if rustc_hash.is_some() {
        for s in strings {
            if s.contains("rustc version") || s.contains("rustc ") {
                let simple_version = Regex::new(r"\b(\d+\.\d+\.\d+)\b").ok()?;
                if let Some(caps) = simple_version.captures(s) {
                    let version = &caps[1];
                    if version.starts_with("1.") {
                        return Some((version.to_string(), Confidence::Medium));
                    }
                }
            }
        }
    }

    // Low confidence - version number near rust-related strings
    // Be more selective to avoid picking up dependency versions
    let simple_version = Regex::new(r"\b(\d+\.\d+\.\d+)\b").ok()?;
    for s in strings {
        // Only consider strings that explicitly mention rust/rustc/cargo
        if (s.contains("rustc") || s.contains("rust compiler") || s.contains("rust version"))
            && !s.contains("/deps/") && !s.contains("\\deps\\") 
            && !s.contains("/registry/") && !s.contains("\\registry\\") {
            if let Some(caps) = simple_version.captures(s) {
                let version = &caps[1];
                // Rust versions start with 1.x and are typically < 2.0
                if version.starts_with("1.") && version < "2.0.0" {
                    return Some((version.to_string(), Confidence::Low));
                }
            }
        }
    }

    None
}

fn detect_compiler_info(strings: &[String]) -> Option<(String, Confidence)> {
    // High confidence - full compiler info
    for s in strings {
        if s.contains("rustc") && s.contains("(") && s.contains(")") && s.contains("-") {
            if let Some(start) = s.find("rustc") {
                let potential = &s[start..];
                if potential.len() < 200 {
                    return Some((potential.to_string(), Confidence::High));
                }
            }
        }
    }

    // Medium confidence - partial compiler info
    for s in strings {
        if s.contains("/rustc/") && s.len() > 40 && s.len() < 200 {
            return Some((s.to_string(), Confidence::Medium));
        }
    }

    None
}

fn detect_panic_handler(strings: &[String]) -> Option<(String, Confidence)> {
    // Look for panic handler patterns
    let panic_patterns = [
        ("std::panicking::rust_panic_with_hook", Confidence::High),
        ("rust_begin_unwind", Confidence::High),
        ("panic_unwind", Confidence::Medium),
        ("panic_abort", Confidence::Medium),
        ("panic handler", Confidence::Low),
    ];

    for (pattern, confidence) in &panic_patterns {
        if strings.iter().any(|s| s.contains(pattern)) {
            return Some((pattern.to_string(), *confidence));
        }
    }

    None
}

fn detect_allocator(strings: &[String]) -> Option<(String, Confidence)> {
    // Look for allocator patterns
    let alloc_patterns = [
        ("__rust_alloc", "System allocator", Confidence::High),
        ("jemallocator", "jemalloc", Confidence::High),
        ("mimalloc", "mimalloc", Confidence::High),
        ("tcmalloc", "tcmalloc", Confidence::High),
        (
            "alloc::alloc::Global",
            "Global allocator",
            Confidence::Medium,
        ),
    ];

    for (pattern, name, confidence) in &alloc_patterns {
        if strings.iter().any(|s| s.contains(pattern)) {
            return Some((name.to_string(), *confidence));
        }
    }

    None
}

fn detect_crates(strings: &[String], is_stripped: bool) -> Vec<CrateInfo> {
    let mut crates = HashSet::new();
    let mut crate_infos = Vec::new();

    // Pattern 1: High confidence - .cargo/registry paths with versions
    let cargo_regex =
        Regex::new(r"\.cargo/registry/src/[^/]+/([a-zA-Z0-9_-]+)-(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)")
            .unwrap();

    // Pattern 1b: High confidence - .cargo/git checkouts (common in Windows)
    let cargo_git_regex =
        Regex::new(r"\.cargo[/\\]git[/\\]checkouts[/\\]([a-zA-Z0-9_-]+)-[a-f0-9]+[/\\][a-f0-9]+")
            .unwrap();

    // Pattern 2: Medium confidence - version in path
    let path_regex = Regex::new(r"/([a-zA-Z0-9_-]+)-(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)/").unwrap();

    // Pattern 3: Low confidence - module paths
    let module_regex = Regex::new(r"^([a-zA-Z0-9_]+)::").unwrap();

    for s in strings {
        // High confidence matches - cargo registry
        if let Some(caps) = cargo_regex.captures(s) {
            let name = caps[1].to_string();
            let version = caps[2].to_string();
            let key = format!("{name}-{version}");

            if crates.insert(key) {
                crate_infos.push(CrateInfo {
                    name,
                    version: Some(version),
                    path: Some(s.clone()),
                    confidence: Confidence::High,
                });
            }
        }
        // High confidence matches - cargo git
        else if let Some(caps) = cargo_git_regex.captures(s) {
            let name = caps[1].to_string();
            let key = format!("{name}-git");

            if crates.insert(key) && is_likely_crate_name(&name) {
                crate_infos.push(CrateInfo {
                    name,
                    version: None,
                    path: Some(s.clone()),
                    confidence: Confidence::High,
                });
            }
        }
        // Medium confidence matches
        else if let Some(caps) = path_regex.captures(s) {
            let name = caps[1].to_string();
            let version = caps[2].to_string();
            let key = format!("{name}-{version}");

            if crates.insert(key) && !name.starts_with("rust") && is_likely_crate_name(&name) {
                crate_infos.push(CrateInfo {
                    name,
                    version: Some(version),
                    path: Some(s.clone()),
                    confidence: Confidence::Medium,
                });
            }
        }
        // Low confidence - only use for stripped binaries or when we have few high confidence matches
        else if is_stripped || crate_infos.len() < 3 {
            if let Some(caps) = module_regex.captures(s) {
                let name = caps[1].to_string();
                if !crates.contains(&name) && is_likely_crate_name(&name) && name.len() > 3 {
                    crates.insert(name.clone());
                    crate_infos.push(CrateInfo {
                        name,
                        version: None,
                        path: None,
                        confidence: Confidence::Low,
                    });
                }
            }
        }
    }

    // Additional heuristics for common crates in stripped binaries
    if is_stripped {
        let common_crate_patterns = [
            ("serde", "serde"),
            ("tokio", "tokio"),
            ("hyper", "hyper"),
            ("reqwest", "reqwest"),
            ("clap", "clap"),
            ("anyhow", "anyhow"),
            ("thiserror", "thiserror"),
            ("druid", "druid"),
            ("piet", "piet"),
            ("rusqlite", "rusqlite"),
            ("rustls", "rustls"),
            ("ring", "ring"),
            ("tracing", "tracing"),
            ("futures", "futures"),
            ("async-std", "async_std"),
            ("winapi", "winapi"),
            ("windows", "windows"),
        ];

        for (pattern, name) in &common_crate_patterns {
            if !crates.contains(*name) && strings.iter().any(|s| s.contains(pattern)) {
                crates.insert(name.to_string());
                crate_infos.push(CrateInfo {
                    name: name.to_string(),
                    version: None,
                    path: None,
                    confidence: Confidence::Low,
                });
            }
        }
    }

    // Sort by confidence then by name
    crate_infos.sort_by(|a, b| match (a.confidence, b.confidence) {
        (Confidence::High, Confidence::High) => a.name.cmp(&b.name),
        (Confidence::High, _) => std::cmp::Ordering::Less,
        (_, Confidence::High) => std::cmp::Ordering::Greater,
        (Confidence::Medium, Confidence::Medium) => a.name.cmp(&b.name),
        (Confidence::Medium, _) => std::cmp::Ordering::Less,
        (_, Confidence::Medium) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    crate_infos
}

fn is_likely_crate_name(name: &str) -> bool {
    // Filter out common std/core modules and generic names
    let std_modules = [
        "std",
        "core",
        "alloc",
        "proc_macro",
        "test",
        "panic",
        "fmt",
        "io",
        "fs",
        "env",
        "path",
        "process",
        "thread",
        "sync",
        "cell",
        "rc",
        "vec",
        "string",
        "str",
        "slice",
        "option",
        "result",
        "error",
        "convert",
        "iter",
        "ops",
        "cmp",
        "clone",
        "default",
        "hash",
        "marker",
        "mem",
        "ptr",
        "raw",
        "intrinsics",
        "primitive",
        "keyword",
        "main",
        "lib",
        "mod",
        "impl",
        "trait",
        "fn",
        "enum",
        "struct",
        "type",
        "const",
        "static",
        "let",
        "mut",
    ];

    !std_modules.contains(&name) && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn detect_build_profile(strings: &[String]) -> Option<(String, Confidence)> {
    // High confidence - explicit debug/release paths
    for s in strings {
        if s.contains("/target/release/") || s.contains("\\target\\release\\") {
            return Some(("release".to_string(), Confidence::High));
        }
        if s.contains("/target/debug/") || s.contains("\\target\\debug\\") {
            return Some(("debug".to_string(), Confidence::High));
        }
    }

    // Medium confidence - debug assertions
    for s in strings {
        if s.contains("debug_assertions") || s.contains("debug_assert") {
            return Some(("debug".to_string(), Confidence::Medium));
        }
    }

    None
}

fn detect_project_paths(strings: &[String]) -> Vec<(String, Confidence)> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    // Look for source file paths
    let path_regex = Regex::new(r"((?:[A-Za-z]:)?(?:[/\\][^/\\]+)+\.rs)").unwrap();

    for s in strings {
        if let Some(caps) = path_regex.captures(s) {
            let path = caps[1].to_string();

            // Determine confidence based on path content
            let confidence = if path.contains("src/") || path.contains("src\\") {
                Confidence::High
            } else if path.contains(".rs") {
                Confidence::Medium
            } else {
                Confidence::Low
            };

            // Extract project-specific paths (not stdlib)
            if !path.contains("/rustc/")
                && !path.contains("\\rustc\\")
                && !path.contains("/.cargo/")
                && !path.contains("\\.cargo\\")
                && seen.insert(path.clone())
            {
                paths.push((path, confidence));
            }
        }
    }

    // Sort by confidence
    paths.sort_by(|a, b| match (a.1, b.1) {
        (Confidence::High, Confidence::High) => a.0.cmp(&b.0),
        (Confidence::High, _) => std::cmp::Ordering::Less,
        (_, Confidence::High) => std::cmp::Ordering::Greater,
        (Confidence::Medium, Confidence::Medium) => a.0.cmp(&b.0),
        (Confidence::Medium, _) => std::cmp::Ordering::Less,
        (_, Confidence::Medium) => std::cmp::Ordering::Greater,
        _ => a.0.cmp(&b.0),
    });

    paths.truncate(10); // Limit to 10 most relevant paths
    paths
}

fn detect_target_triple(strings: &[String]) -> Option<(String, Confidence)> {
    // Common target triples
    let target_patterns = [
        ("x86_64-pc-windows-msvc", Confidence::High),
        ("x86_64-pc-windows-gnu", Confidence::High),
        ("i686-pc-windows-msvc", Confidence::High),
        ("i686-pc-windows-gnu", Confidence::High),
        ("x86_64-unknown-linux-gnu", Confidence::High),
        ("x86_64-apple-darwin", Confidence::High),
        ("aarch64-apple-darwin", Confidence::High),
        ("aarch64-unknown-linux-gnu", Confidence::High),
    ];

    for (triple, confidence) in &target_patterns {
        if strings.iter().any(|s| s.contains(triple)) {
            return Some((triple.to_string(), *confidence));
        }
    }

    // Look for partial matches
    if strings.iter().any(|s| s.contains("pc-windows-msvc")) {
        return Some(("*-pc-windows-msvc".to_string(), Confidence::Medium));
    }
    if strings.iter().any(|s| s.contains("pc-windows-gnu")) {
        return Some(("*-pc-windows-gnu".to_string(), Confidence::Medium));
    }
    if strings.iter().any(|s| s.contains("unknown-linux-gnu")) {
        return Some(("*-unknown-linux-gnu".to_string(), Confidence::Medium));
    }

    None
}

fn format_with_confidence(text: &str, confidence: Confidence) -> ColoredString {
    match confidence {
        Confidence::High => text.green().bold(),
        Confidence::Medium => text.yellow(),
        Confidence::Low => text.red().dimmed(),
    }
}

fn print_confidence_legend() {
    println!("\n{}", "Confidence Legend:".bold());
    println!("  {} - High confidence (exact match)", "■".green().bold());
    println!("  {} - Medium confidence (heuristic)", "■".yellow());
    println!("  {} - Low confidence (pattern match)", "■".red().dimmed());
}

fn print_analysis_results(info: &RustBinaryInfo, binary_path: &str) {
    println!("\n{}", "=== Patina Analysis Results ===".bold());
    println!("{}: {}", "Binary".bold(), binary_path);

    if info.is_stripped {
        println!("{}: {}", "Status".bold(), "STRIPPED BINARY".red().bold());
    }

    println!(
        "{}: {}",
        "Is Rust Binary".bold(),
        if info.is_rust_binary {
            "YES".green().bold()
        } else {
            "NO".red().bold()
        }
    );

    if !info.is_rust_binary {
        println!("\n{}", "This does not appear to be a Rust binary.".red());
        return;
    }

    print_confidence_legend();

    println!("\n{}", "=== Compiler Information ===".bold());

    if let Some((version, conf)) = &info.rust_version {
        println!(
            "{}: {}",
            "Rust Version".bold(),
            format_with_confidence(version, *conf)
        );
    } else {
        println!("{}: {}", "Rust Version".bold(), "Unknown".dimmed());
    }

    if let Some((compiler, conf)) = &info.compiler_info {
        println!(
            "{}: {}",
            "Compiler Info".bold(),
            format_with_confidence(compiler, *conf)
        );
    }

    if let Some((handler, conf)) = &info.panic_handler {
        println!(
            "{}: {}",
            "Panic Handler".bold(),
            format_with_confidence(handler, *conf)
        );
    }

    if let Some((allocator, conf)) = &info.allocator {
        println!(
            "{}: {}",
            "Allocator".bold(),
            format_with_confidence(allocator, *conf)
        );
    }

    if let Some((profile, conf)) = &info.build_profile {
        println!(
            "{}: {}",
            "Build Profile".bold(),
            format_with_confidence(profile, *conf)
        );
    }

    if let Some((triple, conf)) = &info.target_triple {
        println!(
            "{}: {}",
            "Target Triple".bold(),
            format_with_confidence(triple, *conf)
        );
    }

    if !info.project_paths.is_empty() {
        println!("\n{}", "=== Project Structure ===".bold());
        println!("{} ({}):", "Source Paths".bold(), info.project_paths.len());
        for (path, conf) in &info.project_paths {
            println!("  {}", format_with_confidence(path, *conf));
        }
    }

    println!("\n{} ({}):", "Detected Crates".bold(), info.crates.len());

    // Group by confidence
    let high_conf: Vec<_> = info
        .crates
        .iter()
        .filter(|c| c.confidence == Confidence::High)
        .collect();
    let med_conf: Vec<_> = info
        .crates
        .iter()
        .filter(|c| c.confidence == Confidence::Medium)
        .collect();
    let low_conf: Vec<_> = info
        .crates
        .iter()
        .filter(|c| c.confidence == Confidence::Low)
        .collect();

    if !high_conf.is_empty() {
        println!("\n  {}", "High Confidence:".green().bold());
        for crate_info in &high_conf {
            print!("    - {}", crate_info.name.green().bold());
            if let Some(version) = &crate_info.version {
                print!(" v{}", version.green());
            }
            println!();
        }
    }

    if !med_conf.is_empty() {
        println!("\n  {}", "Medium Confidence:".yellow());
        for crate_info in &med_conf {
            print!("    - {}", crate_info.name.yellow());
            if let Some(version) = &crate_info.version {
                print!(" v{}", version.yellow());
            }
            println!();
        }
    }

    if !low_conf.is_empty() {
        println!("\n  {}", "Low Confidence:".red().dimmed());
        for crate_info in &low_conf {
            print!("    - {}", crate_info.name.red().dimmed());
            if let Some(version) = &crate_info.version {
                print!(" v{}", version.red().dimmed());
            }
            println!();
        }
    }

    if info.is_stripped {
        println!(
            "\n{}",
            "Note: Binary is stripped, some information may be missing or less accurate."
                .yellow()
                .italic()
        );
    }
}
