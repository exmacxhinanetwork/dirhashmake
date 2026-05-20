use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use clap::Parser;
use csv::Writer;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
enum EntryType {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone)]
struct Entry {
    path: PathBuf,
    relative_path: PathBuf,
    entry_type: EntryType,
    sha256: Option<String>,
    size: Option<u64>,
    modified: Option<DateTime<Utc>>,
    link_target: Option<String>,
}

#[derive(Debug)]
struct ScanStats {
    total_entries: u64,
    total_files: u64,
    total_dirs: u64,
    total_symlinks: u64,
    total_bytes: u64,
    scan_duration: Duration,
}

#[derive(Parser)]
#[command(name = "dirhashmake")]
struct Args {
    #[arg(default_value = ".")]
    directory: PathBuf,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(short = 'j', long)]
    jobs: Option<usize>,

    #[arg(long)]
    absolute: bool,

    #[arg(long, value_parser = ["scan"])]
    confirm: Option<String>,

    #[arg(short = 'r', long, default_value_t = true)]
    recursive: bool,

    #[arg(long)]
    max_depth: Option<usize>,
}

fn parse_env_options() -> HashMap<String, String> {
    let binary_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_uppercase()))
        .unwrap_or_default();

    if let Ok(val) = std::env::var(&binary_name) {
        val.split(':')
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect()
    } else {
        HashMap::new()
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

async fn walk_dir_async(
    root: &Path,
    recursive: bool,
    max_depth: Option<usize>,
    current_depth: usize,
    tx: &mpsc::Sender<Entry>,
    root_for_relative: &Path,
    absolute: bool,
) {
    let mut dir = match tokio::fs::read_dir(root).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("warning: cannot read directory {:?}: {}", root, e);
            return;
        }
    };

    while let Ok(Some(direntry)) = dir.next_entry().await {
        let path = direntry.path();
        let file_type = match direntry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        let relative_path = if absolute {
            path.canonicalize().unwrap_or(path.clone())
        } else {
            path.strip_prefix(root_for_relative)
                .unwrap_or(&path)
                .to_path_buf()
        };

        let entry_type = if file_type.is_symlink() {
            EntryType::Symlink
        } else if file_type.is_dir() {
            EntryType::Dir
        } else {
            EntryType::File
        };

        let link_target = if file_type.is_symlink() {
            tokio::fs::read_link(&path)
                .await
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let (size, modified) = if file_type.is_file() || file_type.is_dir() {
            match direntry.metadata().await {
                Ok(meta) => (Some(meta.len()), meta.modified().ok().map(DateTime::<Utc>::from)),
                Err(_) => (None, None),
            }
        } else {
            (None, None)
        };

        let entry = Entry {
            path: path.clone(),
            relative_path,
            entry_type,
            sha256: None,
            size,
            modified,
            link_target,
        };

        let _ = tx.send(entry).await;

        if recursive && file_type.is_dir() && !file_type.is_symlink() {
            let should_recurse = match max_depth {
                Some(limit) => current_depth < limit,
                None => true,
            };
            if should_recurse {
                let path = path.clone();
                let root_for_relative = root_for_relative.to_path_buf();
                let tx = tx.clone();
                Box::pin(walk_dir_async(
                    &path,
                    recursive,
                    max_depth,
                    current_depth + 1,
                    &tx,
                    &root_for_relative,
                    absolute,
                ))
                .await;
            }
        }
    }
}

async fn collect_entries_async(
    root: &Path,
    recursive: bool,
    max_depth: Option<usize>,
    absolute: bool,
) -> Vec<Entry> {
    let (tx, mut rx) = mpsc::channel::<Entry>(256);

    let root_path = root.to_path_buf();
    let tx_clone = tx.clone();

    tokio::spawn(async move {
        let root_entry_type = if tokio::fs::symlink_metadata(&root_path).await.is_ok_and(|m| m.is_symlink()) {
            EntryType::Symlink
        } else if tokio::fs::metadata(&root_path).await.is_ok_and(|m| m.is_dir()) {
            EntryType::Dir
        } else {
            EntryType::File
        };

        let root_link_target = if matches!(root_entry_type, EntryType::Symlink) {
            tokio::fs::read_link(&root_path).await.ok().map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let (root_size, root_modified) = if matches!(root_entry_type, EntryType::File | EntryType::Dir) {
            match tokio::fs::metadata(&root_path).await {
                Ok(meta) => (Some(meta.len()), meta.modified().ok().map(DateTime::<Utc>::from)),
                Err(_) => (None, None),
            }
        } else {
            (None, None)
        };

        let root_relative = if absolute {
            root_path.canonicalize().unwrap_or(root_path.clone())
        } else {
            PathBuf::new()
        };

        let root_entry = Entry {
            path: root_path.clone(),
            relative_path: root_relative,
            entry_type: root_entry_type.clone(),
            sha256: None,
            size: root_size,
            modified: root_modified,
            link_target: root_link_target,
        };
        let _ = tx_clone.send(root_entry).await;

        if matches!(root_entry_type, EntryType::Dir) && recursive {
            walk_dir_async(
                &root_path,
                recursive,
                max_depth,
                0,
                &tx_clone,
                &root_path,
                absolute,
            )
            .await;
        }
    });

    drop(tx);

    let mut entries = Vec::new();
    while let Some(entry) = rx.recv().await {
        entries.push(entry);
    }
    entries
}

async fn run_pre_scan_async(
    root: &Path,
    recursive: bool,
    max_depth: Option<usize>,
    absolute: bool,
) -> ScanStats {
    let start = Instant::now();

    let entries = collect_entries_async(root, recursive, max_depth, absolute).await;

    let mut total_entries: u64 = 0;
    let mut total_files: u64 = 0;
    let mut total_dirs: u64 = 0;
    let mut total_symlinks: u64 = 0;
    let mut total_bytes: u64 = 0;

    for entry in &entries {
        total_entries += 1;
        match entry.entry_type {
            EntryType::File => {
                total_files += 1;
                total_bytes += entry.size.unwrap_or(0);
            }
            EntryType::Dir => total_dirs += 1,
            EntryType::Symlink => total_symlinks += 1,
        }
    }

    ScanStats {
        total_entries,
        total_files,
        total_dirs,
        total_symlinks,
        total_bytes,
        scan_duration: start.elapsed(),
    }
}

fn print_stats(stats: &ScanStats, verbose: bool) {
    eprintln!("── Pre-scan ─────────────────────");
    eprintln!("  Entries:      {}", stats.total_entries);
    eprintln!("  Files:        {}", stats.total_files);
    eprintln!("  Directories:  {}", stats.total_dirs);
    eprintln!("  Symlinks:     {}", stats.total_symlinks);
    eprintln!("  Total size:   {}", format_bytes(stats.total_bytes));
    eprintln!("  Scan time:    {:?}", stats.scan_duration);

    if verbose && stats.total_files > 0 {
        let hash_throughput_mbps = 150.0;
        let est_seconds = stats.total_bytes as f64 / (hash_throughput_mbps * 1024.0 * 1024.0);
        if est_seconds > 0.1 {
            eprintln!("  Est. hash:    {:.1}s", est_seconds);
        }
    }
    eprintln!("────────────────────────────────");
}

fn confirm_scan() -> bool {
    eprint!("Continue? [Y/n] ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let input = input.trim().to_lowercase();
    input.is_empty() || input == "y" || input == "yes"
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        run().await;
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    std::process::exit(0);
}

async fn run() {
    let env_opts = parse_env_options();

    let mut args = Args::parse();

    if !args.verbose && env_opts.get("verbose") == Some(&"true".to_string()) {
        args.verbose = true;
    }

    if args.confirm.is_none() {
        if let Some(v) = env_opts.get("confirm") {
            if v == "scan" {
                args.confirm = Some("scan".to_string());
            }
        }
    }

    let root = args.directory.clone();
    let absolute = args.absolute;
    let verbose = args.verbose;
    let recursive = args.recursive;
    let max_depth = if args.recursive { args.max_depth } else { Some(0) };
    let jobs = args.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    let scan_stats = run_pre_scan_async(&root, recursive, max_depth, absolute).await;
    print_stats(&scan_stats, verbose);

    if args.confirm.as_deref() == Some("scan") && !confirm_scan() {
        eprintln!("Aborted.");
        return;
    }

    let start = Instant::now();

    let entries = collect_entries_async(&root, recursive, max_depth, absolute).await;
    let total_entries = entries.len();

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs));
    let mut set = tokio::task::JoinSet::new();

    for (idx, entry) in entries.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.unwrap();
            let result = process_entry(entry, absolute).await;
            (idx, result)
        });
    }

    let mut results: Vec<Option<Entry>> = vec![None; total_entries];
    let mut files_processed: u64 = 0;
    let mut dirs_processed: u64 = 0;
    let mut symlinks_processed: u64 = 0;

    while let Some(result) = set.join_next().await {
        let (idx, entry_result) = result.unwrap();
        if let Ok(ref entry) = entry_result {
            match entry.entry_type {
                EntryType::File => files_processed += 1,
                EntryType::Dir => dirs_processed += 1,
                EntryType::Symlink => symlinks_processed += 1,
            }
        }

        if verbose {
            if let Ok(ref entry) = entry_result {
                eprintln!(
                    "[{}/{}] hashing   {}",
                    files_processed + dirs_processed + symlinks_processed,
                    total_entries,
                    entry.relative_path.display()
                );
            } else if let Err(ref e) = entry_result {
                eprintln!("[ERROR] {}: {}", idx, e);
            }
        }

        results[idx] = entry_result.ok();
    }

    let mut final_entries: Vec<Entry> = results.into_iter().flatten().collect();
    final_entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let hash_duration = start.elapsed();

    if verbose {
        eprintln!(
            "✓ Processed {} files, {} dirs, {} symlinks in {:?}",
            files_processed, dirs_processed, symlinks_processed, hash_duration
        );
    }

    write_csv(&final_entries, &args.output).unwrap();
}

async fn process_entry(
    entry: Entry,
    _absolute: bool,
) -> Result<Entry, String> {
    let path = entry.path.clone();
    let relative_path = entry.relative_path.clone();
    let entry_type = entry.entry_type.clone();

    match entry_type {
        EntryType::File => {
            let metadata = tokio::fs::metadata(&path)
                .await
                .map_err(|e| e.to_string())?;
            let size = metadata.len();
            let modified = metadata
                .modified()
                .ok()
                .map(DateTime::<Utc>::from);

            let file = tokio::fs::File::open(&path)
                .await
                .map_err(|e| e.to_string())?;
            let mut reader = tokio::io::BufReader::new(file);
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 65536];

            loop {
                let n = reader.read(&mut buf).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }

            let hash = format!("{:x}", hasher.finalize());

            Ok(Entry {
                path,
                relative_path,
                entry_type: EntryType::File,
                sha256: Some(hash),
                size: Some(size),
                modified,
                link_target: None,
            })
        }
        EntryType::Symlink => {
            Ok(Entry {
                path,
                relative_path,
                entry_type: EntryType::Symlink,
                sha256: None,
                size: None,
                modified: None,
                link_target: entry.link_target,
            })
        }
        EntryType::Dir => {
            Ok(Entry {
                path,
                relative_path,
                entry_type: EntryType::Dir,
                sha256: None,
                size: None,
                modified: None,
                link_target: None,
            })
        }
    }
}

fn write_csv(entries: &[Entry], output: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr: Writer<Box<dyn Write>> = if let Some(path) = output {
        let file = std::fs::File::create(path)?;
        Writer::from_writer(Box::new(file))
    } else {
        Writer::from_writer(Box::new(std::io::stdout()))
    };

    wtr.write_record(["path", "type", "sha256", "size", "modified", "link_target"])?;

    for entry in entries {
        let type_str = match entry.entry_type {
            EntryType::File => "file",
            EntryType::Dir => "dir",
            EntryType::Symlink => "symlink",
        };

        let size_str = entry.size.map(|s| s.to_string());
        let modified_str = entry.modified.map(|m| m.to_rfc3339());
        let link_target_str = entry.link_target.clone();

        wtr.write_record(&[
            entry.relative_path.to_string_lossy().to_string(),
            type_str.to_string(),
            entry.sha256.clone().unwrap_or_default(),
            size_str.unwrap_or_default(),
            modified_str.unwrap_or_default(),
            link_target_str.unwrap_or_default(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
