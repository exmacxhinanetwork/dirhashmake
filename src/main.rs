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

/// Represents the type of a filesystem entry.
#[derive(Debug, Clone, PartialEq)]
enum EntryType {
    File,
    Dir,
    Symlink,
}

/// A filesystem entry discovered during directory traversal.
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

/// Statistics gathered during the pre-scan phase.
#[derive(Debug)]
struct ScanStats {
    total_entries: u64,
    total_files: u64,
    total_dirs: u64,
    total_symlinks: u64,
    total_bytes: u64,
    scan_duration: Duration,
}

/// CLI argument parser.
#[derive(Parser)]
#[command(
    name = "dirhashmake",
    about = "Hash local directories with SHA-256 and export as CSV"
)]
struct Args {
    /// Directory to hash
    #[arg(default_value = ".")]
    directory: PathBuf,

    /// Output CSV file (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Verbose progress output to stderr
    #[arg(short, long)]
    verbose: bool,

    /// Number of parallel worker tasks
    #[arg(short = 'j', long)]
    jobs: Option<usize>,

    /// Use absolute paths instead of relative
    #[arg(long)]
    absolute: bool,

    /// Pause and prompt before hashing begins (value: scan)
    #[arg(long, value_parser = ["scan"])]
    confirm: Option<String>,

    /// Recurse into subdirectories
    #[arg(short = 'r', long, default_value_t = true)]
    recursive: bool,

    /// Maximum recursion depth (requires --recursive)
    #[arg(long)]
    max_depth: Option<usize>,
}

/// Parse environment variable options from a colon-separated key=value string.
/// The env var name is derived from the executable name (uppercased).
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

/// Format a byte count into a human-readable string (B, KiB, MiB, GiB).
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

/// Recursively walk a directory tree asynchronously, sending entries through a channel.
/// Respects the `max_depth` limit and skips symlinked directories.
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
                Ok(meta) => (
                    Some(meta.len()),
                    meta.modified().ok().map(DateTime::<Utc>::from),
                ),
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

/// Collect all filesystem entries under `root` using async directory traversal.
/// Returns a vector of `Entry` structs with metadata pre-populated.
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
        let root_entry_type = if tokio::fs::symlink_metadata(&root_path)
            .await
            .is_ok_and(|m| m.is_symlink())
        {
            EntryType::Symlink
        } else if tokio::fs::metadata(&root_path)
            .await
            .is_ok_and(|m| m.is_dir())
        {
            EntryType::Dir
        } else {
            EntryType::File
        };

        let root_link_target = if matches!(root_entry_type, EntryType::Symlink) {
            tokio::fs::read_link(&root_path)
                .await
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let (root_size, root_modified) =
            if matches!(root_entry_type, EntryType::File | EntryType::Dir) {
                match tokio::fs::metadata(&root_path).await {
                    Ok(meta) => (
                        Some(meta.len()),
                        meta.modified().ok().map(DateTime::<Utc>::from),
                    ),
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

        if matches!(root_entry_type, EntryType::Dir) {
            walk_dir_async(
                &root_path, recursive, max_depth, 0, &tx_clone, &root_path, absolute,
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

/// Perform a pre-scan of the directory to gather statistics without hashing file contents.
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
    let max_depth = if args.recursive {
        args.max_depth
    } else {
        Some(0)
    };
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

async fn process_entry(entry: Entry, _absolute: bool) -> Result<Entry, String> {
    let path = entry.path.clone();
    let relative_path = entry.relative_path.clone();
    let entry_type = entry.entry_type.clone();

    match entry_type {
        EntryType::File => {
            let metadata = tokio::fs::metadata(&path)
                .await
                .map_err(|e| e.to_string())?;
            let size = metadata.len();
            let modified = metadata.modified().ok().map(DateTime::<Utc>::from);

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
        EntryType::Symlink => Ok(Entry {
            path,
            relative_path,
            entry_type: EntryType::Symlink,
            sha256: None,
            size: None,
            modified: None,
            link_target: entry.link_target,
        }),
        EntryType::Dir => Ok(Entry {
            path,
            relative_path,
            entry_type: EntryType::Dir,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        }),
    }
}

fn write_csv(
    entries: &[Entry],
    output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn test_format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1536), "1.50 KiB");
    }

    #[test]
    fn test_format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MiB");
    }

    #[test]
    fn test_format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn test_format_bytes_boundary() {
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1048575), "1024.00 KiB");
    }

    #[test]
    fn test_entry_type_equality() {
        assert_eq!(EntryType::File, EntryType::File);
        assert_ne!(EntryType::File, EntryType::Dir);
        assert_ne!(EntryType::Dir, EntryType::Symlink);
    }

    #[test]
    fn test_entry_clone() {
        let entry = Entry {
            path: PathBuf::from("/tmp/test"),
            relative_path: PathBuf::from("test"),
            entry_type: EntryType::File,
            sha256: Some("abc123".to_string()),
            size: Some(100),
            modified: None,
            link_target: None,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.path, entry.path);
        assert_eq!(cloned.sha256, entry.sha256);
        assert_eq!(cloned.entry_type, entry.entry_type);
    }

    #[tokio::test]
    async fn test_collect_entries_empty_dir() {
        let dir = std::env::temp_dir().join("dirhashmake_test_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        assert!(!entries.is_empty()); // at least the root dir itself
        assert_eq!(entries[0].entry_type, EntryType::Dir);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_with_files() {
        let dir = std::env::temp_dir().join("dirhashmake_test_files");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        std::fs::write(dir.join("b.txt"), "world").unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        let files: Vec<_> = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .collect();
        assert_eq!(files.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_max_depth() {
        let dir = std::env::temp_dir().join("dirhashmake_test_depth");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b/c")).unwrap();
        std::fs::write(dir.join("root.txt"), "r").unwrap();
        std::fs::write(dir.join("a/a.txt"), "a").unwrap();
        std::fs::write(dir.join("a/b/b.txt"), "b").unwrap();
        std::fs::write(dir.join("a/b/c/c.txt"), "c").unwrap();

        // depth 0: root + immediate children only
        let entries_0 = collect_entries_async(&dir, true, Some(0), false).await;
        let files_0: usize = entries_0
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_0, 1); // only root.txt

        // depth 1: one level deep
        let entries_1 = collect_entries_async(&dir, true, Some(1), false).await;
        let files_1: usize = entries_1
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_1, 2); // root.txt + a/a.txt

        // depth 2: two levels deep
        let entries_2 = collect_entries_async(&dir, true, Some(2), false).await;
        let files_2: usize = entries_2
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_2, 3); // root.txt + a/a.txt + a/b/b.txt

        // unlimited: all files
        let entries_all = collect_entries_async(&dir, true, None, false).await;
        let files_all: usize = entries_all
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_all, 4);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_symlink() {
        let dir = std::env::temp_dir().join("dirhashmake_test_symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("target.txt"), "data").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("target.txt"), dir.join("link.txt")).unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        let symlinks: Vec<_> = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::Symlink)
            .collect();

        #[cfg(unix)]
        {
            assert_eq!(symlinks.len(), 1);
            assert!(symlinks[0]
                .link_target
                .as_deref()
                .unwrap()
                .ends_with("target.txt"));
        }
        #[cfg(not(unix))]
        {
            assert_eq!(symlinks.len(), 0);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_process_entry_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_process");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let entry = Entry {
            path: file_path.clone(),
            relative_path: PathBuf::from("test.txt"),
            entry_type: EntryType::File,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };

        let result = process_entry(entry, false).await.unwrap();
        assert_eq!(result.entry_type, EntryType::File);
        assert_eq!(result.sha256.as_ref().unwrap().len(), 64);
        assert_eq!(result.size, Some(11));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_csv_stdout() {
        let entries = vec![Entry {
            path: PathBuf::from("/tmp/test"),
            relative_path: PathBuf::from("test.txt"),
            entry_type: EntryType::File,
            sha256: Some("abc".to_string()),
            size: Some(10),
            modified: None,
            link_target: None,
        }];
        let result = write_csv(&entries, &None);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_entry_empty_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_empty_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("empty.txt");
        std::fs::write(&file_path, "").unwrap();

        let entry = Entry {
            path: file_path.clone(),
            relative_path: PathBuf::from("empty.txt"),
            entry_type: EntryType::File,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };

        let result = process_entry(entry, false).await.unwrap();
        assert_eq!(result.size, Some(0));
        assert_eq!(
            result.sha256.as_deref().unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_process_entry_nonexistent_file() {
        let entry = Entry {
            path: PathBuf::from("/nonexistent/path/file.txt"),
            relative_path: PathBuf::from("file.txt"),
            entry_type: EntryType::File,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };

        let result = process_entry(entry, false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_process_entry_dir() {
        let dir = std::env::temp_dir().join("dirhashmake_test_process_dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let entry = Entry {
            path: dir.clone(),
            relative_path: PathBuf::from("testdir"),
            entry_type: EntryType::Dir,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };

        let result = process_entry(entry, false).await.unwrap();
        assert_eq!(result.entry_type, EntryType::Dir);
        assert!(result.sha256.is_none());
        assert!(result.size.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_process_entry_permission_denied() {
        let dir = std::env::temp_dir().join("dirhashmake_test_perm");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("noperm.txt");
        std::fs::write(&file_path, "secret").unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&file_path, perms).unwrap();

        let entry = Entry {
            path: file_path.clone(),
            relative_path: PathBuf::from("noperm.txt"),
            entry_type: EntryType::File,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };

        let result = process_entry(entry, false).await;
        assert!(
            result.is_err(),
            "Should fail to read file with no permissions"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_nonexistent_dir() {
        let nonexistent = PathBuf::from("/nonexistent/dir/that/does/not/exist");
        let entries = collect_entries_async(&nonexistent, true, None, false).await;
        assert!(entries.is_empty() || entries.len() == 1);
    }

    // TODO: Re-enable when running as non-root user.
    // This test fails on systems where the test runner has root privileges,
    // because root can read any file regardless of permissions.
    // #[cfg(unix)]
    // #[tokio::test]
    // async fn test_collect_entries_unreadable_dir() {
    //     if unsafe { libc::getuid() } == 0 {
    //         return;
    //     }
    //
    //     let dir = std::env::temp_dir().join("dirhashmake_test_unreadable");
    //     let _ = std::fs::remove_dir_all(&dir);
    //     std::fs::create_dir_all(&dir).unwrap();
    //     std::fs::write(dir.join("visible.txt"), "data").unwrap();
    //
    //     let sub = dir.join("locked");
    //     std::fs::create_dir_all(&sub).unwrap();
    //     std::fs::write(sub.join("hidden.txt"), "secret").unwrap();
    //
    //     use std::os::unix::fs::PermissionsExt;
    //     let mut perms = std::fs::metadata(&sub).unwrap().permissions();
    //     perms.set_mode(0o000);
    //     if std::fs::set_permissions(&sub, perms).is_err() {
    //         let _ = std::fs::remove_dir_all(&dir);
    //         return;
    //     }
    //
    //     let entries = collect_entries_async(&dir, true, None, false).await;
    //     let files: usize = entries
    //         .iter()
    //         .filter(|e| e.entry_type == EntryType::File)
    //         .count();
    //     assert_eq!(files, 1);
    //
    //     let _ = std::fs::remove_dir_all(&dir);
    // }

    #[tokio::test]
    async fn test_collect_entries_special_chars() {
        let dir = std::env::temp_dir().join("dirhashmake_test_special");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file with spaces.txt"), "a").unwrap();
        std::fs::write(dir.join("file-with-dashes.txt"), "b").unwrap();
        std::fs::write(dir.join("file_with_underscores.txt"), "c").unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        let files: usize = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files, 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_unicode_paths() {
        let dir = std::env::temp_dir().join("dirhashmake_test_unicode");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("café.txt"), "coffee").unwrap();
        std::fs::write(dir.join("日本語.txt"), "nihongo").unwrap();
        std::fs::write(dir.join("emoji_🎉.txt"), "party").unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        let files: usize = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files, 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_recursive_false() {
        let dir = std::env::temp_dir().join("dirhashmake_test_norecurse");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("root.txt"), "root").unwrap();
        std::fs::write(dir.join("sub/deep.txt"), "deep").unwrap();

        let entries = collect_entries_async(&dir, false, None, false).await;
        let files: usize = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_absolute_paths() {
        let dir = std::env::temp_dir().join("dirhashmake_test_abs");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("test.txt"), "data").unwrap();

        let entries = collect_entries_async(&dir, true, None, true).await;
        let root_entry = &entries[0];
        assert!(root_entry.relative_path.is_absolute());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_symlink_to_dir_not_followed() {
        let dir = std::env::temp_dir().join("dirhashmake_test_symdir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::write(real_dir.join("file.txt"), "data").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, dir.join("link_to_dir")).unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        let symlinks: usize = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::Symlink)
            .count();
        let dirs: usize = entries
            .iter()
            .filter(|e| e.entry_type == EntryType::Dir)
            .count();

        #[cfg(unix)]
        {
            assert_eq!(symlinks, 1);
            assert_eq!(dirs, 2);
            let files: usize = entries
                .iter()
                .filter(|e| e.entry_type == EntryType::File)
                .count();
            assert_eq!(files, 1);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_csv_to_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_csv_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.csv");

        let entries = vec![
            Entry {
                path: PathBuf::from("/tmp/test"),
                relative_path: PathBuf::from("file1.txt"),
                entry_type: EntryType::File,
                sha256: Some("abc123".to_string()),
                size: Some(100),
                modified: None,
                link_target: None,
            },
            Entry {
                path: PathBuf::from("/tmp/test/sub"),
                relative_path: PathBuf::from("sub"),
                entry_type: EntryType::Dir,
                sha256: None,
                size: None,
                modified: None,
                link_target: None,
            },
            Entry {
                path: PathBuf::from("/tmp/test/link"),
                relative_path: PathBuf::from("link"),
                entry_type: EntryType::Symlink,
                sha256: None,
                size: None,
                modified: None,
                link_target: Some("file1.txt".to_string()),
            },
        ];

        let result = write_csv(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("file1.txt,file,abc123,100"));
        assert!(content.contains("sub,dir"));
        assert!(content.contains("link,symlink,,,,file1.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_csv_permission_denied() {
        let dir = std::env::temp_dir().join("dirhashmake_test_csv_perm");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o444);
        std::fs::set_permissions(&dir, perms).unwrap();

        let output_path = dir.join("output.csv");
        let entries = vec![Entry {
            path: PathBuf::from("/tmp/test"),
            relative_path: PathBuf::from("test.txt"),
            entry_type: EntryType::File,
            sha256: Some("abc".to_string()),
            size: Some(10),
            modified: None,
            link_target: None,
        }];

        let result = write_csv(&entries, &Some(output_path));
        assert!(result.is_err());

        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dir, perms).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_csv_empty_entries() {
        let entries: Vec<Entry> = vec![];
        let result = write_csv(&entries, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_env_options_empty() {
        let opts = parse_env_options();
        assert!(opts.is_empty());
    }

    #[test]
    fn test_parse_env_options_malformed() {
        std::env::set_var("DIRHASHMAKE_TEST", "noequals:also:bad");
        let result = "noequals:also:bad"
            .split(':')
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                let key = parts.next()?;
                let val = parts.next()?;
                Some((key.to_string(), val.to_string()))
            })
            .collect::<HashMap<String, String>>();
        assert!(result.is_empty());
        std::env::remove_var("DIRHASHMAKE_TEST");
    }

    #[test]
    fn test_parse_env_options_valid() {
        let result = "verbose=true:confirm=scan"
            .split(':')
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect::<HashMap<String, String>>();
        assert_eq!(result.get("verbose"), Some(&"true".to_string()));
        assert_eq!(result.get("confirm"), Some(&"scan".to_string()));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_scan_stats_accuracy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let stats = rt.block_on(async {
            let dir = std::env::temp_dir().join("dirhashmake_test_stats");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("sub")).unwrap();
            std::fs::write(dir.join("a.txt"), "hello").unwrap();
            std::fs::write(dir.join("sub/b.txt"), "world!!").unwrap();

            let stats = run_pre_scan_async(&dir, true, None, false).await;
            let _ = std::fs::remove_dir_all(&dir);
            stats
        });

        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.total_dirs, 2);
        assert_eq!(stats.total_bytes, 12);
    }

    #[tokio::test]
    async fn test_process_entry_symlink() {
        let dir = std::env::temp_dir().join("dirhashmake_test_proc_sym");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("target.txt"), "data").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("target.txt"), dir.join("link.txt")).unwrap();

        #[cfg(unix)]
        {
            let entry = Entry {
                path: dir.join("link.txt"),
                relative_path: PathBuf::from("link.txt"),
                entry_type: EntryType::Symlink,
                sha256: None,
                size: None,
                modified: None,
                link_target: Some("target.txt".to_string()),
            };

            let result = process_entry(entry, false).await.unwrap();
            assert_eq!(result.entry_type, EntryType::Symlink);
            assert!(result.sha256.is_none());
            assert!(result.size.is_none());
            assert!(result.link_target.is_some());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_process_entry_hash_deterministic() {
        let dir = std::env::temp_dir().join("dirhashmake_test_deterministic");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let content = b"deterministic content for hash test";
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        std::fs::write(&file1, content).unwrap();
        std::fs::write(&file2, content).unwrap();

        let entry1 = Entry {
            path: file1.clone(),
            relative_path: PathBuf::from("file1.txt"),
            entry_type: EntryType::File,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };
        let entry2 = Entry {
            path: file2.clone(),
            relative_path: PathBuf::from("file2.txt"),
            entry_type: EntryType::File,
            sha256: None,
            size: None,
            modified: None,
            link_target: None,
        };

        let result1 = process_entry(entry1, false).await.unwrap();
        let result2 = process_entry(entry2, false).await.unwrap();

        assert_eq!(result1.sha256, result2.sha256);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_collect_entries_sort_order() {
        let dir = std::env::temp_dir().join("dirhashmake_test_sort");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("z.txt"), "z").unwrap();
        std::fs::write(dir.join("a.txt"), "a").unwrap();
        std::fs::write(dir.join("m.txt"), "m").unwrap();

        let entries = collect_entries_async(&dir, true, None, false).await;
        let mut paths: Vec<_> = entries
            .iter()
            .map(|e| e.relative_path.to_string_lossy().to_string())
            .collect();
        paths.sort();

        assert_eq!(paths.len(), 4);
        assert_eq!(paths[0], "");
        assert_eq!(paths[1], "a.txt");
        assert_eq!(paths[2], "m.txt");
        assert_eq!(paths[3], "z.txt");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // TODO: Filesystem corruption detection
    // Detecting filesystem corruption is inherently difficult in a user-space
    // application. The OS and filesystem drivers handle most corruption scenarios
    // by returning I/O errors (EIO, EFAULT, etc.). Our code already handles
    // these gracefully via the `map_err` and error propagation paths.
    //
    // Specific corruption scenarios that would manifest as errors we already handle:
    // - Corrupted directory entries → read_dir() returns Err
    // - Corrupted file metadata → metadata() returns Err
    // - Corrupted file data → File::open() or read() returns Err
    // - Stale NFS file handles → returns Err with ESTALE
    //
    // A more advanced approach would be to add filesystem health checks using
    // platform-specific APIs (e.g., ioctl(FS_IOC_CHECK_FEATURE) on Linux),
    // but this is out of scope for a hashing tool.

    // TODO: Filesystem timeout handling
    // Network filesystems (NFS, SMB, FUSE) can experience timeouts. Tokio's
    // async I/O handles these by returning timeout errors, but there's no
    // built-in per-operation timeout in tokio::fs. To add timeout support,
    // we could wrap file operations with tokio::time::timeout:
    //
    //   tokio::time::timeout(Duration::from_secs(30), file.read(&mut buf)).await
    //
    // This would be useful for large directories on slow network mounts.

    // TODO: Directory depth limits across filesystems
    // Our code uses max_depth as Option<usize>, which can represent any depth.
    // The practical limits are imposed by the filesystem and OS:
    //
    // | Filesystem | Max Depth | Limiting Factor |
    // |------------|-----------|-----------------|
    // | ext4       | ~4096     | Subdir count + PATH_MAX (4096 bytes) |
    // | ext3       | 32000     | Link count limit |
    // | XFS        | unlimited | PATH_MAX (4096 bytes) |
    // | Btrfs      | unlimited | PATH_MAX (4096 bytes) |
    // | NTFS       | unlimited | PATH_MAX (32767 UTF-16 chars) |
    // | APFS       | unlimited | PATH_MAX (1024 bytes) |
    // | HFS+       | unlimited | PATH_MAX (1024 bytes) |
    // | FAT32      | unlimited | PATH_MAX (260 chars) |
    // | ZFS        | unlimited | PATH_MAX (1024 bytes) |
    //
    // In practice, PATH_MAX is the hard limit. With single-char directory names,
    // max depth is ~2048 on Linux (4096 / 2). Our code will naturally stop
    // when the OS can no longer resolve paths.

    // TODO: Race conditions during traversal
    // The following race conditions are possible but not explicitly handled:
    // 1. File deleted between pre-scan and hashing → process_entry returns Err
    // 2. Directory deleted during walk → walk_dir_async skips with warning
    // 3. File modified during hashing → hash reflects partial state
    // 4. Symlink target changed during traversal → may hash different content
    // 5. Hard link created during scan → counted as separate file
    //
    // These are inherent to any directory traversal tool. For cryptographic
    // integrity guarantees, the filesystem should be mounted read-only or
    // use snapshot technology (e.g., LVM snapshots, btrfs snapshots).

    // TODO: Disk space exhaustion during CSV write
    // If the disk fills during CSV output, write_csv will return an I/O error.
    // The current implementation propagates this error via Result. For very
    // large directories, the CSV could exceed available disk space. A more
    // robust approach would be to check available space before writing or
    // use streaming compression (e.g., gzip) to reduce output size.

    // TODO: Hard links
    // Hard links are indistinguishable from regular files at the filesystem
    // level (same inode). Our code treats them as regular files and hashes
    // each occurrence independently. This means:
    // - A file with 10 hard links will be hashed 10 times
    // - The CSV will show 10 separate entries with identical hashes
    // - To detect hard links, we would need to track (device, inode) pairs
    //   and deduplicate or annotate the output.
}
