use std::io::Write;
use std::path::PathBuf;

use csv::Writer;

use crate::types::{Entry, EntryType, ScanStats};

/// Format a byte count into a human-readable string (B, KiB, MiB, GiB).
pub fn format_bytes(bytes: u64) -> String {
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

/// Print pre-scan statistics to stderr.
pub fn print_stats(stats: &ScanStats, verbose: bool) {
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

/// Write entries to CSV output (file or stdout).
pub fn write_csv(
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
    use crate::types::EntryType;
    use std::path::PathBuf;

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
}
