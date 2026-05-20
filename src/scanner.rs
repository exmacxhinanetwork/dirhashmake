use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

use crate::types::{Entry, EntryType, ScanStats};

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
pub async fn collect_entries(
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
pub async fn run_pre_scan(
    root: &Path,
    recursive: bool,
    max_depth: Option<usize>,
    absolute: bool,
) -> ScanStats {
    let start = Instant::now();

    let entries = collect_entries(root, recursive, max_depth, absolute).await;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_collect_entries_empty_dir() {
        let dir = std::env::temp_dir().join("dirhashmake_test_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let entries = collect_entries(&dir, true, None, false).await;
        assert!(!entries.is_empty());
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

        let entries = collect_entries(&dir, true, None, false).await;
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

        let entries_0 = collect_entries(&dir, true, Some(0), false).await;
        let files_0: usize = entries_0
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_0, 1);

        let entries_1 = collect_entries(&dir, true, Some(1), false).await;
        let files_1: usize = entries_1
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_1, 2);

        let entries_2 = collect_entries(&dir, true, Some(2), false).await;
        let files_2: usize = entries_2
            .iter()
            .filter(|e| e.entry_type == EntryType::File)
            .count();
        assert_eq!(files_2, 3);

        let entries_all = collect_entries(&dir, true, None, false).await;
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

        let entries = collect_entries(&dir, true, None, false).await;
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
    async fn test_collect_entries_nonexistent_dir() {
        let nonexistent = PathBuf::from("/nonexistent/dir/that/does/not/exist");
        let entries = collect_entries(&nonexistent, true, None, false).await;
        assert!(entries.is_empty() || entries.len() == 1);
    }

    #[tokio::test]
    async fn test_collect_entries_special_chars() {
        let dir = std::env::temp_dir().join("dirhashmake_test_special");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file with spaces.txt"), "a").unwrap();
        std::fs::write(dir.join("file-with-dashes.txt"), "b").unwrap();
        std::fs::write(dir.join("file_with_underscores.txt"), "c").unwrap();

        let entries = collect_entries(&dir, true, None, false).await;
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

        let entries = collect_entries(&dir, true, None, false).await;
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

        let entries = collect_entries(&dir, false, None, false).await;
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

        let entries = collect_entries(&dir, true, None, true).await;
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

        let entries = collect_entries(&dir, true, None, false).await;
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

    #[tokio::test]
    async fn test_collect_entries_sort_order() {
        let dir = std::env::temp_dir().join("dirhashmake_test_sort");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("z.txt"), "z").unwrap();
        std::fs::write(dir.join("a.txt"), "a").unwrap();
        std::fs::write(dir.join("m.txt"), "m").unwrap();

        let entries = collect_entries(&dir, true, None, false).await;
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

            let stats = run_pre_scan(&dir, true, None, false).await;
            let _ = std::fs::remove_dir_all(&dir);
            stats
        });

        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.total_dirs, 2);
        assert_eq!(stats.total_bytes, 12);
    }
}
