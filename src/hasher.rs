use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::types::{Entry, EntryType};

/// Process a single entry: compute SHA-256 for files, pass through for dirs/symlinks.
pub async fn process_entry(entry: Entry, _absolute: bool) -> Result<Entry, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
