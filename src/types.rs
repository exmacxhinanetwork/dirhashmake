/// Represents the type of a filesystem entry.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryType {
    File,
    Dir,
    Symlink,
}

/// A filesystem entry discovered during directory traversal.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: std::path::PathBuf,
    pub relative_path: std::path::PathBuf,
    pub entry_type: EntryType,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
    pub link_target: Option<String>,
}

/// Statistics gathered during the pre-scan phase.
#[derive(Debug)]
pub struct ScanStats {
    pub total_entries: u64,
    pub total_files: u64,
    pub total_dirs: u64,
    pub total_symlinks: u64,
    pub total_bytes: u64,
    pub scan_duration: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
