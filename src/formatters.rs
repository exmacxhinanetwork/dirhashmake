use std::io::Write;
use std::path::PathBuf;

use csv::Writer;
use serde::Serialize;

use crate::cli::ExportFormat;
use crate::types::{Entry, EntryType};

/// Serializable representation of an entry for JSON/YAML output.
#[derive(Serialize)]
struct SerializableEntry {
    path: String,
    r#type: String,
    sha256: String,
    size: Option<u64>,
    modified: Option<String>,
    link_target: Option<String>,
}

impl From<&Entry> for SerializableEntry {
    fn from(entry: &Entry) -> Self {
        let type_str = match entry.entry_type {
            EntryType::File => "file",
            EntryType::Dir => "dir",
            EntryType::Symlink => "symlink",
        };
        SerializableEntry {
            path: entry.relative_path.to_string_lossy().to_string(),
            r#type: type_str.to_string(),
            sha256: entry.sha256.clone().unwrap_or_default(),
            size: entry.size,
            modified: entry.modified.map(|m| m.to_rfc3339()),
            link_target: entry.link_target.clone(),
        }
    }
}

/// Write entries in the specified format.
pub fn write_output(
    entries: &[Entry],
    output: &Option<PathBuf>,
    format: ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        ExportFormat::Csv => write_csv(entries, output),
        ExportFormat::Json => write_json(entries, output),
        ExportFormat::Yaml => write_yaml(entries, output),
        ExportFormat::Sql => write_sql(entries, output),
        ExportFormat::Html => write_html(entries, output),
    }
}

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
pub fn print_stats(stats: &crate::types::ScanStats, verbose: bool) {
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

/// Write entries as CSV.
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

/// Write entries as JSON.
fn write_json(
    entries: &[Entry],
    output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let serializable: Vec<SerializableEntry> =
        entries.iter().map(SerializableEntry::from).collect();

    let json = serde_json::to_string_pretty(&serializable)?;

    if let Some(path) = output {
        std::fs::write(path, json)?;
    } else {
        println!("{json}");
    }

    Ok(())
}

/// Write entries as YAML.
fn write_yaml(
    entries: &[Entry],
    output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let serializable: Vec<SerializableEntry> =
        entries.iter().map(SerializableEntry::from).collect();

    let yaml = serde_yaml::to_string(&serializable)?;

    if let Some(path) = output {
        std::fs::write(path, yaml)?;
    } else {
        print!("{yaml}");
    }

    Ok(())
}

/// Write entries as SQL INSERT statements.
fn write_sql(
    entries: &[Entry],
    output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = if let Some(path) = output {
        let file = std::fs::File::create(path)?;
        Box::new(file)
    } else {
        Box::new(std::io::stdout())
    };

    writeln!(out, "-- dirhashmake SQL export")?;
    writeln!(out, "-- Generated by dirhashmake")?;
    writeln!(out)?;
    writeln!(out, "CREATE TABLE IF NOT EXISTS file_hashes (")?;
    writeln!(out, "    path TEXT NOT NULL,")?;
    writeln!(out, "    type TEXT NOT NULL,")?;
    writeln!(out, "    sha256 TEXT,")?;
    writeln!(out, "    size INTEGER,")?;
    writeln!(out, "    modified TEXT,")?;
    writeln!(out, "    link_target TEXT")?;
    writeln!(out, ");")?;
    writeln!(out)?;

    for entry in entries {
        let type_str = match entry.entry_type {
            EntryType::File => "file",
            EntryType::Dir => "dir",
            EntryType::Symlink => "symlink",
        };

        let path = sql_escape(&entry.relative_path.to_string_lossy());
        let sha256 = entry
            .sha256
            .as_ref()
            .map(|s| sql_escape(s))
            .unwrap_or_else(|| "NULL".to_string());
        let size = entry
            .size
            .map(|s| s.to_string())
            .unwrap_or("NULL".to_string());
        let modified = entry
            .modified
            .map(|m| sql_escape(&m.to_rfc3339()))
            .unwrap_or("NULL".to_string());
        let link_target = entry
            .link_target
            .as_ref()
            .map(|s| sql_escape(s))
            .unwrap_or("NULL".to_string());

        writeln!(
            out,
            "INSERT INTO file_hashes (path, type, sha256, size, modified, link_target) VALUES ('{path}', '{type_str}', {sha256}, {size}, {modified}, {link_target});"
        )?;
    }

    out.flush()?;
    Ok(())
}

/// Escape a string for SQL (single quotes doubled).
fn sql_escape(s: &str) -> String {
    s.replace('\'', "''")
}

/// Write entries as HTML5 with embedded CSS.
fn write_html(
    entries: &[Entry],
    output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = if let Some(path) = output {
        let file = std::fs::File::create(path)?;
        Box::new(file)
    } else {
        Box::new(std::io::stdout())
    };

    let file_count = entries
        .iter()
        .filter(|e| e.entry_type == EntryType::File)
        .count();
    let dir_count = entries
        .iter()
        .filter(|e| e.entry_type == EntryType::Dir)
        .count();
    let sym_count = entries
        .iter()
        .filter(|e| e.entry_type == EntryType::Symlink)
        .count();
    let total_size: u64 = entries.iter().map(|e| e.size.unwrap_or(0)).sum();

    writeln!(out, "<!DOCTYPE html>")?;
    writeln!(out, "<html lang=\"en\">")?;
    writeln!(out, "<head>")?;
    writeln!(out, "  <meta charset=\"UTF-8\">")?;
    writeln!(
        out,
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    )?;
    writeln!(out, "  <title>dirhashmake - Directory Hash Report</title>")?;
    writeln!(out, "  <style>")?;
    writeln!(out, "    :root {{")?;
    writeln!(out, "      --bg: #0f1117;")?;
    writeln!(out, "      --surface: #1a1d27;")?;
    writeln!(out, "      --border: #2a2d3a;")?;
    writeln!(out, "      --text: #e2e4eb;")?;
    writeln!(out, "      --text-dim: #8b8fa3;")?;
    writeln!(out, "      --accent: #6c72cb;")?;
    writeln!(out, "      --file: #4ade80;")?;
    writeln!(out, "      --dir: #facc15;")?;
    writeln!(out, "      --symlink: #f472b6;")?;
    writeln!(
        out,
        "      --mono: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;"
    )?;
    writeln!(
        out,
        "      --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;"
    )?;
    writeln!(out, "    }}")?;
    writeln!(
        out,
        "    * {{ margin: 0; padding: 0; box-sizing: border-box; }}"
    )?;
    writeln!(out, "    body {{")?;
    writeln!(out, "      font-family: var(--sans);")?;
    writeln!(out, "      background: var(--bg);")?;
    writeln!(out, "      color: var(--text);")?;
    writeln!(out, "      line-height: 1.6;")?;
    writeln!(out, "      padding: 2rem;")?;
    writeln!(out, "      max-width: 1200px;")?;
    writeln!(out, "      margin: 0 auto;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    h1 {{")?;
    writeln!(out, "      font-size: 1.5rem;")?;
    writeln!(out, "      font-weight: 600;")?;
    writeln!(out, "      margin-bottom: 0.5rem;")?;
    writeln!(out, "      color: var(--accent);")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    .subtitle {{")?;
    writeln!(out, "      color: var(--text-dim);")?;
    writeln!(out, "      font-size: 0.875rem;")?;
    writeln!(out, "      margin-bottom: 1.5rem;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    .stats {{")?;
    writeln!(out, "      display: grid;")?;
    writeln!(
        out,
        "      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));"
    )?;
    writeln!(out, "      gap: 1rem;")?;
    writeln!(out, "      margin-bottom: 2rem;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    .stat {{")?;
    writeln!(out, "      background: var(--surface);")?;
    writeln!(out, "      border: 1px solid var(--border);")?;
    writeln!(out, "      border-radius: 8px;")?;
    writeln!(out, "      padding: 1rem;")?;
    writeln!(out, "      text-align: center;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    .stat-value {{")?;
    writeln!(out, "      font-size: 1.5rem;")?;
    writeln!(out, "      font-weight: 700;")?;
    writeln!(out, "      font-family: var(--mono);")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    .stat-label {{")?;
    writeln!(out, "      font-size: 0.75rem;")?;
    writeln!(out, "      color: var(--text-dim);")?;
    writeln!(out, "      text-transform: uppercase;")?;
    writeln!(out, "      letter-spacing: 0.05em;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    .stat-files .stat-value {{ color: var(--file); }}")?;
    writeln!(out, "    .stat-dirs .stat-value {{ color: var(--dir); }}")?;
    writeln!(
        out,
        "    .stat-symlinks .stat-value {{ color: var(--symlink); }}"
    )?;
    writeln!(
        out,
        "    .stat-size .stat-value {{ color: var(--accent); }}"
    )?;
    writeln!(out, "    table {{")?;
    writeln!(out, "      width: 100%;")?;
    writeln!(out, "      border-collapse: collapse;")?;
    writeln!(out, "      font-size: 0.875rem;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    th {{")?;
    writeln!(out, "      text-align: left;")?;
    writeln!(out, "      padding: 0.75rem 1rem;")?;
    writeln!(out, "      background: var(--surface);")?;
    writeln!(out, "      border-bottom: 2px solid var(--border);")?;
    writeln!(out, "      color: var(--text-dim);")?;
    writeln!(out, "      font-weight: 600;")?;
    writeln!(out, "      text-transform: uppercase;")?;
    writeln!(out, "      font-size: 0.7rem;")?;
    writeln!(out, "      letter-spacing: 0.05em;")?;
    writeln!(out, "      position: sticky;")?;
    writeln!(out, "      top: 0;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    td {{")?;
    writeln!(out, "      padding: 0.6rem 1rem;")?;
    writeln!(out, "      border-bottom: 1px solid var(--border);")?;
    writeln!(out, "      font-family: var(--mono);")?;
    writeln!(out, "      font-size: 0.8rem;")?;
    writeln!(out, "    }}")?;
    writeln!(
        out,
        "    tr:hover td {{ background: rgba(108, 114, 203, 0.05); }}"
    )?;
    writeln!(out, "    .type-badge {{")?;
    writeln!(out, "      display: inline-block;")?;
    writeln!(out, "      padding: 0.15rem 0.5rem;")?;
    writeln!(out, "      border-radius: 4px;")?;
    writeln!(out, "      font-size: 0.7rem;")?;
    writeln!(out, "      font-weight: 600;")?;
    writeln!(out, "      text-transform: uppercase;")?;
    writeln!(out, "    }}")?;
    writeln!(
        out,
        "    .type-file {{ background: rgba(74, 222, 128, 0.15); color: var(--file); }}"
    )?;
    writeln!(
        out,
        "    .type-dir {{ background: rgba(250, 204, 21, 0.15); color: var(--dir); }}"
    )?;
    writeln!(
        out,
        "    .type-symlink {{ background: rgba(244, 114, 182, 0.15); color: var(--symlink); }}"
    )?;
    writeln!(out, "    .hash {{ color: var(--text-dim); }}")?;
    writeln!(
        out,
        "    .hash-empty {{ color: var(--border); font-style: italic; }}"
    )?;
    writeln!(
        out,
        "    .size {{ color: var(--text-dim); text-align: right; }}"
    )?;
    writeln!(out, "    .link-target {{ color: var(--accent); }}")?;
    writeln!(out, "    .footer {{")?;
    writeln!(out, "      margin-top: 2rem;")?;
    writeln!(out, "      padding-top: 1rem;")?;
    writeln!(out, "      border-top: 1px solid var(--border);")?;
    writeln!(out, "      color: var(--text-dim);")?;
    writeln!(out, "      font-size: 0.75rem;")?;
    writeln!(out, "      text-align: center;")?;
    writeln!(out, "    }}")?;
    writeln!(out, "    @media (max-width: 768px) {{")?;
    writeln!(out, "      body {{ padding: 1rem; }}")?;
    writeln!(out, "      table {{ font-size: 0.75rem; }}")?;
    writeln!(out, "      td, th {{ padding: 0.5rem; }}")?;
    writeln!(
        out,
        "      .stats {{ grid-template-columns: repeat(2, 1fr); }}"
    )?;
    writeln!(out, "    }}")?;
    writeln!(out, "  </style>")?;
    writeln!(out, "</head>")?;
    writeln!(out, "<body>")?;
    writeln!(out, "  <h1>Directory Hash Report</h1>")?;
    writeln!(out, "  <p class=\"subtitle\">Generated by dirhashmake</p>")?;
    writeln!(out, "  <div class=\"stats\">")?;
    writeln!(out, "    <div class=\"stat stat-files\">")?;
    writeln!(out, "      <div class=\"stat-value\">{file_count}</div>")?;
    writeln!(out, "      <div class=\"stat-label\">Files</div>")?;
    writeln!(out, "    </div>")?;
    writeln!(out, "    <div class=\"stat stat-dirs\">")?;
    writeln!(out, "      <div class=\"stat-value\">{dir_count}</div>")?;
    writeln!(out, "      <div class=\"stat-label\">Directories</div>")?;
    writeln!(out, "    </div>")?;
    writeln!(out, "    <div class=\"stat stat-symlinks\">")?;
    writeln!(out, "      <div class=\"stat-value\">{sym_count}</div>")?;
    writeln!(out, "      <div class=\"stat-label\">Symlinks</div>")?;
    writeln!(out, "    </div>")?;
    writeln!(out, "    <div class=\"stat stat-size\">")?;
    writeln!(
        out,
        "      <div class=\"stat-value\">{}</div>",
        format_bytes(total_size)
    )?;
    writeln!(out, "      <div class=\"stat-label\">Total Size</div>")?;
    writeln!(out, "    </div>")?;
    writeln!(out, "  </div>")?;
    writeln!(out, "  <table>")?;
    writeln!(out, "    <thead>")?;
    writeln!(out, "      <tr>")?;
    writeln!(out, "        <th>Path</th>")?;
    writeln!(out, "        <th>Type</th>")?;
    writeln!(out, "        <th>SHA-256</th>")?;
    writeln!(out, "        <th>Size</th>")?;
    writeln!(out, "        <th>Modified</th>")?;
    writeln!(out, "        <th>Link Target</th>")?;
    writeln!(out, "      </tr>")?;
    writeln!(out, "    </thead>")?;
    writeln!(out, "    <tbody>")?;

    for entry in entries {
        let type_str = match entry.entry_type {
            EntryType::File => "file",
            EntryType::Dir => "dir",
            EntryType::Symlink => "symlink",
        };
        let type_class = match entry.entry_type {
            EntryType::File => "type-file",
            EntryType::Dir => "type-dir",
            EntryType::Symlink => "type-symlink",
        };

        let path = html_escape(&entry.relative_path.to_string_lossy());
        let hash_display = entry
            .sha256
            .as_ref()
            .map(|h| format!("<span class=\"hash\">{}</span>", html_escape(h)))
            .unwrap_or_else(|| "<span class=\"hash-empty\">—</span>".to_string());
        let size_display = entry
            .size
            .map(|s| format!("<span class=\"size\">{}</span>", s))
            .unwrap_or_else(|| "<span class=\"size\">—</span>".to_string());
        let modified_display = entry
            .modified
            .map(|m| {
                format!(
                    "<span class=\"modified\">{}</span>",
                    html_escape(&m.to_rfc3339())
                )
            })
            .unwrap_or_else(|| "<span class=\"modified\">—</span>".to_string());
        let link_display = entry
            .link_target
            .as_ref()
            .map(|t| format!("<span class=\"link-target\">{}</span>", html_escape(t)))
            .unwrap_or_else(|| "<span class=\"link-target\">—</span>".to_string());

        writeln!(out, "      <tr>")?;
        writeln!(out, "        <td>{path}</td>")?;
        writeln!(
            out,
            "        <td><span class=\"type-badge {type_class}\">{type_str}</span></td>"
        )?;
        writeln!(out, "        <td>{hash_display}</td>")?;
        writeln!(out, "        <td>{size_display}</td>")?;
        writeln!(out, "        <td>{modified_display}</td>")?;
        writeln!(out, "        <td>{link_display}</td>")?;
        writeln!(out, "      </tr>")?;
    }

    writeln!(out, "    </tbody>")?;
    writeln!(out, "  </table>")?;
    writeln!(out, "  <div class=\"footer\">")?;
    writeln!(
        out,
        "    {} entries &middot; Generated by dirhashmake",
        entries.len()
    )?;
    writeln!(out, "  </div>")?;
    writeln!(out, "</body>")?;
    writeln!(out, "</html>")?;

    out.flush()?;
    Ok(())
}

/// Escape a string for HTML content.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_entries() -> Vec<Entry> {
        vec![
            Entry {
                path: PathBuf::from("/tmp/test"),
                relative_path: PathBuf::from("file.txt"),
                entry_type: EntryType::File,
                sha256: Some("abc123def456".to_string()),
                size: Some(1024),
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
                link_target: Some("file.txt".to_string()),
            },
        ]
    }

    #[test]
    fn test_write_json() {
        let entries = test_entries();
        let result = write_json(&entries, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_json_to_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_json");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.json");

        let entries = test_entries();
        let result = write_json(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("file.txt"));
        assert!(content.contains("abc123def456"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_yaml() {
        let entries = test_entries();
        let result = write_yaml(&entries, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_yaml_to_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_yaml");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.yaml");

        let entries = test_entries();
        let result = write_yaml(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("file.txt"));
        assert!(content.contains("abc123def456"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_sql() {
        let entries = test_entries();
        let result = write_sql(&entries, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_sql_to_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_sql");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.sql");

        let entries = test_entries();
        let result = write_sql(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("CREATE TABLE"));
        assert!(content.contains("INSERT INTO"));
        assert!(content.contains("file.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_sql_escaping() {
        let entries = vec![Entry {
            path: PathBuf::from("/tmp/test"),
            relative_path: PathBuf::from("file'with'quotes.txt"),
            entry_type: EntryType::File,
            sha256: Some("abc".to_string()),
            size: Some(10),
            modified: None,
            link_target: None,
        }];

        let dir = std::env::temp_dir().join("dirhashmake_test_sql_escape");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.sql");

        let result = write_sql(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("''"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_html() {
        let entries = test_entries();
        let result = write_html(&entries, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_html_to_file() {
        let dir = std::env::temp_dir().join("dirhashmake_test_html");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.html");

        let entries = test_entries();
        let result = write_html(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("<html"));
        assert!(content.contains("<style>"));
        assert!(content.contains("file.txt"));
        assert!(content.contains("abc123def456"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_html_escaping() {
        let entries = vec![Entry {
            path: PathBuf::from("/tmp/test"),
            relative_path: PathBuf::from("file<script>alert(1)</script>.txt"),
            entry_type: EntryType::File,
            sha256: Some("abc".to_string()),
            size: Some(10),
            modified: None,
            link_target: None,
        }];

        let dir = std::env::temp_dir().join("dirhashmake_test_html_escape");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output_path = dir.join("output.html");

        let result = write_html(&entries, &Some(output_path.clone()));
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(!content.contains("<script>"));
        assert!(content.contains("&lt;script&gt;"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_csv_with_format() {
        let entries = test_entries();
        let result = write_csv(&entries, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_output_dispatch() {
        let entries = test_entries();

        for fmt in [
            ExportFormat::Csv,
            ExportFormat::Json,
            ExportFormat::Yaml,
            ExportFormat::Sql,
            ExportFormat::Html,
        ] {
            let result = write_output(&entries, &None, fmt);
            assert!(result.is_ok(), "Failed for format: {fmt}");
        }
    }

    #[test]
    fn test_format_bytes_all() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Csv.to_string(), "csv");
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::Yaml.to_string(), "yaml");
        assert_eq!(ExportFormat::Sql.to_string(), "sql");
        assert_eq!(ExportFormat::Html.to_string(), "html");
    }

    #[test]
    fn test_export_format_from_str() {
        assert_eq!("csv".parse::<ExportFormat>().unwrap(), ExportFormat::Csv);
        assert_eq!("json".parse::<ExportFormat>().unwrap(), ExportFormat::Json);
        assert_eq!("yaml".parse::<ExportFormat>().unwrap(), ExportFormat::Yaml);
        assert_eq!("yml".parse::<ExportFormat>().unwrap(), ExportFormat::Yaml);
        assert_eq!("sql".parse::<ExportFormat>().unwrap(), ExportFormat::Sql);
        assert_eq!("html".parse::<ExportFormat>().unwrap(), ExportFormat::Html);
        assert_eq!("htm".parse::<ExportFormat>().unwrap(), ExportFormat::Html);
        assert!("unknown".parse::<ExportFormat>().is_err());
    }
}
