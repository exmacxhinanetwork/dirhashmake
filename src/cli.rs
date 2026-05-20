use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;

/// Supported export formats.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ExportFormat {
    #[default]
    Csv,
    Json,
    Yaml,
    Sql,
    Html,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportFormat::Csv => write!(f, "csv"),
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::Yaml => write!(f, "yaml"),
            ExportFormat::Sql => write!(f, "sql"),
            ExportFormat::Html => write!(f, "html"),
        }
    }
}

impl std::str::FromStr for ExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "csv" => Ok(ExportFormat::Csv),
            "json" => Ok(ExportFormat::Json),
            "yaml" | "yml" => Ok(ExportFormat::Yaml),
            "sql" => Ok(ExportFormat::Sql),
            "html" | "htm" => Ok(ExportFormat::Html),
            other => Err(format!("unknown format: {other}")),
        }
    }
}

/// CLI argument parser.
#[derive(Parser)]
#[command(
    name = "dirhashmake",
    about = "Hash local directories with SHA-256 and export results"
)]
pub struct Args {
    /// Directory to hash
    #[arg(default_value = ".")]
    pub directory: PathBuf,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Export format (csv, json, yaml, sql, html)
    #[arg(short, long, default_value = "csv")]
    pub format: ExportFormat,

    /// Verbose progress output to stderr
    #[arg(short, long)]
    pub verbose: bool,

    /// Number of parallel worker tasks
    #[arg(short = 'j', long)]
    pub jobs: Option<usize>,

    /// Use absolute paths instead of relative
    #[arg(long)]
    pub absolute: bool,

    /// Pause and prompt before hashing begins (value: scan)
    #[arg(long, value_parser = ["scan"])]
    pub confirm: Option<String>,

    /// Recurse into subdirectories
    #[arg(short = 'r', long, default_value_t = true)]
    pub recursive: bool,

    /// Maximum recursion depth (requires --recursive)
    #[arg(long)]
    pub max_depth: Option<usize>,
}

/// Parse environment variable options from a colon-separated key=value string.
/// The env var name is derived from the executable name (uppercased).
pub fn parse_env_options() -> HashMap<String, String> {
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

/// Merge environment variable options into parsed CLI args.
/// CLI flags take precedence over env var values.
pub fn merge_env_options(args: &mut Args, env_opts: &HashMap<String, String>) {
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

    if let Some(fmt_str) = env_opts.get("format") {
        if let Ok(fmt) = fmt_str.parse::<ExportFormat>() {
            args.format = fmt;
        }
    }
}

/// Prompt the user to confirm before proceeding with hashing.
pub fn confirm_scan() -> bool {
    eprint!("Continue? [Y/n] ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let input = input.trim().to_lowercase();
    input.is_empty() || input == "y" || input == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
