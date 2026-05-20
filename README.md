# dirhashmake

A multi-threaded Rust CLI that recursively hashes local directories with SHA-256 and exports results as CSV.

## Features

- **SHA-256 hashing** of all files in a directory tree
- **Async directory traversal** using `tokio::fs`
- **Parallel processing** with configurable worker count
- **Pre-scan phase** with statistics and optional confirmation prompt
- **Depth control** via `--max-depth`
- **Verbose progress** telemetry to stderr
- **Environment variable** configuration (`DIRHASHMAKE`)
- **CSV output** with path, type, hash, size, modified time, and symlink target

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/dirhashmake`.

## Usage

```
dirhashmake [OPTIONS] [DIRECTORY]
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `[DIRECTORY]` | `.` | Directory to hash |

### Options

| Flag | Description |
|------|-------------|
| `-o, --output <FILE>` | Write CSV to file (default: stdout) |
| `-v, --verbose` | Print progress to stderr |
| `-j, --jobs <N>` | Number of parallel workers (default: CPU count) |
| `-r, --recursive` | Recurse into subdirectories (default: true) |
| `--max-depth <N>` | Limit recursion depth |
| `--absolute` | Use absolute paths |
| `--confirm=scan` | Prompt before hashing begins |
| `-h, --help` | Print help |

### Environment Variable

Set `DIRHASHMAKE` with colon-separated `key=value` pairs:

```bash
DIRHASHMAKE=verbose=true:confirm=scan dirhashmake /path/to/dir
```

### Examples

```bash
# Hash current directory, output to stdout
dirhashmake

# Hash a directory, write CSV to file
dirhashmake /path/to/project -o hashes.csv

# Hash with verbose progress, limit to 2 levels deep
dirhashmake /path/to/project --max-depth 2 -v

# Hash with confirmation prompt
dirhashmake /large/dir --confirm=scan -o output.csv

# Use environment variable for defaults
export DIRHASHMAKE=verbose=true
dirhashmake /path/to/dir
```

## CSV Output

| Column | Description |
|--------|-------------|
| `path` | Relative or absolute path |
| `type` | `file`, `dir`, or `symlink` |
| `sha256` | SHA-256 hex digest (blank for dirs/symlinks) |
| `size` | File size in bytes (blank for dirs/symlinks) |
| `modified` | ISO 8601 timestamp (blank for symlinks) |
| `link_target` | Symlink target path (blank for files/dirs) |

## Architecture

- **Pre-scan**: Async directory walk collecting metadata-only statistics
- **Confirmation**: Optional prompt when `--confirm=scan` is set
- **Hashing**: Parallel tokio tasks with semaphore-gated concurrency
- **Output**: Sorted CSV written via `csv` crate

## Dependencies

- `clap` — CLI argument parsing
- `sha2` — SHA-256 hashing
- `tokio` — Async runtime and file I/O
- `csv` — CSV output
- `chrono` — Timestamp formatting
