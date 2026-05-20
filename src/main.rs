mod cli;
mod formatters;
mod hasher;
mod scanner;
mod types;

use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use tokio::task::JoinSet;

use cli::{confirm_scan, merge_env_options, parse_env_options, Args};
use hasher::process_entry;
use scanner::{collect_entries, run_pre_scan};
use types::EntryType;

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
    merge_env_options(&mut args, &env_opts);

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

    let scan_stats = run_pre_scan(&root, recursive, max_depth, absolute).await;
    formatters::print_stats(&scan_stats, verbose);

    if args.confirm.as_deref() == Some("scan") && !confirm_scan() {
        eprintln!("Aborted.");
        return;
    }

    let start = Instant::now();

    let entries = collect_entries(&root, recursive, max_depth, absolute).await;
    let total_entries = entries.len();

    let semaphore = Arc::new(tokio::sync::Semaphore::new(jobs));
    let mut set = JoinSet::new();

    for (idx, entry) in entries.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.unwrap();
            let result = process_entry(entry, absolute).await;
            (idx, result)
        });
    }

    let mut results: Vec<Option<types::Entry>> = vec![None; total_entries];
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

    let mut final_entries: Vec<types::Entry> = results.into_iter().flatten().collect();
    final_entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let hash_duration = start.elapsed();

    if verbose {
        eprintln!(
            "✓ Processed {} files, {} dirs, {} symlinks in {:?}",
            files_processed, dirs_processed, symlinks_processed, hash_duration
        );
    }

    formatters::write_output(&final_entries, &args.output, args.format).unwrap();
}
