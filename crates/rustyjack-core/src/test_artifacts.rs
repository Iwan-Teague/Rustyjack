//! Test artifact builders for Discord webhook uploads.
//!
//! Generates two artifacts after a test run:
//! - A ZIP archive of the run directory (streaming, no self-inclusion)
//! - A plaintext "all logs" file (streaming, chunked if oversized)

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

/// Default max bytes per artifact file (8 MiB).
const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Safety margin subtracted from max to avoid edge-case overflows.
const SAFETY_MARGIN: u64 = 256 * 1024;
/// Max lines to include from head of a large log.
const LOG_HEAD_LINES: usize = 200;
/// Max lines to include from tail of a large log.
const LOG_TAIL_LINES: usize = 400;
/// Threshold above which logs are truncated (64 KiB).
const LOG_TRUNCATE_THRESHOLD: u64 = 64 * 1024;
/// Section delimiter for plaintext log.
const SECTION_DELIM: &str = "================================================================";
/// Optional subdirectory in run_dir where installer logs are copied.
const INSTALL_LOGS_DIR_NAME: &str = "install_logs";

/// Build a plaintext "all logs" file from the test run directory.
///
/// Structure:
/// - Header metadata (run_id, timestamp, suite list, device info)
/// - Master run summary (run_summary.md verbatim)
/// - Per-suite sections in directory order with delimiters
/// - Truncates large logs (head/tail)
///
/// Returns paths to the generated file(s). If the output exceeds `max_bytes`,
/// it is chunked into `all_logs_part01.txt`, `all_logs_part02.txt`, etc.
pub fn build_plaintext_logs(
    run_dir: &Path,
    run_id: &str,
    max_bytes: Option<u64>,
) -> Result<Vec<PathBuf>> {
    let max = max_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);
    let effective_max = max.saturating_sub(SAFETY_MARGIN);

    // First pass: build content into a temporary single file
    let tmp_path = run_dir.join(format!("rustyjack_{}_all_logs.tmp", run_id));
    {
        let file = File::create(&tmp_path)
            .with_context(|| format!("creating temp log file: {}", tmp_path.display()))?;
        let mut writer = BufWriter::new(file);

        // Header
        writeln!(writer, "{}", SECTION_DELIM)?;
        writeln!(writer, "RustyJack Test Run - All Logs")?;
        writeln!(writer, "{}", SECTION_DELIM)?;
        writeln!(writer, "Run ID: {}", run_id)?;
        writeln!(
            writer,
            "Timestamp: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        )?;
        if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
            writeln!(writer, "Host: {}", hostname.trim())?;
        }
        writeln!(writer, "Results root: {}", run_dir.display())?;

        // Suite list
        let mut suites: Vec<String> = Vec::new();
        if let Ok(entries) = fs::read_dir(run_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name != INSTALL_LOGS_DIR_NAME {
                            suites.push(name.to_string());
                        }
                    }
                }
            }
        }
        suites.sort();
        writeln!(writer, "Suites: {}", suites.join(", "))?;
        writeln!(writer)?;

        // Master summary
        let summary_path = run_dir.join("run_summary.md");
        if summary_path.exists() {
            writeln!(writer, "{}", SECTION_DELIM)?;
            writeln!(writer, "MASTER SUMMARY: run_summary.md")?;
            writeln!(writer, "{}", SECTION_DELIM)?;
            append_file_streaming(&summary_path, &mut writer, None)?;
            writeln!(writer)?;
        }

        // Optional installer logs collected under run_dir/install_logs
        append_install_logs_section(run_dir, &mut writer)?;

        // Per-suite sections
        for suite_name in &suites {
            let suite_dir = run_dir.join(suite_name);
            if !suite_dir.is_dir() {
                continue;
            }

            writeln!(writer, "{}", SECTION_DELIM)?;
            writeln!(writer, "SUITE: {}", suite_name)?;
            writeln!(writer, "{}", SECTION_DELIM)?;

            // report.md
            let report = suite_dir.join("report.md");
            if report.exists() {
                writeln!(writer, "--- {}/report.md ---", suite_name)?;
                append_file_streaming(&report, &mut writer, None)?;
                writeln!(writer)?;
            }

            // run.log (potentially truncated)
            let log = suite_dir.join("run.log");
            if log.exists() {
                writeln!(writer, "--- {}/run.log ---", suite_name)?;
                let log_size =
                    fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
                if log_size > LOG_TRUNCATE_THRESHOLD {
                    append_file_head_tail(
                        &log,
                        &mut writer,
                        LOG_HEAD_LINES,
                        LOG_TAIL_LINES,
                    )?;
                } else {
                    append_file_streaming(&log, &mut writer, None)?;
                }
                writeln!(writer)?;
            }

            // summary.jsonl
            let summary_jsonl = suite_dir.join("summary.jsonl");
            if summary_jsonl.exists() {
                writeln!(writer, "--- {}/summary.jsonl ---", suite_name)?;
                let jsonl_size =
                    fs::metadata(&summary_jsonl).map(|m| m.len()).unwrap_or(0);
                if jsonl_size > LOG_TRUNCATE_THRESHOLD {
                    append_file_head_tail(
                        &summary_jsonl,
                        &mut writer,
                        50,
                        100,
                    )?;
                } else {
                    append_file_streaming(&summary_jsonl, &mut writer, None)?;
                }
                writeln!(writer)?;
            }
        }

        writer.flush()?;
    }

    // Check if chunking is needed
    let tmp_size = fs::metadata(&tmp_path)
        .map(|m| m.len())
        .unwrap_or(0);

    if tmp_size <= effective_max {
        // Single file, rename
        let final_path = run_dir.join(format!("rustyjack_{}_all_logs.txt", run_id));
        fs::rename(&tmp_path, &final_path)
            .with_context(|| "renaming all_logs temp file")?;
        return Ok(vec![final_path]);
    }

    // Chunk the file
    let parts = chunk_file(&tmp_path, run_dir, run_id, effective_max)?;
    fs::remove_file(&tmp_path).ok();
    Ok(parts)
}

/// Chunk a large file into numbered parts, preferring to split on suite boundaries.
fn chunk_file(
    src: &Path,
    output_dir: &Path,
    run_id: &str,
    max_bytes: u64,
) -> Result<Vec<PathBuf>> {
    let reader = BufReader::new(File::open(src)?);
    let mut parts: Vec<PathBuf> = Vec::new();
    let mut part_num: u32 = 1;
    let mut current_bytes: u64 = 0;
    let mut writer = create_part_writer(output_dir, run_id, part_num)?;
    parts.push(part_path(output_dir, run_id, part_num));

    for line in reader.lines() {
        let line = line.context("reading line from temp logs")?;
        let line_bytes = (line.len() + 1) as u64; // +1 for newline

        // Check if we should split: prefer splitting at suite boundaries
        if current_bytes + line_bytes > max_bytes && current_bytes > 0 {
            writer.flush()?;
            part_num += 1;
            writer = create_part_writer(output_dir, run_id, part_num)?;
            parts.push(part_path(output_dir, run_id, part_num));
            current_bytes = 0;
        }

        writeln!(writer, "{}", line)?;
        current_bytes += line_bytes;
    }

    writer.flush()?;
    Ok(parts)
}

fn part_path(dir: &Path, run_id: &str, part: u32) -> PathBuf {
    dir.join(format!("rustyjack_{}_all_logs_part{:02}.txt", run_id, part))
}

fn create_part_writer(
    dir: &Path,
    run_id: &str,
    part: u32,
) -> Result<BufWriter<File>> {
    let path = part_path(dir, run_id, part);
    let file = File::create(&path)
        .with_context(|| format!("creating part file: {}", path.display()))?;
    Ok(BufWriter::new(file))
}

/// Append an entire file to the writer using streaming I/O.
fn append_file_streaming(
    path: &Path,
    writer: &mut impl Write,
    max_bytes: Option<u64>,
) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut written: u64 = 0;

    for line in reader.lines() {
        let line = line?;
        let line_bytes = (line.len() + 1) as u64;
        if let Some(max) = max_bytes {
            if written + line_bytes > max {
                writeln!(writer, "[TRUNCATED at {} bytes]", written)?;
                break;
            }
        }
        writeln!(writer, "{}", line)?;
        written += line_bytes;
    }
    Ok(())
}

/// Append head + tail of a large file with a [TRUNCATED] marker.
fn append_file_head_tail(
    path: &Path,
    writer: &mut impl Write,
    head_lines: usize,
    tail_lines: usize,
) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening file for head/tail: {}", path.display()))?;
    let reader = BufReader::new(file);

    // Collect all lines (streaming but we need tail, so buffer line refs)
    // For memory safety on Pi, we only keep the tail buffer
    let mut head_done = false;
    let mut head_count = 0;
    let mut tail_buf: Vec<String> = Vec::with_capacity(tail_lines);
    let mut total_lines: usize = 0;

    for line in reader.lines() {
        let line = line?;
        total_lines += 1;

        if !head_done {
            writeln!(writer, "{}", line)?;
            head_count += 1;
            if head_count >= head_lines {
                head_done = true;
            }
        } else {
            if tail_buf.len() >= tail_lines {
                tail_buf.remove(0);
            }
            tail_buf.push(line);
        }
    }

    if head_done && !tail_buf.is_empty() {
        let skipped = total_lines - head_count - tail_buf.len();
        if skipped > 0 {
            writeln!(
                writer,
                "\n[TRUNCATED: {} lines omitted ({} total lines)]\n",
                skipped, total_lines
            )?;
        }
        for line in &tail_buf {
            writeln!(writer, "{}", line)?;
        }
    }

    Ok(())
}

fn append_install_logs_section(run_dir: &Path, writer: &mut impl Write) -> Result<()> {
    let install_dir = run_dir.join(INSTALL_LOGS_DIR_NAME);
    if !install_dir.is_dir() {
        return Ok(());
    }

    let mut files: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(&install_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();

    if files.is_empty() {
        return Ok(());
    }

    writeln!(writer, "{}", SECTION_DELIM)?;
    writeln!(writer, "INSTALLER LOGS")?;
    writeln!(writer, "{}", SECTION_DELIM)?;
    for file in files {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        writeln!(writer, "--- {}/{} ---", INSTALL_LOGS_DIR_NAME, name)?;
        let size = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        if size > LOG_TRUNCATE_THRESHOLD {
            append_file_head_tail(&file, writer, LOG_HEAD_LINES, LOG_TAIL_LINES)?;
        } else {
            append_file_streaming(&file, writer, None)?;
        }
        writeln!(writer)?;
    }

    Ok(())
}

/// Build a ZIP archive of the run directory using the `zip` crate.
/// - Archive is created outside run_dir (in temp), then moved in.
/// - Uses relative paths inside the archive.
/// - Skips FIFOs, sockets, the ZIP output itself, and existing archives.
pub fn build_results_zip(
    run_dir: &Path,
    run_id: &str,
) -> Result<PathBuf> {
    let final_path = run_dir.join(format!("rustyjack_{}_results.zip", run_id));
    let tmp_path = std::env::temp_dir().join(format!("rj_zip_{}.zip", run_id));

    {
        let file = File::create(&tmp_path)
            .with_context(|| format!("creating temp ZIP: {}", tmp_path.display()))?;
        let mut zip = zip::ZipWriter::new(BufWriter::new(file));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        let base_name = run_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("results");

        for entry in WalkDir::new(run_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip the final zip itself (if it exists from a previous run)
            if path == final_path {
                continue;
            }

            // Skip problematic file types
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if let Ok(ft) = path.symlink_metadata().map(|m| m.file_type()) {
                    if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device()
                    {
                        continue;
                    }
                }
            }

            // Skip existing archives and temp files
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(ext, "zip" | "tmp") {
                    continue;
                }
            }

            // Build relative path: base_name/relative_to_run_dir
            let relative = path
                .strip_prefix(run_dir)
                .unwrap_or(path);
            let archive_path = if relative == Path::new("") {
                base_name.to_string()
            } else {
                format!("{}/{}", base_name, relative.to_string_lossy().replace('\\', "/"))
            };

            if path.is_dir() {
                zip.add_directory(&archive_path, options)?;
            } else if path.is_file() {
                zip.start_file(&archive_path, options)?;
                let mut f = File::open(path)?;
                io::copy(&mut f, &mut zip)?;
            }
        }

        zip.finish()?;
    }

    // Move temp ZIP into run_dir
    fs::rename(&tmp_path, &final_path).or_else(|_| {
        // rename can fail across filesystems; fallback to copy+delete
        fs::copy(&tmp_path, &final_path)?;
        fs::remove_file(&tmp_path).ok();
        Ok::<(), io::Error>(())
    }).with_context(|| "moving ZIP to run directory")?;

    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_run_dir(dir: &Path, run_id: &str) {
        // Create master summary
        fs::write(
            dir.join("run_summary.md"),
            "# Test Summary\n- Tests: 10\n- Passed: 8\n- Failed: 2\n",
        )
        .unwrap();

        // Create two suite directories
        let suite_a = dir.join("suite_a");
        fs::create_dir_all(&suite_a).unwrap();
        fs::write(suite_a.join("report.md"), "# Suite A Report\nAll good.\n").unwrap();
        fs::write(suite_a.join("run.log"), "line 1\nline 2\nline 3\n").unwrap();

        let suite_b = dir.join("suite_b");
        fs::create_dir_all(&suite_b).unwrap();
        fs::write(suite_b.join("report.md"), "# Suite B Report\nSome issues.\n").unwrap();
        fs::write(
            suite_b.join("run.log"),
            "b_line 1\nb_line 2\nb_line 3\n",
        )
        .unwrap();
        fs::write(
            suite_b.join("summary.jsonl"),
            "{\"test\":\"b1\",\"pass\":true}\n{\"test\":\"b2\",\"pass\":false}\n",
        )
        .unwrap();
    }

    #[test]
    fn test_plaintext_logs_single_file() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run_001");
        fs::create_dir_all(&run_dir).unwrap();
        setup_run_dir(&run_dir, "001");

        let parts = build_plaintext_logs(&run_dir, "001", None).unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].exists());

        let content = fs::read_to_string(&parts[0]).unwrap();
        assert!(content.contains("RustyJack Test Run - All Logs"));
        assert!(content.contains("Run ID: 001"));
        assert!(content.contains("MASTER SUMMARY: run_summary.md"));
        assert!(content.contains("SUITE: suite_a"));
        assert!(content.contains("SUITE: suite_b"));
        assert!(content.contains("# Suite A Report"));
        assert!(content.contains("b_line 1"));
    }

    #[test]
    fn test_plaintext_logs_include_install_logs() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run_install");
        fs::create_dir_all(&run_dir).unwrap();
        setup_run_dir(&run_dir, "install");

        let install_dir = run_dir.join(INSTALL_LOGS_DIR_NAME);
        fs::create_dir_all(&install_dir).unwrap();
        fs::write(
            install_dir.join("install_latest.log"),
            "[INFO] installer start\n[INFO] installer done\n",
        )
        .unwrap();

        let parts = build_plaintext_logs(&run_dir, "install", None).unwrap();
        assert_eq!(parts.len(), 1);
        let content = fs::read_to_string(&parts[0]).unwrap();
        assert!(content.contains("INSTALLER LOGS"));
        assert!(content.contains("install_logs/install_latest.log"));
        assert!(content.contains("[INFO] installer done"));
    }

    #[test]
    fn test_plaintext_logs_delimiters() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run_002");
        fs::create_dir_all(&run_dir).unwrap();
        setup_run_dir(&run_dir, "002");

        let parts = build_plaintext_logs(&run_dir, "002", None).unwrap();
        let content = fs::read_to_string(&parts[0]).unwrap();

        // Verify section delimiters appear
        let delim_count = content.matches(SECTION_DELIM).count();
        // Header (1 pair) + master summary (1) + 2 suites (2) = at least 4 pairs of delimiters
        assert!(delim_count >= 8, "Expected at least 8 delimiters, got {}", delim_count);
    }

    #[test]
    fn test_plaintext_logs_chunking() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run_003");
        fs::create_dir_all(&run_dir).unwrap();
        setup_run_dir(&run_dir, "003");

        // Add a large log to force chunking with a very small max
        let suite_c = run_dir.join("suite_c");
        fs::create_dir_all(&suite_c).unwrap();
        let big_log: String = (0..5000)
            .map(|i| format!("Log line {} with some padding data to make it bigger\n", i))
            .collect();
        fs::write(suite_c.join("run.log"), &big_log).unwrap();
        fs::write(suite_c.join("report.md"), "# Suite C\n").unwrap();

        // Set max to 2 KiB to force multiple chunks
        let parts = build_plaintext_logs(&run_dir, "003", Some(2 * 1024)).unwrap();
        assert!(parts.len() > 1, "Expected multiple parts, got {}", parts.len());

        // Verify naming pattern
        for (i, part) in parts.iter().enumerate() {
            let expected_suffix = format!("all_logs_part{:02}.txt", i + 1);
            assert!(
                part.to_string_lossy().contains(&expected_suffix),
                "Part {} name mismatch: {:?}",
                i,
                part
            );
            // Each part should be under the effective max
            let size = fs::metadata(part).unwrap().len();
            // Allow some slack for the last line that pushes slightly over
            assert!(
                size <= 2 * 1024 + 256,
                "Part {} too large: {} bytes",
                i,
                size
            );
        }
    }

    #[test]
    fn test_zip_no_self_inclusion() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run_zip");
        fs::create_dir_all(&run_dir).unwrap();
        setup_run_dir(&run_dir, "zip1");

        let zip_path = build_results_zip(&run_dir, "zip1").unwrap();
        assert!(zip_path.exists());

        // Open and verify contents
        let file = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let mut names: Vec<String> = Vec::new();
        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            names.push(entry.name().to_string());
        }

        // Should not contain any .zip files
        assert!(
            !names.iter().any(|n| n.ends_with(".zip")),
            "ZIP contains itself: {:?}",
            names
        );

        // Should contain expected files with relative paths
        assert!(
            names.iter().any(|n| n.contains("run_summary.md")),
            "Missing run_summary.md in: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.contains("suite_a/report.md")),
            "Missing suite_a/report.md in: {:?}",
            names
        );

        // All paths should be relative (start with the base directory name)
        for name in &names {
            assert!(
                name.starts_with("run_zip"),
                "Non-relative path in ZIP: {}",
                name
            );
        }
    }

    #[test]
    fn test_head_tail_truncation() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("big.log");
        let lines: String = (0..1000)
            .map(|i| format!("Line {}\n", i))
            .collect();
        fs::write(&log_path, &lines).unwrap();

        let mut output = Vec::new();
        append_file_head_tail(&log_path, &mut output, 5, 3).unwrap();
        let result = String::from_utf8(output).unwrap();

        // Should contain first 5 lines
        assert!(result.contains("Line 0"));
        assert!(result.contains("Line 4"));
        // Should contain last 3 lines
        assert!(result.contains("Line 997"));
        assert!(result.contains("Line 998"));
        assert!(result.contains("Line 999"));
        // Should contain truncation marker
        assert!(result.contains("[TRUNCATED:"));
    }
}
