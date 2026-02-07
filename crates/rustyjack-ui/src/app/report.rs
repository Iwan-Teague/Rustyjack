use std::{
    collections::{HashMap, HashSet},
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use chrono::Local;
use serde_json::Value;
use walkdir::WalkDir;

use crate::{
    types::{ArtifactItem, MacUsageRecord, PipelineStats, TraversalResult},
    util::{count_lines, dir_has_files, port_role, shorten_for_display},
};

use super::state::App;

impl App {
    pub(crate) fn collect_network_names(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        let loot = self.root.join("loot");
        for name in ["Ethernet", "Wireless", "reports"] {
            if let Ok(entries) = fs::read_dir(loot.join(name)) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        if let Some(n) = entry.file_name().to_str() {
                            set.insert(n.to_string());
                        }
                    }
                }
            }
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        list
    }

    pub(crate) fn format_system_time(ts: SystemTime) -> String {
        let dt: chrono::DateTime<Local> = ts.into();
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    pub(crate) fn format_size_short(size: u64) -> String {
        if size < 1024 {
            format!("{}B", size)
        } else if size < 1024 * 1024 {
            format!("{:.1}KB", (size as f64) / 1024.0)
        } else {
            format!("{:.1}MB", (size as f64) / 1024.0 / 1024.0)
        }
    }

    pub(crate) fn safe_count_lines_limited(path: &Path, max_bytes: u64) -> Option<usize> {
        let meta = fs::metadata(path).ok()?;
        if meta.len() > max_bytes {
            return None;
        }
        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        Some(reader.lines().flatten().count())
    }

    pub(crate) fn summarize_json_file(path: &Path, max_bytes: u64) -> Option<String> {
        let meta = fs::metadata(path).ok()?;
        if meta.len() > max_bytes {
            return Some("large json (skipped)".to_string());
        }
        let data = fs::read_to_string(path).ok()?;
        let value: Value = serde_json::from_str(&data).ok()?;
        match value {
            Value::Array(arr) => Some(format!("entries: {}", arr.len())),
            Value::Object(map) => {
                if let Some(arr) = map.get("devices").and_then(|v| v.as_array()) {
                    return Some(format!("devices: {}", arr.len()));
                }
                if let Some(arr) = map.get("networks").and_then(|v| v.as_array()) {
                    return Some(format!("networks: {}", arr.len()));
                }
                if let Some(ssid) = map.get("ssid").and_then(|v| v.as_str()) {
                    return Some(format!("ssid: {}", shorten_for_display(ssid, 12)));
                }
                let mut keys: Vec<String> = map.keys().take(3).cloned().collect();
                if map.len() > 3 {
                    keys.push(format!("+{} more", map.len() - 3));
                }
                if keys.is_empty() {
                    None
                } else {
                    Some(format!("keys: {}", keys.join(",")))
                }
            }
            _ => None,
        }
    }

    pub(crate) fn classify_artifact_kind(name_lower: &str, ext: Option<&str>) -> (String, bool) {
        match ext {
            Some("pcap") | Some("pcapng") | Some("cap") => return ("pcap".to_string(), true),
            Some("hccapx") => return ("handshake".to_string(), true),
            Some("json") => {
                if name_lower.contains("handshake") || name_lower.contains("pmkid") {
                    return ("handshake".to_string(), true);
                }
                return ("json".to_string(), false);
            }
            Some("log") => return ("log".to_string(), false),
            Some("txt") => return ("txt".to_string(), false),
            Some("gz") => {
                if name_lower.contains("pcap") {
                    return ("pcap".to_string(), true);
                }
            }
            _ => {}
        }
        if name_lower.contains("credentials") {
            return ("credentials".to_string(), true);
        }
        if name_lower.contains("visits") {
            return ("visits".to_string(), true);
        }
        if name_lower.contains("pipeline") {
            return ("pipeline".to_string(), true);
        }
        if name_lower.contains("capture") {
            return ("capture".to_string(), true);
        }
        ("file".to_string(), false)
    }

    pub(crate) fn extract_pipeline_run(base: &Path, path: &Path) -> Option<String> {
        let rel = path.strip_prefix(base).ok()?;
        let mut comps = rel.components().peekable();
        while let Some(c) = comps.next() {
            if let Component::Normal(name) = c {
                if name == "pipelines" {
                    if let Some(Component::Normal(run)) = comps.next() {
                        return run.to_str().map(|s| s.to_string());
                    }
                }
            }
        }
        None
    }

    pub(crate) fn build_artifact_item(base: &Path, path: &Path) -> Option<ArtifactItem> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let rel = path
            .strip_prefix(base)
            .unwrap_or(path)
            .display()
            .to_string();
        let size = meta.len();
        let modified = meta.modified().ok();
        let name_lower = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase());
        let (kind, mut important) = Self::classify_artifact_kind(&name_lower, ext.as_deref());
        let mut note = None;

        let pipeline_run = Self::extract_pipeline_run(base, path);
        if pipeline_run.is_some() {
            important = true;
        }

        match kind.as_str() {
            "credentials" => {
                if let Some(count) = Self::safe_count_lines_limited(path, 512 * 1024) {
                    note = Some(format!("entries: {}", count));
                }
                important = true;
            }
            "visits" => {
                if let Some(count) = Self::safe_count_lines_limited(path, 512 * 1024) {
                    note = Some(format!("visits: {}", count));
                }
                important = true;
            }
            "json" | "handshake" => {
                if let Some(summary) = Self::summarize_json_file(path, 512 * 1024) {
                    note = Some(summary);
                }
                if kind == "handshake" {
                    important = true;
                }
            }
            "pcap" | "capture" => {
                note = Some(format!("size {}", Self::format_size_short(size)));
                important = true;
            }
            _ => {
                if size == 0 {
                    note = Some("empty file".to_string());
                }
            }
        }

        Some(ArtifactItem {
            rel,
            kind,
            size,
            modified,
            note,
            important,
            pipeline_run,
        })
    }

    pub(crate) fn summarize_counts(counts: &HashMap<String, usize>) -> String {
        let mut parts: Vec<(String, usize)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        parts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        parts
            .into_iter()
            .take(6)
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(crate) fn format_pipeline_lines(
        &self,
        pipeline: &HashMap<String, PipelineStats>,
    ) -> Vec<String> {
        if pipeline.is_empty() {
            return Vec::new();
        }
        let mut runs: Vec<(&String, &PipelineStats)> = pipeline.iter().collect();
        runs.sort_by(|a, b| b.1.latest.cmp(&a.1.latest).then_with(|| b.0.cmp(a.0)));
        let mut lines = Vec::new();
        for (idx, (name, stats)) in runs.iter().enumerate() {
            let mut parts = Vec::new();
            if stats.captures > 0 {
                parts.push(format!("pcap:{}", stats.captures));
            }
            if stats.creds > 0 {
                parts.push(format!("creds:{}", stats.creds));
            }
            if stats.visits > 0 {
                parts.push(format!("visits:{}", stats.visits));
            }
            if stats.logs > 0 {
                parts.push(format!("logs:{}", stats.logs));
            }
            let detail = if parts.is_empty() {
                format!("files: {}", stats.files)
            } else {
                format!("files: {} ({})", stats.files, parts.join(", "))
            };
            let mut line = format!("Pipeline run {} - {}", name, detail);
            if let Some(ts) = stats.latest {
                line.push_str(&format!(" [{}]", Self::format_system_time(ts)));
            }
            lines.push(line);
            if idx >= 2 {
                break;
            }
        }
        if pipeline.len() > 3 {
            lines.push(format!(" +{} more pipeline run(s)", pipeline.len() - 3));
        }
        lines
    }

    pub(crate) fn format_artifact_details(
        &self,
        items: &[ArtifactItem],
        limit: usize,
        total: usize,
    ) -> (Vec<String>, usize) {
        if items.is_empty() {
            return (Vec::new(), 0);
        }
        let mut items = items.to_vec();
        items.sort_by(|a, b| match (b.modified, a.modified) {
            (Some(tb), Some(ta)) => tb.cmp(&ta),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            _ => b.rel.cmp(&a.rel),
        });
        let mut notable: Vec<ArtifactItem> =
            items.iter().cloned().filter(|i| i.important).collect();
        let mut others: Vec<ArtifactItem> =
            items.iter().cloned().filter(|i| !i.important).collect();
        let mut selected = Vec::new();
        if !notable.is_empty() {
            let take = notable.len().min(limit);
            selected.extend(notable.drain(..take));
        }
        if selected.len() < limit && !others.is_empty() {
            let needed = limit - selected.len();
            let take = others.len().min(needed);
            selected.extend(others.drain(..take));
        }
        let extra = total.saturating_sub(selected.len());
        let mut lines = Vec::new();
        for item in selected {
            let mut line = format!(" - {} [{}]", shorten_for_display(&item.rel, 26), item.kind);
            if let Some(ts) = item.modified {
                line.push_str(&format!(" {}", Self::format_system_time(ts)));
            }
            line.push_str(&format!(" {}", Self::format_size_short(item.size)));
            if let Some(note) = item.note {
                line.push_str(&format!(" ({})", shorten_for_display(&note, 24)));
            }
            lines.push(line);
        }
        (lines, extra)
    }

    pub(crate) fn traverse_loot_dir(&self, base: &Path, limit: usize) -> TraversalResult {
        let mut result = TraversalResult::default();
        if !base.exists() {
            return result;
        }
        for entry in WalkDir::new(base).into_iter() {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    result.errors.push(e.to_string());
                    continue;
                }
            };
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            if let Some(item) = Self::build_artifact_item(base, path) {
                result.total_files += 1;
                *result.counts.entry(item.kind.clone()).or_insert(0) += 1;
                if let Some(run) = item.pipeline_run.as_ref() {
                    let stats = result.pipeline.entry(run.clone()).or_default();
                    stats.files += 1;
                    match item.kind.as_str() {
                        "pcap" | "capture" => stats.captures += 1,
                        "credentials" => stats.creds += 1,
                        "visits" => stats.visits += 1,
                        "log" => stats.logs += 1,
                        _ => {}
                    }
                    if let Some(ts) = item.modified {
                        stats.latest = match stats.latest {
                            Some(existing) => Some(existing.max(ts)),
                            None => Some(ts),
                        };
                    }
                }
                result.items.push(item);
            }
        }
        if result.items.len() > limit * 3 {
            // Keep memory bounded on very large trees
            result.items.truncate(limit * 3);
        }
        result
    }

    pub(crate) fn service_risk_notes(
        &self,
        ports: &std::collections::HashSet<u16>,
        banners: &[String],
    ) -> Vec<String> {
        let mut notes = Vec::new();
        let contains = |p: u16| ports.contains(&p);
        if contains(23) {
            notes.push("Telnet open (port 23) – cleartext management".to_string());
        }
        if contains(21) {
            notes.push("FTP open (port 21) – cleartext file transfer".to_string());
        }
        if contains(445) || contains(139) {
            notes.push("SMB/Windows file sharing exposed; lateral movement risk".to_string());
        }
        if contains(9100) || contains(515) || contains(631) {
            notes.push("Printer services detected; potential print spooler abuse".to_string());
        }
        if contains(2049) || contains(111) {
            notes.push("NFS/RPC exposed; check for anonymous exports".to_string());
        }
        if contains(548) || contains(445) {
            notes.push("NAS/file services present; audit shares and access controls".to_string());
        }
        if contains(3389) {
            notes.push("RDP open; enforce strong auth and lockouts".to_string());
        }
        if contains(80) && contains(443) && contains(8080) {
            notes.push("Multiple web ports; check for management panels".to_string());
        }
        let banner_hits: Vec<String> = banners
            .iter()
            .filter_map(|b| {
                let lower = b.to_ascii_lowercase();
                if lower.contains("printer") || lower.contains("jetdirect") {
                    Some("Banner hints printer hardware".to_string())
                } else if lower.contains("nas") || lower.contains("smb") {
                    Some("Banner indicates NAS/file server".to_string())
                } else if lower.contains("camera") || lower.contains("dvr") {
                    Some("Banner suggests camera/DVR device".to_string())
                } else {
                    None
                }
            })
            .collect();
        notes.extend(banner_hits);
        notes
    }

    pub(crate) fn append_artifact_section(
        &self,
        label: &str,
        dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push(label.to_string());
        if !dir.exists() {
            lines.push("No artifacts found here.".to_string());
            next_steps.push("Collect loot for this network to populate reports.".to_string());
            lines.push(String::new());
            return;
        }
        let traversal = self.traverse_loot_dir(dir, 12);
        if traversal.total_files == 0 {
            lines.push("Artifacts directory is empty.".to_string());
            next_steps.push("Run captures/scans to generate loot for this network.".to_string());
            lines.push(String::new());
            return;
        }
        let counts = Self::summarize_counts(&traversal.counts);
        let mut header = format!("Files: {}", traversal.total_files);
        if !counts.is_empty() {
            header.push_str(&format!(" ({})", counts));
        }
        lines.push(header);

        let pipeline_lines = self.format_pipeline_lines(&traversal.pipeline);
        if !pipeline_lines.is_empty() {
            lines.extend(pipeline_lines.clone());
            insights.push("Pipeline runs recorded; review artifacts for each run.".to_string());
        }

        let (detail_lines, extra) =
            self.format_artifact_details(&traversal.items, 12, traversal.total_files);
        if detail_lines.is_empty() {
            lines.push("No files could be summarized.".to_string());
        } else {
            lines.extend(detail_lines);
        }
        if extra > 0 {
            lines.push(format!(" +{} more file(s) not listed", extra));
        }
        if !traversal.errors.is_empty() {
            lines.push(format!(
                "Skipped {} item(s) due to read errors",
                traversal.errors.len()
            ));
        }
        lines.push(String::new());
    }

    pub(crate) fn generate_network_report(
        &mut self,
        network: &str,
    ) -> Result<(PathBuf, Vec<String>)> {
        let reports_root = self.root.join("loot").join("reports");
        fs::create_dir_all(&reports_root).ok();
        let reports_dir = reports_root.join(network);
        fs::create_dir_all(&reports_dir).ok();
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let path = reports_dir.join(format!("report_{timestamp}.txt"));

        let mut lines = Vec::new();
        let mut insights = Vec::new();
        let mut next_steps = Vec::new();
        lines.push(format!("Network Report: {}", network));
        lines.push(format!("Generated: {}", timestamp));
        lines.push(String::new());

        let eth_dir = self.root.join("loot").join("Ethernet").join(network);
        self.append_eth_report(
            network,
            &eth_dir,
            &mut lines,
            &mut insights,
            &mut next_steps,
        );

        let wifi_dir = self.root.join("loot").join("Wireless").join(network);
        self.append_wifi_report(&wifi_dir, &mut lines, &mut insights, &mut next_steps);

        self.append_mac_usage(network, &mut lines, &mut insights, &mut next_steps);

        self.append_combined_impact(
            network,
            &eth_dir,
            &wifi_dir,
            &mut lines,
            &mut insights,
            &mut next_steps,
        );

        if !insights.is_empty() || !next_steps.is_empty() {
            lines.push("[Insights]".to_string());
            if insights.is_empty() {
                lines.push("No notable findings captured.".to_string());
            } else {
                lines.extend(insights.clone());
            }
            lines.push(String::new());
            lines.push("[Next Steps]".to_string());
            if next_steps.is_empty() {
                lines.push("Consider deeper scanning or credential capture.".to_string());
            } else {
                lines.extend(next_steps.clone());
            }
        }

        fs::write(&path, lines.join("\n"))
            .with_context(|| format!("writing {}", path.display()))?;

        let final_path = if self.loot_encryption_active() {
            match self.encrypt_loot_file_in_place(&path) {
                Ok(enc_path) => enc_path,
                Err(e) => {
                    return Err(e.context("encrypting report output"));
                }
            }
        } else {
            path
        };

        Ok((final_path, lines))
    }

    pub(crate) fn append_eth_report(
        &self,
        network: &str,
        eth_dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[Ethernet]".to_string());
        if !eth_dir.exists() {
            lines.push("No Ethernet loot for this network.".to_string());
            lines.push(String::new());
            next_steps.push("Run Ethernet discovery/inventory to profile wired hosts.".to_string());
            return;
        }

        let mut collected_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
        let mut collected_banners: Vec<String> = Vec::new();

        // Inventory
        match self.read_inventory_summary(eth_dir) {
            Ok(Some((count, samples))) => {
                lines.push(format!("Inventory devices: {}", count));
                for s in samples {
                    lines.push(format!(" - {}", s));
                }
                if count == 0 {
                    next_steps.push(
                        "Inventory empty; run Device Inventory to profile hosts.".to_string(),
                    );
                }
            }
            Ok(None) => {
                lines.push("Inventory: none found".to_string());
                next_steps
                    .push("Inventory missing; run Device Inventory on this network.".to_string());
            }
            Err(e) => lines.push(format!(
                "Inventory read error: {}",
                shorten_for_display(&e.to_string(), 24)
            )),
        }

        // Port scans
        let port_lines = self.summarize_port_scans(network, eth_dir);
        if port_lines.is_empty() {
            lines.push("Port scans: none found".to_string());
            next_steps.push("Perform a port scan on key hosts to discover services.".to_string());
        } else {
            lines.extend(port_lines);
        }
        // Collect ports/banners for risk analysis
        let portscan_candidates = self.collect_portscan_candidates(network, eth_dir);
        for path in portscan_candidates.iter().take(4) {
            if let Ok((ports, banners)) = self.parse_portscan_file(path) {
                for p in ports {
                    collected_ports.insert(p);
                }
                for b in banners {
                    collected_banners.push(b);
                }
            }
        }

        // Discovery snapshots
        let discovery = self.summarize_discovery(network, eth_dir);
        if discovery.is_empty() {
            lines.push("Discovery: none found".to_string());
            next_steps.push("Run LAN discovery to map active hosts.".to_string());
        } else {
            lines.extend(discovery);
        }

        // MITM / DNS spoof
        let mitm = self.summarize_mitm(eth_dir);
        lines.extend(mitm.clone());
        if mitm
            .iter()
            .any(|l| l.contains("PCAPs:") || l.contains("Credentials:"))
        {
            insights.push(
                "Active MITM/DNS spoof activity recorded; artifacts may reveal testing footprint."
                    .to_string(),
            );
        }

        // Credential/visit summary
        let cred_lines = self.summarize_credentials(eth_dir);
        if cred_lines.is_empty() {
            lines.push("DNS spoof creds: none recorded".to_string());
            next_steps.push("Run MITM/DNS spoof to collect credentials or visits.".to_string());
        } else {
            lines.extend(cred_lines.clone());
            insights.push("Credentials/visit artifacts present; review carefully.".to_string());
        }

        // Service risk hints
        if !collected_ports.is_empty() || !collected_banners.is_empty() {
            let risks = self.service_risk_notes(&collected_ports, &collected_banners);
            if !risks.is_empty() {
                lines.push("Service insights:".to_string());
                lines.extend(risks.iter().take(4).map(|r| format!(" - {}", r)));
                if risks.len() > 4 {
                    lines.push(format!(" +{} more service hints", risks.len() - 4));
                }
                insights.push("Service fingerprints suggest potential weak points.".to_string());
            }
        }

        self.append_artifact_section("Ethernet loot sweep", eth_dir, lines, insights, next_steps);
    }

    pub(crate) fn append_wifi_report(
        &self,
        wifi_dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[Wireless]".to_string());
        if !wifi_dir.exists() {
            lines.push("No wireless loot for this network.".to_string());
            next_steps.push("Collect wireless captures/handshakes for this network.".to_string());
            return;
        }

        // DNS spoof/reverse shell context
        let dnsspoof_caps = self.root.join("DNSSpoof").join("captures");
        let dnsspoof_present = dir_has_files(&dnsspoof_caps);
        let (reverse_shells, bridge_events, payload_samples) = self.summarize_payload_activity();
        let bridge_pcaps = self.count_bridge_pcaps();

        let handshake_count = self.count_handshake_files(wifi_dir);
        if handshake_count > 0 {
            lines.push(format!("Captures: {} file(s)", handshake_count));
            insights.push(format!(
                "Wireless captures present ({} files).",
                handshake_count
            ));
        } else {
            lines.push("Captures: none found".to_string());
            next_steps.push("Attempt handshake/PMKID capture to obtain credentials.".to_string());
        }

        // DNS spoof captures
        if dnsspoof_present {
            lines.push("DNS spoof captures present".to_string());
            insights.push("Portal activity recorded; check visits/credentials.".to_string());
            next_steps.push("Inspect DNSSpoof/captures for creds/visits.".to_string());
        }

        // Payload-driven actions (reverse shells, bridges)
        if reverse_shells > 0 || bridge_events > 0 || bridge_pcaps > 0 {
            lines.push("Post-connection payloads:".to_string());
            if reverse_shells > 0 {
                lines.push(format!("Reverse shells launched: {}", reverse_shells));
                insights.push(
                    "Reverse shells were launched; ensure callbacks stay controlled.".to_string(),
                );
                next_steps.push(
                    "Review payload.log and close shells that are no longer needed.".to_string(),
                );
            }
            if bridge_events > 0 {
                lines.push(format!("Bridge toggles logged: {}", bridge_events));
                insights.push(
                    "Transparent bridge used; captures may hold in-transit credentials."
                        .to_string(),
                );
                next_steps.push("Review bridge PCAPs for credentials/session tokens.".to_string());
            }
            if bridge_pcaps > 0 {
                lines.push(format!("Bridge captures: {} PCAP(s)", bridge_pcaps));
            }
            if !payload_samples.is_empty() {
                lines.push("Recent payload log entries:".to_string());
                for entry in payload_samples.iter().rev().take(3) {
                    lines.push(format!(" - {}", shorten_for_display(entry, 72)));
                }
            }
        }

        self.append_artifact_section("Wireless loot sweep", wifi_dir, lines, insights, next_steps);
    }

    pub(crate) fn append_mac_usage(
        &self,
        network: &str,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[MAC Usage]".to_string());
        let mac_lines = self.summarize_mac_usage(network);
        if mac_lines.is_empty() {
            lines.push("No MAC usage entries logged for this network.".to_string());
            next_steps.push(
                "No MAC usage recorded; log activity to track interface rotation.".to_string(),
            );
        } else {
            lines.extend(mac_lines.iter().cloned());
            insights.push("MAC usage recorded; review rotation against opsec needs.".to_string());
        }
        lines.push(String::new());
    }

    pub(crate) fn append_combined_impact(
        &self,
        network: &str,
        eth_dir: &Path,
        wifi_dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[Combined Impact]".to_string());
        let mut summary = Vec::new();

        let inv_count = match self.read_inventory_summary(eth_dir) {
            Ok(Some((count, _))) => Some(count),
            _ => None,
        };
        if let Some(c) = inv_count {
            summary.push(format!("Ethernet hosts: {}", c));
        }
        let handshake_count = self.count_handshake_files(wifi_dir);
        if handshake_count > 0 {
            summary.push(format!("Wireless captures: {}", handshake_count));
        }

        let mac_count = self.mac_usage_count(network);
        if mac_count > 0 {
            summary.push(format!("MAC entries: {}", mac_count));
        }

        let dnsspoof_caps = self.root.join("DNSSpoof").join("captures");
        let dnsspoof_present = dir_has_files(&dnsspoof_caps);
        if dnsspoof_present {
            summary.push("DNS spoof captures present".to_string());
        }

        let (reverse_shells, bridge_events, _) = self.summarize_payload_activity();
        let bridge_pcaps = self.count_bridge_pcaps();
        if reverse_shells > 0 {
            summary.push(format!("Reverse shells: {}", reverse_shells));
        }
        if bridge_pcaps > 0 {
            summary.push(format!("Bridge PCAPs: {}", bridge_pcaps));
        }

        // Simple next-step heuristics
        if let Some(c) = inv_count {
            if c > 0 && handshake_count == 0 {
                next_steps.push(
                    "Hosts found on wired but no wireless captures; consider wireless attacks."
                        .to_string(),
                );
            }
        }
        if dnsspoof_present && handshake_count == 0 {
            next_steps.push(
                "DNS spoof run captured visits; follow up with wireless capture/handshake if needed."
                    .to_string(),
            );
        }
        if reverse_shells > 0 {
            insights.push(
                "Reverse shell callbacks launched; ensure only intended hosts are phoning home."
                    .to_string(),
            );
            next_steps.push("Audit payload.log and shut down shells after testing.".to_string());
        }
        if bridge_pcaps > 0 {
            insights.push(
                "Transparent bridge captures exist; PCAPs may hold cleartext credentials."
                    .to_string(),
            );
            next_steps.push("Review bridge PCAPs for credentials/session tokens.".to_string());
        }
        if handshake_count > 0 && dnsspoof_present {
            next_steps.push(
                "Use portal traffic plus wireless captures to correlate victims and crack credentials."
                    .to_string(),
            );
        }
        if reverse_shells > 0 && handshake_count > 0 {
            next_steps.push(
                "Combine cracked Wi-Fi creds with reverse shell access to pivot deeper."
                    .to_string(),
            );
        }
        if bridge_events > 0 && inv_count.unwrap_or(0) > 0 && handshake_count == 0 {
            next_steps.push(
                "Bridge captures without wireless loot; harvest creds from PCAPs or add handshake capture."
                    .to_string(),
            );
        }

        if summary.is_empty() {
            lines.push("No cross-medium data yet; collect Ethernet and Wireless loot.".to_string());
            next_steps.push(
                "Gather both wired and wireless data to build combined insights.".to_string(),
            );
            lines.push(String::new());
            return;
        }

        lines.push(summary.join(" | "));
        if inv_count.unwrap_or(0) == 0 {
            next_steps
                .push("Inventory empty; run Device Inventory to correlate hosts.".to_string());
        }
        if handshake_count == 0 {
            next_steps.push(
                "No wireless captures; attempt handshake/PMKID or probe captures.".to_string(),
            );
        }
        if mac_count == 0 {
            next_steps.push(
                "MAC usage not logged; ensure MAC logging is enabled during attacks.".to_string(),
            );
        }

        lines.push(String::new());
        insights.push(
            "Combined view links wired hosts, wireless captures, and MAC usage per network."
                .to_string(),
        );
    }

    pub(crate) fn summarize_payload_activity(&self) -> (usize, usize, Vec<String>) {
        let path = self.root.join("loot").join("payload.log");
        let mut reverse_shells = 0usize;
        let mut bridge_events = 0usize;
        let mut recent = Vec::new();
        if let Ok(file) = File::open(&path) {
            for line in BufReader::new(file).lines().flatten() {
                let lower = line.to_ascii_lowercase();
                let mut matched = false;
                if lower.contains("reverse-shell") {
                    reverse_shells += 1;
                    matched = true;
                }
                if lower.contains("bridge start") || lower.contains("bridge stop") {
                    bridge_events += 1;
                    matched = true;
                }
                if matched {
                    recent.push(line.clone());
                    if recent.len() > 5 {
                        recent.remove(0);
                    }
                }
            }
        }
        (reverse_shells, bridge_events, recent)
    }

    pub(crate) fn count_bridge_pcaps(&self) -> usize {
        let eth_root = self.root.join("loot").join("Ethernet");
        if !eth_root.exists() {
            return 0;
        }
        let mut pcaps = 0usize;
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !name.starts_with("bridge_") {
                    continue;
                }
                for item in WalkDir::new(&path).into_iter().flatten() {
                    let p = item.path();
                    if !p.is_file() {
                        continue;
                    }
                    if let Some(fname) = p.file_name().and_then(|n| n.to_str()) {
                        if fname.starts_with("mitm_") && fname.ends_with(".pcap") {
                            pcaps += 1;
                        }
                    }
                }
            }
        }
        pcaps
    }

    pub(crate) fn summarize_mac_usage(&self, network: &str) -> Vec<String> {
        let log_path = self.root.join("loot").join("reports").join("mac_usage.log");
        let file = match File::open(&log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines().flatten() {
            if let Ok(rec) = serde_json::from_str::<MacUsageRecord>(&line) {
                if rec.tag == network {
                    entries.push(rec);
                }
            }
        }
        if entries.is_empty() {
            return Vec::new();
        }
        entries.sort_by(|a, b| b.ts.cmp(&a.ts));
        let total = entries.len();
        let mut lines = Vec::new();
        lines.push(format!("MAC usage entries: {}", total));
        for rec in entries.iter().take(5) {
            lines.push(format!(
                " - {} via {} [{}] {}",
                rec.mac, rec.interface, rec.context, rec.ts
            ));
        }
        if total > 5 {
            lines.push(format!(" +{} more entries", total - 5));
        }
        lines
    }

    pub(crate) fn mac_usage_count(&self, network: &str) -> usize {
        let log_path = self.root.join("loot").join("reports").join("mac_usage.log");
        let file = match File::open(&log_path) {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let reader = BufReader::new(file);
        let mut count = 0usize;
        for line in reader.lines().flatten() {
            if let Ok(rec) = serde_json::from_str::<MacUsageRecord>(&line) {
                if rec.tag == network {
                    count += 1;
                }
            }
        }
        count
    }

    pub(crate) fn read_inventory_summary(
        &self,
        dir: &Path,
    ) -> Result<Option<(usize, Vec<String>)>> {
        if !dir.exists() {
            return Ok(None);
        }
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("inventory_") && name.ends_with(".json") {
                            files.push(path);
                        }
                    }
                }
            }
        }
        if files.is_empty() {
            return Ok(None);
        }
        files.sort();
        let latest = files
            .last()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No loot files found in directory"))?;
        let data = fs::read_to_string(&latest)
            .with_context(|| format!("Failed to read loot file: {}", latest.display()))?;
        let parsed: Vec<Value> = serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse loot JSON from: {}", latest.display()))?;
        let count = parsed.len();
        let mut samples = Vec::new();
        for dev in parsed.iter().take(4) {
            let ip = dev.get("ip").and_then(|v| v.as_str()).unwrap_or("?");
            let host = dev.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
            let os = dev.get("os_hint").and_then(|v| v.as_str()).unwrap_or("");
            let ports: Vec<String> = dev
                .get("open_ports")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| p.as_u64().map(|n| n as u16))
                        .collect()
                })
                .unwrap_or_else(Vec::new)
                .into_iter()
                .map(|p| format!("{}{}", p, port_role(p)))
                .collect();
            let mut desc = format!("{}", ip);
            if !host.is_empty() {
                desc.push_str(&format!(" ({})", host));
            }
            if !os.is_empty() {
                desc.push_str(&format!(" [{}]", os));
            }
            if !ports.is_empty() {
                desc.push_str(&format!(" ports: {}", ports.join(",")));
            }
            samples.push(desc);
        }
        Ok(Some((count, samples)))
    }

    pub(crate) fn summarize_port_scans(&self, network: &str, eth_dir: &Path) -> Vec<String> {
        let mut summaries = Vec::new();
        let mut candidates = Vec::new();
        if eth_dir.exists() {
            if let Ok(entries) = fs::read_dir(eth_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("portscan_") && name.ends_with(".txt") {
                                candidates.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        // Fallback: portscan files in loot/Ethernet containing the network name
        let eth_root = self.root.join("loot").join("Ethernet");
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("portscan_") && name.contains(network) {
                            candidates.push(path.clone());
                        }
                    }
                }
            }
        }
        if candidates.is_empty() {
            return summaries;
        }

        for path in candidates.iter().take(3) {
            if let Ok((ports, banners)) = self.parse_portscan_file(path) {
                let mut line = format!("Port scan: {} open", ports.len());
                if !ports.is_empty() {
                    let preview: Vec<String> = ports
                        .iter()
                        .take(6)
                        .map(|p| format!("{}{}", p, port_role(*p)))
                        .collect();
                    line.push_str(&format!(" [{}]", preview.join(", ")));
                }
                summaries.push(line);
                if !banners.is_empty() {
                    summaries.push(format!(" Banners: {}", banners.join(" | ")));
                }
            }
        }
        summaries
    }

    pub(crate) fn parse_portscan_file(&self, path: &Path) -> Result<(Vec<u16>, Vec<String>)> {
        let contents = fs::read_to_string(path)?;
        let mut ports = Vec::new();
        let mut banners = Vec::new();
        let mut in_open = false;
        let mut in_banners = false;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Open ports:") {
                in_open = true;
                in_banners = false;
                continue;
            }
            if trimmed.starts_with("Banners:") {
                in_banners = true;
                in_open = false;
                continue;
            }
            if in_open {
                if let Ok(p) = trimmed.parse::<u16>() {
                    ports.push(p);
                }
            } else if in_banners {
                if !trimmed.is_empty() {
                    banners.push(trimmed.to_string());
                }
            }
        }
        Ok((ports, banners))
    }

    pub(crate) fn collect_portscan_candidates(
        &self,
        network: &str,
        eth_dir: &Path,
    ) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if eth_dir.exists() {
            if let Ok(entries) = fs::read_dir(eth_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("portscan_") && name.ends_with(".txt") {
                                candidates.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        let eth_root = self.root.join("loot").join("Ethernet");
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("portscan_") && name.contains(network) {
                            candidates.push(path.clone());
                        }
                    }
                }
            }
        }
        candidates
    }

    pub(crate) fn summarize_discovery(&self, network: &str, eth_dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        let mut candidates = Vec::new();
        if eth_dir.exists() {
            if let Ok(entries) = fs::read_dir(eth_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("discovery_") {
                                candidates.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        let eth_root = self.root.join("loot").join("Ethernet");
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("discovery_") && name.contains(network) {
                            candidates.push(path.clone());
                        }
                    }
                }
            }
        }
        if candidates.is_empty() {
            return lines;
        }
        for path in candidates.iter().take(2) {
            if let Ok(count) = self.count_discovery_hosts(path) {
                lines.push(format!(
                    "Discovery: {} host(s) in {}",
                    count,
                    shorten_for_display(path.to_string_lossy().as_ref(), 18)
                ));
            }
        }
        lines
    }

    pub(crate) fn count_discovery_hosts(&self, path: &Path) -> Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0usize;
        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("LAN Discovery")
                || trimmed.starts_with("Interface")
                || trimmed.starts_with("Timeout")
                || trimmed.starts_with("Hosts:")
            {
                continue;
            }
            if trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                count += 1;
            }
        }
        Ok(count)
    }

    pub(crate) fn summarize_mitm(&self, eth_dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        if !eth_dir.exists() {
            return lines;
        }
        let mut pcaps = 0usize;
        if let Ok(entries) = fs::read_dir(eth_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("mitm_") && name.ends_with(".pcap") {
                            pcaps += 1;
                        }
                    }
                }
            }
        }
        let mut visits = 0usize;
        let mut creds = 0usize;
        let dns_dir = eth_dir.join("dnsspoof");
        if dns_dir.exists() {
            for entry in WalkDir::new(&dns_dir).into_iter().flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "visits.log" {
                            visits += count_lines(path).unwrap_or(0);
                        } else if name == "credentials.log" {
                            creds += count_lines(path).unwrap_or(0);
                        }
                    }
                }
            }
        }
        if pcaps == 0 && visits == 0 && creds == 0 {
            lines.push("MITM/DNS: none found".to_string());
        } else {
            lines.push(format!("MITM PCAPs: {}", pcaps));
            lines.push(format!("Spoof visits: {}", visits));
            lines.push(format!("Credentials: {}", creds));
        }
        lines
    }

    pub(crate) fn summarize_credentials(&self, eth_dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        let dns_dir = eth_dir.join("dnsspoof");
        if !dns_dir.exists() {
            return lines;
        }
        let mut total_creds = 0usize;
        let mut unique_creds: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total_visits = 0usize;
        let mut domains: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        let mut earliest: Option<SystemTime> = None;
        let mut latest: Option<SystemTime> = None;

        for entry in WalkDir::new(&dns_dir).into_iter().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let domain = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            let meta_time = path.metadata().and_then(|m| m.modified()).ok();
            if let Some(mt) = meta_time {
                earliest = Some(earliest.map(|e| e.min(mt)).unwrap_or(mt));
                latest = Some(latest.map(|l| l.max(mt)).unwrap_or(mt));
            }

            if fname == "credentials.log" {
                if let Ok(file) = File::open(path) {
                    for line in BufReader::new(file).lines().flatten() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        total_creds += 1;
                        unique_creds.insert(trimmed.to_string());
                        let entry = domains.entry(domain.clone()).or_insert((0, 0));
                        entry.0 += 1;
                    }
                }
            } else if fname == "visits.log" {
                if let Ok(file) = File::open(path) {
                    for line in BufReader::new(file).lines().flatten() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        total_visits += 1;
                        let entry = domains.entry(domain.clone()).or_insert((0, 0));
                        entry.1 += 1;
                    }
                }
            }
        }

        if total_creds == 0 && total_visits == 0 {
            return lines;
        }

        let mut domain_parts = Vec::new();
        for (d, (c, v)) in domains.iter() {
            if *c > 0 || *v > 0 {
                domain_parts.push(format!("{} (creds {}, visits {})", d, c, v));
            }
        }
        domain_parts.sort();

        if total_creds > 0 {
            lines.push(format!(
                "Credentials: {} total ({} unique)",
                total_creds,
                unique_creds.len()
            ));
            if total_creds > unique_creds.len() {
                lines.push(" Duplicate credentials observed across sessions.".to_string());
            }
        } else {
            lines.push("Credentials: none recorded".to_string());
        }
        if total_visits > 0 {
            lines.push(format!("Spoof visits: {}", total_visits));
        }

        if !domain_parts.is_empty() {
            lines.push(format!(
                "Domains: {}",
                shorten_for_display(&domain_parts.join(" | "), 48)
            ));
        }

        if let Some(ts) = earliest {
            lines.push(format!("First artifact: {}", Self::format_system_time(ts)));
        }
        if let Some(ts) = latest {
            lines.push(format!("Last artifact: {}", Self::format_system_time(ts)));
        }

        lines
    }

    pub(crate) fn count_handshake_files(&self, dir: &Path) -> usize {
        if !dir.exists() {
            return 0;
        }
        let exts = ["pcap", "pcapng", "cap", "hccapx"];
        let mut count = 0usize;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if exts.iter().any(|x| ext.eq_ignore_ascii_case(x)) {
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }

    pub(crate) fn choose_dnsspoof_site(&mut self, sites: &[String]) -> Result<Option<String>> {
        if sites.is_empty() {
            return Ok(None);
        }
        let mut options = sites.to_vec();
        options.push("Cancel".to_string());
        let Some(choice) = self.choose_from_menu("DNS Spoof Site", &options)? else {
            return Ok(None);
        };
        if choice >= sites.len() {
            Ok(None)
        } else {
            Ok(Some(sites[choice].clone()))
        }
    }

}
