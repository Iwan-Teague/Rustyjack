use super::state::StartApErrorHint;

pub(crate) fn format_bytes_per_sec(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B/s", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB/s", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB/s", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub(crate) fn extract_errno(err: &str) -> Option<i32> {
    let lower = err.to_ascii_lowercase();
    for key in ["errno", "os error"] {
        if let Some(pos) = lower.find(key) {
            let rest = &lower[pos + key.len()..];
            let digits: String = rest
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                if let Ok(num) = digits.parse::<i32>() {
                    return Some(num);
                }
            }
        }
    }
    None
}

pub(crate) fn classify_start_ap_error(err: &str) -> Option<StartApErrorHint> {
    let lower = err.to_ascii_lowercase();
    if lower.contains("rfkill") {
        return Some(StartApErrorHint {
            category: "RF-kill blocked",
            hint: "Unblock wireless and retry.",
        });
    }
    if lower.contains("does not support ap")
        || (lower.contains("ap mode") && lower.contains("not support"))
    {
        return Some(StartApErrorHint {
            category: "Adapter lacks AP mode",
            hint: "Use an AP-capable adapter.",
        });
    }
    if lower.contains("interface busy") || lower.contains("device busy") {
        return Some(StartApErrorHint {
            category: "Interface busy",
            hint: "Stop wpa_supplicant/NetworkManager on the AP interface.",
        });
    }
    if lower.contains("no valid channels") || lower.contains("regdom") {
        return Some(StartApErrorHint {
            category: "Regdom/channel invalid",
            hint: "Set a country code and select a valid channel.",
        });
    }

    match extract_errno(err) {
        Some(16) => Some(StartApErrorHint {
            category: "Interface busy",
            hint: "Stop wpa_supplicant/NetworkManager on the AP interface.",
        }),
        Some(19) => Some(StartApErrorHint {
            category: "Interface missing",
            hint: "Check the interface name and adapter.",
        }),
        Some(22) | Some(34) => Some(StartApErrorHint {
            category: "Regdom/channel invalid",
            hint: "Set a country code and select a valid channel.",
        }),
        Some(95) => Some(StartApErrorHint {
            category: "Adapter lacks AP mode",
            hint: "Use an AP-capable adapter.",
        }),
        Some(1) | Some(13) => Some(StartApErrorHint {
            category: "Permission denied",
            hint: "Run as root with CAP_NET_ADMIN.",
        }),
        _ => None,
    }
}

pub(crate) fn mac_error_hint(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("busy") || lower.contains("resource busy") {
        return "Stop hotspot or disconnect Wi-Fi, then retry.";
    }
    if lower.contains("permission") || lower.contains("not permitted") {
        return "Check CAP_NET_ADMIN and systemd sandbox.";
    }
    if lower.contains("not supported") || lower.contains("operation not supported") {
        return "Driver may not allow MAC changes in this mode.";
    }
    "Check permissions/driver."
}
