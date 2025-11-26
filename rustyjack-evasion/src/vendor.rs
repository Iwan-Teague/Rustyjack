//! Vendor OUI database
//!
//! This module contains a database of common WiFi device vendor
//! OUIs (Organizationally Unique Identifiers) for generating
//! MAC addresses that blend in with common devices.
//!
//! ## Usage
//!
//! ```
//! use rustyjack_evasion::vendor::{VendorOui, VENDOR_DATABASE};
//!
//! // Get Apple's OUI
//! let apple = VendorOui::from_name("apple");
//! assert!(apple.is_some());
//!
//! // List all vendors
//! for vendor in VENDOR_DATABASE.iter() {
//!     println!("{}: {:02X}:{:02X}:{:02X}",
//!         vendor.name, vendor.oui[0], vendor.oui[1], vendor.oui[2]);
//! }
//! ```

use serde::{Deserialize, Serialize};

/// A vendor's OUI (first 3 bytes of MAC address)
/// 
/// Note: This struct uses static references for efficiency in the
/// built-in database. For serialization, use [`VendorOuiOwned`].
#[derive(Debug, Clone, Copy)]
pub struct VendorOui {
    /// Vendor name
    pub name: &'static str,
    
    /// Common aliases for this vendor
    pub aliases: &'static [&'static str],
    
    /// The 3-byte OUI
    pub oui: [u8; 3],
    
    /// Description or common devices
    pub description: &'static str,
}

/// Owned version of VendorOui for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorOuiOwned {
    /// Vendor name
    pub name: String,
    /// The 3-byte OUI
    pub oui: [u8; 3],
    /// Description
    pub description: String,
}

impl From<&VendorOui> for VendorOuiOwned {
    fn from(v: &VendorOui) -> Self {
        Self {
            name: v.name.to_string(),
            oui: v.oui,
            description: v.description.to_string(),
        }
    }
}

impl VendorOui {
    /// Look up a vendor by name or alias
    /// 
    /// Case-insensitive matching.
    #[must_use]
    pub fn from_name(name: &str) -> Option<&'static VendorOui> {
        let name_lower = name.to_lowercase();
        
        VENDOR_DATABASE.iter().find(|v| {
            v.name.to_lowercase() == name_lower
                || v.aliases.iter().any(|a| a.to_lowercase() == name_lower)
        })
    }
    
    /// Get all vendors matching a partial name
    #[must_use]
    pub fn search(query: &str) -> Vec<&'static VendorOui> {
        let query_lower = query.to_lowercase();
        
        VENDOR_DATABASE
            .iter()
            .filter(|v| {
                v.name.to_lowercase().contains(&query_lower)
                    || v.description.to_lowercase().contains(&query_lower)
                    || v.aliases.iter().any(|a| a.to_lowercase().contains(&query_lower))
            })
            .collect()
    }
    
    /// Format OUI as colon-separated string
    #[must_use]
    pub fn oui_string(&self) -> String {
        format!("{:02X}:{:02X}:{:02X}", self.oui[0], self.oui[1], self.oui[2])
    }
}

/// Database of common vendor OUIs
/// 
/// Includes major smartphone, laptop, and network equipment vendors.
pub static VENDOR_DATABASE: &[VendorOui] = &[
    // Mobile devices - common targets
    VendorOui {
        name: "Apple",
        aliases: &["iphone", "ipad", "macbook", "mac", "ios"],
        oui: [0xF4, 0x0F, 0x24],
        description: "iPhones, iPads, MacBooks",
    },
    VendorOui {
        name: "Apple-2",
        aliases: &[],
        oui: [0xAC, 0xBC, 0x32],
        description: "Apple devices (alternate OUI)",
    },
    VendorOui {
        name: "Apple-3",
        aliases: &[],
        oui: [0x00, 0x1C, 0xB3],
        description: "Apple devices (alternate OUI)",
    },
    VendorOui {
        name: "Samsung",
        aliases: &["galaxy", "android"],
        oui: [0x00, 0x1A, 0x8A],
        description: "Samsung Galaxy phones/tablets",
    },
    VendorOui {
        name: "Samsung-2",
        aliases: &[],
        oui: [0xEC, 0x1F, 0x72],
        description: "Samsung devices (alternate OUI)",
    },
    VendorOui {
        name: "Google",
        aliases: &["pixel", "nexus", "chromebook"],
        oui: [0xF8, 0x8F, 0xCA],
        description: "Pixel phones, Chromebooks",
    },
    VendorOui {
        name: "Huawei",
        aliases: &["honor"],
        oui: [0x48, 0x46, 0xFB],
        description: "Huawei/Honor devices",
    },
    VendorOui {
        name: "OnePlus",
        aliases: &["oneplus", "oppo"],
        oui: [0x94, 0x65, 0x2D],
        description: "OnePlus phones",
    },
    VendorOui {
        name: "Xiaomi",
        aliases: &["mi", "redmi", "poco"],
        oui: [0x64, 0xCC, 0x2E],
        description: "Xiaomi/Redmi phones",
    },
    
    // Laptops and PCs
    VendorOui {
        name: "Intel",
        aliases: &["laptop", "pc"],
        oui: [0x00, 0x1E, 0x67],
        description: "Intel WiFi adapters",
    },
    VendorOui {
        name: "Intel-2",
        aliases: &[],
        oui: [0x8C, 0xEC, 0x4B],
        description: "Intel WiFi (newer)",
    },
    VendorOui {
        name: "Dell",
        aliases: &["latitude", "xps", "inspiron"],
        oui: [0x00, 0x14, 0x22],
        description: "Dell computers",
    },
    VendorOui {
        name: "HP",
        aliases: &["hewlett-packard", "elitebook", "probook"],
        oui: [0x00, 0x21, 0x5A],
        description: "HP computers",
    },
    VendorOui {
        name: "Lenovo",
        aliases: &["thinkpad", "ideapad"],
        oui: [0x00, 0x1E, 0x4C],
        description: "Lenovo/ThinkPad computers",
    },
    
    // Network equipment
    VendorOui {
        name: "Cisco",
        aliases: &["linksys"],
        oui: [0x00, 0x1B, 0xD5],
        description: "Cisco network equipment",
    },
    VendorOui {
        name: "TP-Link",
        aliases: &["tplink"],
        oui: [0x50, 0xC7, 0xBF],
        description: "TP-Link routers/adapters",
    },
    VendorOui {
        name: "Netgear",
        aliases: &[],
        oui: [0x00, 0x14, 0x6C],
        description: "Netgear routers/adapters",
    },
    VendorOui {
        name: "Asus",
        aliases: &["rog"],
        oui: [0x00, 0x1A, 0x92],
        description: "Asus routers/devices",
    },
    VendorOui {
        name: "D-Link",
        aliases: &["dlink"],
        oui: [0x00, 0x1B, 0x11],
        description: "D-Link routers/adapters",
    },
    VendorOui {
        name: "Ubiquiti",
        aliases: &["unifi", "ubnt"],
        oui: [0xFC, 0xEC, 0xDA],
        description: "Ubiquiti/UniFi equipment",
    },
    
    // WiFi chipset manufacturers
    VendorOui {
        name: "Realtek",
        aliases: &["rtl"],
        oui: [0x00, 0xE0, 0x4C],
        description: "Realtek WiFi chips",
    },
    VendorOui {
        name: "Atheros",
        aliases: &["qualcomm", "qca"],
        oui: [0x00, 0x03, 0x7F],
        description: "Atheros/Qualcomm WiFi",
    },
    VendorOui {
        name: "Broadcom",
        aliases: &["bcm"],
        oui: [0x00, 0x10, 0x18],
        description: "Broadcom WiFi chips",
    },
    VendorOui {
        name: "MediaTek",
        aliases: &["ralink", "mtk"],
        oui: [0x00, 0x0C, 0xE7],
        description: "MediaTek/Ralink WiFi",
    },
    
    // IoT and smart devices
    VendorOui {
        name: "Amazon",
        aliases: &["echo", "alexa", "fire", "kindle"],
        oui: [0x40, 0xB4, 0xCD],
        description: "Amazon Echo/Fire devices",
    },
    VendorOui {
        name: "Ring",
        aliases: &["doorbell"],
        oui: [0x00, 0x62, 0x6E],
        description: "Ring doorbells/cameras",
    },
    VendorOui {
        name: "Nest",
        aliases: &["google-home"],
        oui: [0x18, 0xB4, 0x30],
        description: "Nest/Google Home devices",
    },
    VendorOui {
        name: "Sonos",
        aliases: &["speaker"],
        oui: [0x00, 0x0E, 0x58],
        description: "Sonos speakers",
    },
    VendorOui {
        name: "Philips",
        aliases: &["hue"],
        oui: [0x00, 0x17, 0x88],
        description: "Philips Hue/smart devices",
    },
    
    // Generic/locally administered
    VendorOui {
        name: "Local",
        aliases: &["random", "custom", "private"],
        oui: [0x02, 0x00, 0x00],
        description: "Locally administered (random)",
    },
];

/// Get a list of all vendor names
#[must_use]
pub fn all_vendor_names() -> Vec<&'static str> {
    VENDOR_DATABASE.iter().map(|v| v.name).collect()
}

/// Get a random vendor from the database
pub fn random_vendor() -> &'static VendorOui {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..VENDOR_DATABASE.len());
    &VENDOR_DATABASE[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vendor_lookup() {
        let apple = VendorOui::from_name("apple").unwrap();
        assert_eq!(apple.oui, [0xF4, 0x0F, 0x24]);
        
        // Test alias
        let iphone = VendorOui::from_name("iphone").unwrap();
        assert_eq!(iphone.name, "Apple");
    }
    
    #[test]
    fn test_case_insensitive() {
        assert!(VendorOui::from_name("APPLE").is_some());
        assert!(VendorOui::from_name("Apple").is_some());
        assert!(VendorOui::from_name("apple").is_some());
    }
    
    #[test]
    fn test_vendor_search() {
        let results = VendorOui::search("phone");
        assert!(!results.is_empty());
    }
    
    #[test]
    fn test_oui_string() {
        let apple = VendorOui::from_name("apple").unwrap();
        assert_eq!(apple.oui_string(), "F4:0F:24");
    }
    
    #[test]
    fn test_all_vendors() {
        let names = all_vendor_names();
        assert!(!names.is_empty());
        assert!(names.contains(&"Apple"));
    }
    
    #[test]
    fn test_random_vendor() {
        // Just ensure it doesn't panic
        let _ = random_vendor();
    }
}
