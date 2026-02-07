# UI Action Map (Static UI → Backend Wiring)

This file is the source of truth for UI-to-backend wiring. Each static UI entry must map to a concrete backend path or a bounded local operation. No UI action may route to stubs or no-ops.

Legend:
- Route: Local UI method, Operation runner, or IPC command.
- RequiredOps: daemon ops category required for the IPC endpoint (if applicable).

## MenuAction Mapping

| MenuAction | UI Route | IPC / Backend | RequiredOps |
| --- | --- | --- | --- |
| Submenu | MenuState navigation | Local | N/A |
| ShowInfo | No-op informational entry | Local | N/A |
| RefreshConfig | `App::reload_config` | Local | N/A |
| SaveConfig | `App::save_config` | Local | N/A |
| SetColor | `App::pick_color` | Local | N/A |
| ApplyThemePreset | `App::apply_theme_preset` | Local | N/A |
| ViewDashboards | `dashboard_view` | Local | N/A |
| RestartSystem | `App::restart_system` | `SystemCommand::Reboot` | Power |
| SecureShutdown | `App::secure_shutdown` | `SystemCommand::Poweroff` | Power |
| SystemUpdate | `App::system_update` | `SystemCommand::Update` | Update |
| Loot(section) | `App::show_loot` | `LootCommand::{List,Read}` | Loot |
| DiscordUpload | `App::discord_upload` | `NotifyCommand::Discord(Send)` | System |
| ToggleDiscord | `App::toggle_discord` | Local | N/A |
| ToggleLogs | `App::toggle_logs` | `LoggingConfigSet` endpoint | System |
| DisplayBackendInfo | `App::show_display_backend_info` | Local | N/A |
| DisplayRotationInfo | `App::show_display_rotation_info` | Local | N/A |
| DisplayResolutionInfo | `App::show_display_resolution_info` | Local | N/A |
| DisplayOffsetInfo | `App::show_display_offset_info` | Local | N/A |
| RunDisplayDiscovery | `App::run_display_discovery_action` | Local (updates cached display probe state) | N/A |
| RunDisplayCalibration | `App::run_display_calibration_flow` | Local (manual calibration flow) | N/A |
| ResetDisplayCalibration | `App::reset_display_calibration_action` | Local | N/A |
| ResetDisplayCache | `App::reset_display_cache_action` | Local | N/A |
| ShowDisplayDiagnostics | `App::show_display_diagnostics` | Local | N/A |
| ExportLogsToUsb | `App::export_logs_to_usb` | `SystemCommand::ExportLogsToUsb` | Storage |
| TransferToUSB | `App::transfer_to_usb` | `SystemCommand::UsbMount/UsbUnmount` | Storage |
| HardwareDetect | `App::show_hardware_detect` | `HardwareCommand::Detect` | None |
| SelectActiveInterface | `App::select_active_interface` | `JobKind::InterfaceSelect` | Eth |
| ViewInterfaceStatus | `App::view_interface_status` | `WifiCommand::Status` | Wifi |
| ScanNetworks | `App::scan_wifi_networks` | `WifiCommand::Scan` | Wifi |
| ConnectKnownNetwork | `App::connect_known_network` | `WifiCommand::Profile::Connect` | Wifi |
| WifiStatus | `App::show_wifi_status` | `WifiCommand::Status` | Wifi |
| WifiDisconnect | `App::disconnect_wifi` | `WifiCommand::Disconnect` | Wifi |
| WifiEnsureRoute | `App::ensure_route` | `WifiCommand::Route::Ensure` | Wifi |
| ManageSavedNetworks | `App::manage_saved_networks` | `WifiCommand::Profile::{List,Show,Delete}` | Wifi |
| DeauthAttack | `OperationRunner::run(DeauthAttackOp)` | `WifiCommand::Deauth` | Offensive |
| EvilTwinAttack | `OperationRunner::run(EvilTwinAttackOp)` | `WifiCommand::EvilTwin` | Offensive |
| ProbeSniff | `OperationRunner::run(ProbeSniffOp)` | `WifiCommand::ProbeSniff` | Offensive |
| PmkidCapture | `OperationRunner::run(PmkidCaptureOp)` | `WifiCommand::PmkidCapture` | Offensive |
| KarmaAttack | `OperationRunner::run(KarmaAttackOp)` | `WifiCommand::Karma` | Offensive |
| CrackHandshake | `App::launch_crack_handshake` | `WifiCommand::Crack` | Offensive |
| AttackPipeline(GetPassword) | `App::launch_attack_pipeline` | `WifiCommand::PipelinePreflight` (preflight when no review) | Offensive |
| AttackPipeline(MassCapture) | `App::launch_attack_pipeline` | `WifiCommand::PipelinePreflight` (preflight when no review) | Offensive |
| AttackPipeline(StealthRecon) | `App::launch_attack_pipeline` | `WifiCommand::PipelinePreflight` (preflight when no review) | Offensive |
| AttackPipeline(CredentialHarvest) | `App::launch_attack_pipeline` | `WifiCommand::PipelinePreflight` (preflight when no review) | Offensive |
| AttackPipeline(FullPentest) | `App::launch_attack_pipeline` | `WifiCommand::PipelinePreflight` (preflight when no review) | Offensive |
| ReconGateway | `OperationRunner::run(GatewayReconOp)` | `WifiReconCommand::Gateway` | Wifi |
| ReconArpScan | `OperationRunner::run(ArpScanOp)` | `WifiReconCommand::ArpScan` | Wifi |
| ReconServiceScan | `OperationRunner::run(ServiceScanOp)` | `WifiReconCommand::ServiceScan` | Wifi |
| ReconMdnsScan | `OperationRunner::run(MdnsScanOp)` | `WifiReconCommand::MdnsScan` | Wifi |
| ReconBandwidth | `OperationRunner::run(BandwidthMonitorOp)` | `WifiReconCommand::Bandwidth` | Wifi |
| ReconDnsCapture | `OperationRunner::run(DnsCaptureOp)` | `WifiReconCommand::DnsCapture` | Wifi |
| DnsSpoofStart | `App::start_dns_spoof` | `DnsSpoofCommand::Start` | Offensive |
| DnsSpoofStop | `App::stop_dns_spoof` | `DnsSpoofCommand::Stop` | Offensive |
| ToggleDnsSpoof | `App::toggle_dns_spoof` | `DnsSpoofCommand::{Start,Stop}` | Offensive |
| ReverseShell | `App::launch_reverse_shell` | `ReverseCommand::Launch` | Offensive |
| EthernetDiscovery | `OperationRunner::run(EthernetDiscoveryOp)` | `EthernetCommand::Discover` | Eth |
| EthernetPortScan | `OperationRunner::run(EthernetPortScanOp)` | `EthernetCommand::PortScan` | Eth |
| EthernetInventory | `OperationRunner::run(EthernetInventoryOp)` | `EthernetCommand::Inventory` | Eth |
| EthernetMitm | `OperationRunner::run(EthernetMitmOp)` | `MitmCommand::Start` | Offensive |
| EthernetMitmStatus | `App::show_mitm_status` | `StatusCommand::Network` | None |
| EthernetMitmStop | `App::stop_ethernet_mitm` | `MitmCommand::Stop` | Offensive |
| EthernetSiteCredPipeline | Menu navigation | Local | N/A |
| EthernetSiteCredCapture | `OperationRunner::run(EthernetSiteCredOp)` | `EthernetCommand::SiteCredCapture` | Offensive |
| BuildNetworkReport | `App::build_network_report` | Local | N/A |
| ToggleMacRandomization | `App::toggle_mac_randomization` | Local | N/A |
| TogglePerNetworkMac | `App::toggle_per_network_mac` | Local | N/A |
| RandomizeMacNow | `App::randomize_mac_now` | `WifiCommand::MacRandomize` | Wifi |
| SetVendorMac | `App::set_vendor_mac` | `WifiCommand::MacSetVendor` | Wifi |
| RestoreMac | `App::restore_mac` | `WifiCommand::MacRestore` | Wifi |
| ToggleHostnameRandomization | `App::toggle_hostname_randomization` | Local | N/A |
| RandomizeHostnameNow | `App::randomize_hostname_now` | `SystemCommand::RandomizeHostname` | System |
| SetOperationMode | `App::select_operation_mode` | Local | N/A |
| SetTxPower | `App::set_tx_power` | `WifiCommand::TxPower` | Wifi |
| TogglePassiveMode | `App::toggle_passive_mode` | Local | N/A |
| ToggleOps | `App::toggle_ops` | `OpsConfigSet` endpoint | None |
| PassiveRecon | `App::launch_passive_recon` | Local | N/A |
| ImportWifiFromUsb | `App::import_wifi_from_usb` | Local + profile write | Wifi |
| ImportWebhookFromUsb | `App::import_webhook_from_usb` | Local + config write | N/A |
| EncryptionLoadKey | `App::load_encryption_key_from_usb` | Local | N/A |
| EncryptionGenerateKey | `App::generate_encryption_key_on_usb` | Local | N/A |
| ToggleEncryptionMaster | `App::toggle_encryption_master` | Local | N/A |
| ToggleEncryptWebhook | `App::toggle_encrypt_webhook` | Local | N/A |
| ToggleEncryptLoot | `App::toggle_encrypt_loot` | Local | N/A |
| ToggleEncryptWifiProfiles | `App::toggle_encrypt_wifi_profiles` | Local | N/A |
| FullDiskEncryptionSetup | `App::start_full_disk_encryption_flow` | `SystemCommand::FdePrepare` (preflight only) | System |
| FullDiskEncryptionMigrate | `App::start_fde_migration` | `SystemCommand::FdeMigrate` (preflight only) | System |
| CompletePurge | `App::complete_purge` | `SystemCommand::Purge` (preflight only) | System |
| PurgeLogs | `App::purge_logs` | `SystemCommand::LogsClear` | System |
| Hotspot | `App::manage_hotspot` | `HotspotCommand::{Start,Stop,Status}` | Hotspot |
