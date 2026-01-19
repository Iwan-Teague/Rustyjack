# Build and Install Scripts Analysis
**Date:** January 3, 2026

**Status:** NEEDS FIXES - Missing portal binary installation

---

## Executive Summary

**CRITICAL ISSUE FOUND:** All three installation scripts are missing the `rustyjack-portal` binary that we implemented in Stage 5 Phase 2. The portal process spawning will fail in external mode because the binary won't be installed.

**ADDITIONAL ISSUE:** Docker build scripts only provide an environment; they don't automatically build or package binaries.

---

## Binary Inventory

### Defined Binaries (from Cargo.toml)

| Binary | Crate | Purpose | Currently Installed? |
|--------|-------|---------|---------------------|
| `rustyjack-ui` | rustyjack-ui | Embedded display UI | ✅ YES |
| `rustyjack` | rustyjack-core | CLI tool | ✅ YES |
| `rustyjackd` | rustyjack-daemon | Privileged daemon | ✅ YES |
| `rustyjack-portal` | rustyjack-portal | Captive portal server | ❌ **NO - MISSING** |

---

## Issues Found

### 1. Missing Portal Binary in All Installers

**Impact:** HIGH  
**Affected Scripts:**
- `install_rustyjack.sh` (production)
- `install_rustyjack_dev.sh` (development)
- `install_rustyjack_prebuilt.sh` (prebuilt)

<function_calls>
<invoke name="view">
<parameter name="path">C:\Users\teagu\Desktop\Rustyjack\install_rustyjack_prebuilt.sh
