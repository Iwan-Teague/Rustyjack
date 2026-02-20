#!/usr/bin/env bash
set -euo pipefail

# Run from pcb/ (the folder that contains 3.1_compute-core, 3.2_dram, ...)
# What it does:
#  - clones KiCad reference repos into ./_ref_kicad/repos
#  - creates refs/{projects,sheets,footprints} inside each of your 3.x folders
#  - symlinks (or copies) whole projects into the relevant section(s)
#  - copies selected standalone .kicad_sch pages + footprints into the right places

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing dependency: $1"; exit 1; }
}

require_cmd git
require_cmd curl

# ----------------------------
# Sanity check: we are in pcb/
# ----------------------------
EXPECTED_DIRS=(
  "3.1_compute-core"
  "3.2_dram"
  "3.3_emmc-storage"
  "3.4_microsd-recovery"
  "3.5_ethernet"
  "3.6_usb"
  "3.7_wifi"
  "3.8_ui-spi-buttons"
  "3.9_debug-test-instrumentation"
)

for d in "${EXPECTED_DIRS[@]}"; do
  [[ -d "$d" ]] || { echo "ERROR: expected to be run from pcb/ (missing ./$d)"; exit 1; }
done

ROOT="$(pwd)"
REFROOT="$ROOT/_ref_kicad"
REPOS="$REFROOT/repos"
mkdir -p "$REPOS"

clone_repo() {
  local name="$1"
  local url="$2"
  local branch="${3:-}"
  local dest="$REPOS/$name"

  if [[ -d "$dest/.git" ]]; then
    echo "==> updating $name"
    git -C "$dest" fetch --all --tags --prune
    git -C "$dest" pull --ff-only || true
    return 0
  fi

  echo "==> cloning $name"
  if [[ -n "$branch" ]]; then
    git clone --depth 1 --branch "$branch" "$url" "$dest"
  else
    git clone --depth 1 "$url" "$dest"
  fi
}

mkdir_area_refs() {
  local area="$1"
  mkdir -p "$ROOT/$area/refs/projects" \
           "$ROOT/$area/refs/sheets" \
           "$ROOT/$area/refs/footprints" \
           "$ROOT/$area/refs/pdfs" \
           "$ROOT/$area/refs/appnotes"
}

link_or_copy_repo_into_area() {
  local repo_name="$1"
  local area="$2"
  local src="$REPOS/$repo_name"
  local dst="$ROOT/$area/refs/projects/$repo_name"

  [[ -d "$src" ]] || { echo "WARN: missing repo dir (not cloned?): $repo_name"; return 0; }
  [[ -e "$dst" ]] && return 0

  if ln -s "$src" "$dst" 2>/dev/null; then
    return 0
  fi

  echo "WARN: symlink failed, copying repo into area: $area (this may be larger)"
  cp -a "$src" "$dst"
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -n "$src" "$dst"   # do not overwrite user edits
  else
    echo "WARN: expected file not found: $src"
  fi
}

copy_tree_if_exists() {
  local src_dir="$1"
  local dst_dir="$2"
  if [[ -d "$src_dir" ]]; then
    mkdir -p "$dst_dir"
    cp -an "$src_dir/." "$dst_dir/"
  else
    echo "WARN: expected dir not found: $src_dir"
  fi
}

# ----------------------------
# Clone KiCad reference repos
# ----------------------------

# H616 baseline (KiCad project) :contentReference[oaicite:1]{index=1}
clone_repo "Allwinner_H616_Devboard" "https://github.com/Kononenko-K/Allwinner_H616_Devboard.git"

# DDR3 schematic pages (various KiCad projects)
clone_repo "STM32MP1_SOM" "https://github.com/abhvajpayee/STM32MP1_SOM.git"
clone_repo "reform-kintex-som" "https://github.com/kitspace-forks/reform-kintex-som.git"
clone_repo "Prism-PCB" "https://github.com/Y10-Labs/Prism-PCB.git"
clone_repo "Zynq7000_AD9238" "https://github.com/zzbaw130/Zynq7000_AD9238.git"

# eMMC adapters (KiCad projects) :contentReference[oaicite:2]{index=2}
clone_repo "emmc-wfbga153-microsd" "https://github.com/voltlog/emmc-wfbga153-microsd.git"
clone_repo "eMMC-microSD" "https://github.com/TobleMiner/eMMC-microSD.git"

# Ethernet references (KiCad) :contentReference[oaicite:3]{index=3}
clone_repo "ethernet-pmod" "https://github.com/swetland/ethernet-pmod.git"
clone_repo "kicad-PMOD-LAN8720" "https://github.com/chmousset/kicad-PMOD-LAN8720.git"
clone_repo "KiCAD-Gigabit-Ethernet-Interface-Project" "https://github.com/Saie12/KiCAD-Gigabit-Ethernet-Interface-Project.git"

# USB hub references (KiCad)
clone_repo "USB2514B_USB_Hub" "https://github.com/TheStelmach/USB2514B_USB_Hub.git"
clone_repo "UltraCore-Active-USB-Hub" "https://github.com/ItamarDekel1/UltraCore-Active-USB-Hub.git"

# USB-C / connector references (KiCad)
clone_repo "uC-Breakout-New" "https://github.com/NadavShanun-design/uC-Breakout-New.git"
clone_repo "USBCRP2040Min" "https://github.com/Anathae/USBCRP2040Min.git"

# WiFi module breakout (KiCad)
clone_repo "AP6212_Breakout" "https://github.com/berryelectronics/AP6212_Breakout.git"

# Debug / footprints: Tag-Connect (KiCad lib) :contentReference[oaicite:4]{index=4}
clone_repo "kicad-tag-connect" "https://github.com/nawotech/kicad-tag-connect.git"

# Grab-bag of reusable KiCad sub-sheets (often includes USB/UART/etc.)
clone_repo "kicad_subs" "https://github.com/williamweatherholtz/kicad_subs.git"

# UI footprint help (ST7789 module .kicad_mod) :contentReference[oaicite:5]{index=5}
clone_repo "st7789-320-240" "https://github.com/ccadic/st7789-320-240.git"

# UART bridge board (KiCad project)
clone_repo "USB-UART-CH340C-converter-board-hardware-design" \
  "https://github.com/SolderedElectronics/USB-UART-CH340C-converter-board-hardware-design.git"

# Optional: another full open SBC in KiCad (handy “production-ish” patterns) :contentReference[oaicite:6]{index=6}
clone_repo "nanoberry" "https://github.com/EnzoRF/nanoberry.git"

# ----------------------------
# Create refs folders in YOUR actual dirs
# ----------------------------
for area in "${EXPECTED_DIRS[@]}"; do
  mkdir_area_refs "$area"
done

# ----------------------------
# Link/copy whole projects into each section
# ----------------------------

# 3.1 Compute Core: SoC baseline + general SBC patterns
link_or_copy_repo_into_area "Allwinner_H616_Devboard" "3.1_compute-core"
link_or_copy_repo_into_area "nanoberry" "3.1_compute-core"

# 3.2 DRAM: DDR3 schematic pages + examples
for r in "Allwinner_H616_Devboard" "STM32MP1_SOM" "reform-kintex-som" "Prism-PCB" "Zynq7000_AD9238"; do
  link_or_copy_repo_into_area "$r" "3.2_dram"
done

# 3.3 eMMC: adapters + footprints
for r in "emmc-wfbga153-microsd" "eMMC-microSD"; do
  link_or_copy_repo_into_area "$r" "3.3_emmc-storage"
done

# 3.4 microSD recovery: adapters + microSD sheets (from kicad_subs if present)
for r in "emmc-wfbga153-microsd" "kicad_subs"; do
  link_or_copy_repo_into_area "$r" "3.4_microsd-recovery"
done

# 3.5 Ethernet: RMII + (optional) GigE reference
for r in "ethernet-pmod" "kicad-PMOD-LAN8720" "KiCAD-Gigabit-Ethernet-Interface-Project" "nanoberry"; do
  link_or_copy_repo_into_area "$r" "3.5_ethernet"
done

# 3.6 USB: hub + usb-c refs + reusable sheets
for r in "USB2514B_USB_Hub" "UltraCore-Active-USB-Hub" "uC-Breakout-New" "USBCRP2040Min" "kicad_subs" "nanoberry"; do
  link_or_copy_repo_into_area "$r" "3.6_usb"
done

# 3.7 WiFi: module wiring refs
for r in "AP6212_Breakout"; do
  link_or_copy_repo_into_area "$r" "3.7_wifi"
done

# 3.8 UI: SPI display footprints
for r in "st7789-320-240"; do
  link_or_copy_repo_into_area "$r" "3.8_ui-spi-buttons"
done

# 3.9 Debug / test: Tag-Connect + UART bridge + reusable subsheets
for r in "kicad-tag-connect" "USB-UART-CH340C-converter-board-hardware-design" "kicad_subs"; do
  link_or_copy_repo_into_area "$r" "3.9_debug-test-instrumentation"
done

# ----------------------------
# Copy selected schematic “pages” into refs/sheets
# ----------------------------

# DDR3 / DRAM pages -> 3.2_dram
copy_if_exists "$REPOS/STM32MP1_SOM/DDR3_RAM.kicad_sch" \
               "$ROOT/3.2_dram/refs/sheets/DDR3_RAM.kicad_sch"
copy_if_exists "$REPOS/reform-kintex-som/RAM.kicad_sch" \
               "$ROOT/3.2_dram/refs/sheets/RAM.kicad_sch"
copy_if_exists "$REPOS/Prism-PCB/DDR3.kicad_sch" \
               "$ROOT/3.2_dram/refs/sheets/Prism_DDR3.kicad_sch"
copy_if_exists "$REPOS/Prism-PCB/DDR.kicad_sch" \
               "$ROOT/3.2_dram/refs/sheets/Prism_DDR.kicad_sch"
copy_if_exists "$REPOS/Zynq7000_AD9238/ZYNQ_DDR3.kicad_sch" \
               "$ROOT/3.2_dram/refs/sheets/ZYNQ_DDR3.kicad_sch"

# microSD reusable sheet -> 3.4_microsd-recovery (if present in kicad_subs)
copy_if_exists "$REPOS/kicad_subs/microSD.kicad_sch" \
               "$ROOT/3.4_microsd-recovery/refs/sheets/microSD.kicad_sch"

# USB reusable sheets -> 3.6_usb (if present)
copy_if_exists "$REPOS/kicad_subs/usb_otg_tvs.kicad_sch" \
               "$ROOT/3.6_usb/refs/sheets/usb_otg_tvs.kicad_sch"
copy_if_exists "$REPOS/kicad_subs/usb_fs.kicad_sch" \
               "$ROOT/3.6_usb/refs/sheets/usb_fs.kicad_sch"

# UART bridge reusable sheet -> 3.9_debug-test-instrumentation (if present)
copy_if_exists "$REPOS/kicad_subs/cp2102.kicad_sch" \
               "$ROOT/3.9_debug-test-instrumentation/refs/sheets/cp2102.kicad_sch"

# ----------------------------
# Copy extra footprints into the most relevant sections
# ----------------------------

# Tag-Connect.pretty -> debug/test
copy_tree_if_exists "$REPOS/kicad-tag-connect/Tag-Connect.pretty" \
                    "$ROOT/3.9_debug-test-instrumentation/refs/footprints/Tag-Connect.pretty"
copy_if_exists "$REPOS/kicad-tag-connect/Tag-Connect.lib" \
               "$ROOT/3.9_debug-test-instrumentation/refs/footprints/Tag-Connect.lib"

# ST7789 module footprints -> UI folder
for f in "$REPOS/st7789-320-240/"*.kicad_mod; do
  [[ -f "$f" ]] || continue
  cp -n "$f" "$ROOT/3.8_ui-spi-buttons/refs/footprints/$(basename "$f")"
done

echo
echo "Done."
echo "Each 3.x folder now has:"
echo "  refs/projects   -> full KiCad projects (symlinked or copied)"
echo "  refs/sheets     -> individual .kicad_sch pages you can import"
echo "  refs/footprints -> extra .kicad_mod/.pretty + libs where relevant"