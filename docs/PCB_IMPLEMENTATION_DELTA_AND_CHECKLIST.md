# PCB Implementation Delta And Checklist

## Purpose

This document is the execution bridge between the PCB review and the actual KiCad files under:

- `pcb/actual pcb design/rustyjack-h616/`

It answers one question: what must change in the current KiCad project so the board becomes a reliable, bootable, and software-coherent H616 product.

The intended end state is a board that can:

- power up cleanly from USB-C
- boot from microSD and eMMC
- run DDR3 reliably
- expose Ethernet through LAN8720A + RJ45
- expose on-board Wi-Fi through AW859A
- expose USB host ports and USB-UART debug
- present stable hardware interfaces to Linux and the Rust runtime

If a future edit changes the product scope, that change must be made explicitly in the docs first. Silent scope drift is not acceptable.

## Relationship To Other Docs

Use these documents together:

- [PCB Review And Remediation Plan](PCB_REVIEW_AND_REMEDIATION_PLAN.md)
- [PCB Layout Review Checklist](PCB_LAYOUT_REVIEW_CHECKLIST.md)
- [KiCad v9.0.4 Guide for the H616 Watchdog PCB Mapping Orange Pi Zero2 Reference Subsystems into Deliverables](../pcb/kicad-h616-deliverables-guide.md)
- [Orange Pi Zero2 H616 Reference Extraction](../pcb/orangepi-zero2-h616-reference-extraction.md)
- [Orange Pi Zero2 H616 Reference Map](../pcb/orangepi-zero2-h616-reference-map.md)
- [KeyCAD / KiCad Architecture Document - H616 Rustyjack Prototype PCB (v0)](../pcb/rustyjack-h616-pcb-architecture-v0.md)

This delta document is current-board specific. If the older deliverables guide conflicts with the current KiCad files on Wi-Fi scope, use this document and the review plan as the source of truth for the current board revision.

The linked layout checklist now carries the subsystem status matrix and design-correction register that should drive the PCB repair sequence.

## Source Hierarchy

When this document says "must", the requirement comes from one of these categories:

1. Official KiCad documentation
2. Official silicon vendor datasheet, checklist, layout guide, or package/mechanical spec
3. Public mirror of vendor-authored documentation when the official host is not available
4. Direct evidence from the current Rustyjack KiCad files
5. Project reference docs already checked into the repo

Primary sources for the implementation plan:

- [KiCad 8 Schematic Editor](https://docs.kicad.org/8.0/en/eeschema/eeschema.html)
- [KiCad PCB advanced topics](https://docs.kicad.org/master/en/pcbnew/pcbnew_advanced.html)
- [USB3280 Hardware Design Checklist](https://ww1.microchip.com/downloads/aemDocuments/documents/UNG/ProductDocuments/DesignChecklist/USB3280-HW-Design-Checklist-00004460.pdf)
- [LAN8720A QFN Schematic Checklist](https://ww1.microchip.com/downloads/en/DeviceDoc/LAN8720A%20QFN%20Rev%20D%20Schematic%20Checklist.pdf)
- [AN-1469 PHYTER Design & Layout Guide](https://www.ti.com/lit/an/snla079d/snla079d.pdf)
- [DP83848C datasheet](https://www.ti.com/lit/ds/symlink/dp83848c.pdf)
- [AM62Px eMMC Board Design and Simulation Guidelines](https://www.ti.com/lit/pdf/spradp5)
- [CP2102N Data Sheet](https://www.silabs.com/documents/public/data-sheets/cp2102n-datasheet.pdf)
- [AW859A SPEC V1.4](https://linux-sunxi.org/images/1/1f/AW859A_SPEC_V1.4.pdf)

## Current Product Target

The target board is not a generic H616 demo board. The target is a coherent embedded Linux platform where the following modules all work together:

- H616 SoC
- DDR3 memory
- eMMC primary storage
- microSD recovery storage
- USB-C power input
- USB-A host ports
- Ethernet via LAN8720A and RJ45/magnetics
- on-board Wi-Fi via AW859A
- USB-UART debug bridge via CP2102N

The software side must be able to rely on the hardware side being stable, documented, and reproducible. The board should not require ad hoc hacks to discover its own interfaces.

## Delta Summary

### What is already present but not yet production-grade

- H616 core placement exists, but it still needs final symbol-footprint-ball-map verification and a clean bring-up contract.
- DDR rules exist, but at least one pattern is malformed and the class ordering is risky.
- USB-C / USB-UART hardware exists, but the CP2102N footprint and USB2 routing discipline still need explicit verification.

### What is present in schematic but not yet true on the PCB

- Ethernet is defined in schematic, but it still needs verified board placement, keepout, and routing.
- Wi-Fi is defined in schematic, but the AW859A footprint is blank and the module has no verified board keepout.
- eMMC storage is still carrying placeholder / imported-adapter DNA and needs to be reclaimed as a real Rustyjack subsystem.

### What must stop being ambiguous immediately

- Root schematic scope versus actual PCB scope
- Footprint ownership for Wi-Fi and storage
- Netclass ordering and full sheet-path matching
- Whether a subsystem is production hardware or reference-only

## File-By-File Checklist

### `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_sch`

- [ ] Keep only production sheets in the root schematic.
- [ ] Mark any reference-only material explicitly if it remains in the file.
- [ ] Ensure the root schematic title and sheet list match the actual product scope.
- [ ] Remove any wording that implies a subsystem is on-board if it is not physically implemented.
- [ ] Verify that every `on_board yes` symbol is intended to ship on the board.

### `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`

- [ ] Confirm the board outline, connector edges, and keepouts match the actual assembly plan.
- [ ] Confirm H616, DDR3, eMMC, Ethernet, Wi-Fi, and USB are physically placed in the intended zones.
- [ ] Confirm there are no orphaned footprints for subsystems that are only theoretical.
- [ ] Confirm the Wi-Fi module, RJ45 area, USB connectors, and storage devices obey their mechanical clearances.
- [ ] Confirm testpoints exist for power rails, boot straps, and early bring-up measurements.

### `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pro`

- [ ] Fix the malformed DDR high-byte netclass pattern.
- [ ] Fix the RMII pattern so it matches the actual full sheet-path names.
- [ ] Put exact critical-net patterns before broader fallback patterns.
- [ ] Keep only netclasses that correspond to real routed hardware.
- [ ] Re-run net inspector checks after every netclass change.

### `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_dru`

- [ ] Encode only rules that correspond to the actual production board.
- [ ] Add or keep custom skew rules only where the nets truly exist.
- [ ] Check that rule priorities and class ordering in KiCad match the intended hierarchy.
- [ ] Remove placeholder constraints that protect absent hardware.

### `pcb/actual pcb design/rustyjack-h616/dram.kicad_sch`

- [ ] Make DDR lane naming explicit and stable.
- [ ] Ensure the byte-lane naming supports clear netclass assignment.
- [ ] Avoid ambiguous regex-style naming that can be misread by KiCad patterns.
- [ ] Verify the chosen DDR topology matches the actual H616 board layout, not just the idea of one.

### `pcb/actual pcb design/rustyjack-h616/power.kicad_sch`

- [ ] Verify USB-C is a true 5 V sink with explicit CC pull-down resistors.
- [ ] Verify rail sequencing, power-good behavior, and bring-up testpoints.
- [ ] Verify the board can be safely current-limited on first power.
- [ ] Ensure no rail is only documented in text but absent in the actual power tree.

### `pcb/actual pcb design/rustyjack-h616/usb_uart.kicad_sch`

- [ ] Verify the CP2102N symbol uses the correct footprint variant.
- [ ] Verify the USB2 differential pair is routed and constrained as a real pair.
- [ ] Verify ESD placement is physically close to the connector entry.
- [ ] Verify VBUS switching and connector current handling are correct.
- [ ] Verify the board can enumerate the bridge consistently under Linux.

### `pcb/actual pcb design/rustyjack-h616/sheets/storage_emmc.kicad_sch`

- [ ] Remove all residual placeholder / adapter naming.
- [ ] Decide the production eMMC part number and capture it in the design docs.
- [ ] Verify the symbol pinout against that exact part.
- [ ] Verify the footprint against that exact part.
- [ ] Route the eMMC adjacent to a continuous reference plane with no stubs or plane cuts.

### `pcb/actual pcb design/rustyjack-h616/sheets/ethernet_lan8720.kicad_sch`

- [ ] Verify the LAN8720A symbol, footprint, and pinout are aligned.
- [ ] Place the PHY, magnetics, and RJ45 in the actual board edge geometry.
- [ ] Encode the magnetics / RJ45 keepout as a real mechanical and routing constraint.
- [ ] Keep the RMII nets stable and explicit.
- [ ] Treat shield and chassis strategy as a design decision, not an accident.

### `pcb/actual pcb design/rustyjack-h616/sheets/wifi_aw859a.kicad_sch`

- [ ] Assign a real footprint to `U_WIFI1`.
- [ ] Base that footprint on the AW859A specification, not a generic module example.
- [ ] Verify the antenna keepout, board-edge placement, and copper exclusion rules.
- [ ] Ensure the SDIO nets are named and classed correctly.
- [ ] Verify the Wi-Fi module is physically present on the PCB and not just in schematic.

### `pcb/actual pcb design/rustyjack-h616/io1.kicad_sch` and `pcb/actual pcb design/rustyjack-h616/io2.kicad_sch`

- [ ] Keep external interface names stable and intentional.
- [ ] Avoid hidden naming drift that breaks pattern-based netclass assignment.
- [ ] Verify the Ethernet management nets and any UI/button nets are named for software clarity.
- [ ] Keep these sheets aligned with the actual PCB module placements.

## Software Bring-Up Contract

The board is only finished when Linux and the Rust runtime can use it without special-casing the PCB revision every time.

Minimum contract:

- UART console must come up first and remain accessible for recovery.
- microSD boot must work before eMMC is treated as trustworthy.
- eMMC must enumerate consistently after the storage path is stable.
- Ethernet must bind and obtain link without relying on manual board-specific pokes.
- On-board Wi-Fi must bind through its SDIO path and appear as a normal Linux network interface.
- USB host ports must enumerate external peripherals without brownouts.
- The hardware naming in the docs must match what software actually sees.

If a kernel driver, device tree, or service configuration needs to assume a board-specific label, that label must be documented here and in the matching software docs before the hardware revision is called complete.

## Verification Evidence Required

Before the board revision is considered ready, collect all of the following:

- ERC report with no unresolved electrical errors
- DRC report with no unresolved board errors
- KiCad net inspector evidence showing the right netclasses on the right nets
- Footprint verification evidence for AW859A, LAN8720A, and CP2102N
- Photo or render evidence that the Wi-Fi, Ethernet, power, and USB parts are placed in the intended zones
- A bring-up log showing at least:
  - power rails measured
  - UART boot log seen
  - microSD boot path verified
  - eMMC enumeration verified
  - Ethernet link verified
  - Wi-Fi interface verified

## Execution Order

1. Fix the root schematic truth model.
2. Fix netclass ordering and naming.
3. Lock the H616 core footprint and power bring-up path.
4. Rebuild the AW859A footprint from the spec and place the module.
5. Reclaim the eMMC sheet as a real production design.
6. Place and verify Ethernet hardware.
7. Verify USB-UART and USB host behavior.
8. Re-run ERC, DRC, and net inspector checks.
9. Update the software bring-up docs with the final interface contract.

## Related Output Files

As the design matures, the board should generate and commit:

- updated schematic PDF
- updated PCB file
- updated project file
- updated DRC rules
- updated footprint and symbol libraries if needed
- current bring-up notes and validation evidence

The purpose of this checklist is not to make the repo bigger. It is to make the board revision defensible, repeatable, and honest.
