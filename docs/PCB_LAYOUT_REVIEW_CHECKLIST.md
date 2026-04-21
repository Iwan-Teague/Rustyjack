# PCB Layout Review Checklist

This document is the board-file layout pass for the current Rustyjack H616 PCB project under:

- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`

It answers one question: what still needs to be placed, routed, or reverified on the actual PCB so the board can become a reliable, bootable, software-coherent product.

## Source Hierarchy

When this document says "must", that requirement comes from one of these categories:

1. Official KiCad documentation
2. Official silicon vendor datasheet, checklist, layout guide, or package/mechanical spec
3. Public mirror of vendor-authored documentation when the official host is not available
4. Direct evidence from the current Rustyjack KiCad files

Primary sources used for this layout pass:

- [KiCad 9 Schematic Editor](https://docs.kicad.org/9.0/en/eeschema/eeschema.html)
- [KiCad Introduction](https://docs.kicad.org/9.0/en/introduction/introduction.html)
- [LAN8720A QFN Schematic Checklist](https://ww1.microchip.com/downloads/en/DeviceDoc/LAN8720A%20QFN%20Rev%20D%20Schematic%20Checklist.pdf)
- [AM62Px eMMC Board Design and Simulation Guidelines](https://www.ti.com/lit/pdf/spradp5)
- [CP2102N Data Sheet](https://www.silabs.com/documents/public/data-sheets/cp2102n-datasheet.pdf)
- [AW859A SPEC V1.4](https://linux-sunxi.org/images/1/1f/AW859A_SPEC_V1.4.pdf)
- [KIOXIA e-MMC for Consumer & Industrial](https://americas.kioxia.com/en-us/business/memory/mlc-nand/emmc.html)

## What The Current PCB File Already Shows

The current board file already contains the core implementation references for:

- `U1` H616 SoC
- `U2` DDR3
- `U3` PMIC
- `U4` CP2102N USB-UART bridge
- `J1` microSD
- `J2` USB-C
- `J3` USB-C
- `D3` USB ESD
- `D4` Schottky diode
- `Y1` crystal

That means the core bring-up hardware is present on the PCB and should be reviewed for routing quality, but it is not the main blocker in the current pass.

## What Is Still Missing From The PCB

The current board file does not contain placed footprints for:

- AW859A Wi-Fi module
- LAN8720A Ethernet PHY
- RJ45 / magnetics block
- eMMC storage device

The schematic has already outgrown the PCB layout. The next hard requirement is a schematic-to-PCB sync so these missing subsystems become physical footprints before any final routing review.

## KiCad CLI Validation Snapshot

KiCad 9.0.4 CLI was run after restoring the default footprint and symbol library tables into the local KiCad preferences so standard libraries resolved correctly.

Current report totals:

- DRC: 162 violations, 41 errors, 0 unconnected items
- ERC: 785 violations, 205 errors

Material DRC errors:

- `DDR3_OTHER` clearance violation: 0.0992 mm actual versus 0.1000 mm required, between `/DRAM/SCKE0` and `GND`
- `INTER_CLASS_2` skew violation: actual skew -4.6051 mm versus 4.4450 mm max, from `/DRAM/SA0`
- Courtyard overlap: `R15` and `J1`
- Keepout violation: via at approximately `(144.93 mm, 67.73 mm)`

Material ERC errors:

- `/DRAM/` still reports `pin_not_driven` errors on H616 address pins
- `/WIFI/` still reports `pin_not_connected` and `pin_not_driven` errors on `U_WIFI1`, including `XTAL_IN`, `XTAL_OUT`, and `VBAT`
- `/ETHERNET/` still reports `pin_to_pin` and `pin_not_connected` errors around the imported PMOD-style reference material, so the sheet is not production-clean yet

The remaining warnings are mostly library-drift and schematic-hygiene issues, but the errors above are real blockers for a production PCB.

## Subsystem Status Matrix

Legend:

- `Complete`: present and synchronized into the current PCB context
- `Partial`: present but still needs validation or cleanup
- `Schematic-only`: defined in schematic, but not yet represented as a placed PCB footprint
- `Blocked`: current KiCad evidence shows a concrete defect or missing prerequisite

| Subsystem | Schematic | PCB status | Validation state | Software-ready | Notes |
| --- | --- | --- | --- | --- | --- |
| H616 core | Complete | Complete | Partial | Partial | Core hardware exists on the board, but DDR and schematic hygiene still block signoff. |
| DDR3 | Complete | Complete | Blocked | No | DRC clearance/skew errors remain. |
| PMIC / power tree | Complete | Complete | Partial | Partial | Needs final rail, decoupling, and power-sequence review. |
| microSD boot | Complete | Complete | Partial | Partial | Present, but should be rechecked after the next PCB sync. |
| USB-C power / USB-UART | Complete | Complete | Partial | Partial | Present, but should be reverified after the next PCB sync. |
| eMMC storage | Complete | Schematic-only | Blocked | No | The schematic has the part; the PCB still needs the footprint and placement. |
| Ethernet | Complete | Schematic-only | Blocked | No | The schematic has the part; the PCB still needs the footprint and the imported PMOD remnants removed. |
| Wi-Fi | Complete | Schematic-only | Blocked | No | AW859A is specified in schematic, but the PCB still needs the footprint, placement, and antenna keepout. |

These statuses come from the current board file, the schematic sheets, and the KiCad CLI results above. When a row is closed in the register below, update this matrix at the same time.

## Design-Correction Register

Treat the rows below in priority order. Do not treat later rows as safe until the earlier rows are closed and the board passes DRC/ERC again.

| ID | Priority | Subsystem | Evidence | Required correction | Verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| RC-001 | P1 | DDR3 | DRC `DDR3_OTHER` clearance violation: 0.0992 mm actual versus 0.1000 mm required, between `/DRAM/SCKE0` and `GND`. | Increase spacing or reroute the offending segment so the clearance rule is met everywhere. | Re-run KiCad DRC and confirm zero clearance errors. | Open |
| RC-002 | P1 | DDR3 | DRC `INTER_CLASS_2` skew violation: actual skew -4.6051 mm versus 4.4450 mm max, from `/DRAM/SA0`. | Rebalance the routed lengths or adjust class membership so the skew rule is satisfied. | Re-run KiCad DRC and confirm zero skew errors. | Open |
| RC-003 | P1 | Wi-Fi | ERC `/WIFI/` still shows `pin_not_connected` and `pin_not_driven` errors on `U_WIFI1`, including `XTAL_IN`, `XTAL_OUT`, and `VBAT`; the PCB still lacks the AW859A footprint. | Finish the Wi-Fi connectivity, sync the schematic footprint into the PCB, and place the module with its antenna keepout from the vendor spec. | ERC clean on `/WIFI/` and the PCB contains the AW859A footprint and keepout. | Open |
| RC-004 | P1 | Ethernet | ERC `/ETHERNET/` still shows PMOD-style reference artifacts and `pin_to_pin` / `pin_not_connected` errors; the PCB still lacks the production LAN8720A/RJ45 placement. | Remove imported PMOD remnants, finish the production Ethernet sheet, and sync the LAN8720A/magnetics/RJ45 cluster onto the board. | ERC clean on `/ETHERNET/` and the board contains the intended Ethernet cluster. | Open |
| RC-005 | P1 | eMMC | The schematic has the THGBMNG5D1LBAIL symbol and footprint, but the PCB still does not contain the eMMC footprint. | Sync the schematic change into the PCB and place the eMMC device close to the H616 with a point-to-point routing plan. | PCB contains the eMMC footprint and the bus passes DRC after routing. | Open |
| RC-006 | P2 | Mechanical placement | DRC courtyard overlap between `R15` and `J1`. | Move one of the parts or revise the footprint courtyard only if the mechanical spec supports it. | Re-run DRC and confirm no courtyard overlap. | Open |
| RC-007 | P2 | Keepout / routing | DRC keepout violation from a free via at approximately `(144.93 mm, 67.73 mm)`. | Remove or relocate the via so the keepout is respected. | Re-run DRC and confirm no keepout violations. | Open |

## Layout Tasks That Still Need To Be Done

Treat the P1 register entries above as the first blocking work.

### 1. Sync the schematic to the board file

- Bring the updated `U_WIFI1`, eMMC, LAN8720A, and RJ45/magnetics footprints into the PCB.
- Use KiCad's schematic-to-PCB update workflow rather than treating the board file as authoritative when the schematic has changed.
- Re-run netclass assignment checks after the sync.

### 2. Place the AW859A module

- Place the AW859A module at the board edge so the antenna section has a clean physical launch.
- Use the module's spec drawing for the actual land pattern and placement.
- Keep copper, vias, traces, and planes out of the antenna keepout area.
- Keep the SDIO and control nets short, direct, and on a continuous reference plane.
- Do not rely on a generic RF module footprint or a copied reference board unless it matches the AW859A specification exactly.

### 3. Place the Ethernet PHY, magnetics, and RJ45 cluster

- Place the LAN8720A as a compact cluster with the magnetics and RJ45 at the board edge.
- Keep the RMII nets short and explicit.
- Keep the PHY power and decoupling parts close to the chip.
- Use the LAN8720A checklist values for the transmit and receive terminations, center-tap connections, and VDDCR bypassing.
- Ensure the shield and chassis strategy is intentional, not accidental.

### 4. Place the eMMC device

- Place the WFBGA153 eMMC package close to the H616 so the MMC routing stays short.
- Route the eMMC bus as a point-to-point interface over a solid reference plane.
- Avoid stubs.
- Minimize layer transitions.
- Keep the return current path continuous across any via transition.
- Ensure the final routing can support the selected eMMC timing budget without plane cuts in the routing region.

### 5. Reverify the already-placed core hardware

- Review DDR3 routing against the current netclass and DRC rules.
- Review USB-C and USB-UART routing for pair symmetry, ESD placement, and connector-to-protection distance.
- Review the power tree, test points, and rail placement around the PMIC and SoC.
- Confirm the current board outline and edge connector geometry still match the intended mechanical assembly.

## Exact Routing/Placement Checks By Subsystem

### Wi-Fi

- AW859A is a 44-pin module with a 12 x 12 mm body in the vendor spec.
- The module needs a real footprint, not a schematic-only symbol.
- The layout needs an antenna keepout that is derived from the module spec.
- The PCB should not place copper or vias under the antenna region.
- The Wi-Fi SDIO nets should stay on the same sheet-path naming used by the project netclass rules.

### Ethernet

- The LAN8720A transmit and receive lines need the 49.9 ohm terminations and center-tap handling shown in the Microchip checklist.
- The analog supply needs local decoupling and a ferrite-bead feed from 3.3 V.
- The RJ45 shield / chassis connection should be explicit.
- RMII placement should avoid route crowding and accidental plane splits.

### eMMC

- The selected KIOXIA family is a 153-ball BGA package in the 11.5 x 13.0 mm class.
- The bus should be routed as a tightly controlled point-to-point interface.
- All eMMC signals need a solid ground reference plane.
- Do not allow stubs or unnecessary doglegs.
- Keep the power delivery and decoupling local to the device and the SoC.

### USB-UART

- CP2102N is a USB 2.0 full-speed bridge with an integrated transceiver and oscillator, so the layout should not invent extra external USB complexity.
- Verify the USB pair, ESD placement, and connector entry path on the PCB.
- Confirm the bridge footprint on the PCB matches the selected package variant.

## Acceptance Criteria For This Layout Pass

The layout pass is only complete when all of these are true:

- The schematic has been synchronized into the board file.
- AW859A, LAN8720A, RJ45/magnetics, and eMMC are physically placed in the PCB.
- The Wi-Fi antenna keepout exists on the PCB and matches the module spec.
- The eMMC and Ethernet routing constraints are reflected in the board layout.
- The existing core board hardware still passes ERC/DRC after the update.
- The board file no longer relies on schematic-only intent for any production subsystem.

## What To Review Next

1. Run schematic-to-PCB synchronization.
2. Place the missing subsystems.
3. Re-run DRC and netclass review.
4. Then perform a routing-only review of the already-placed H616 core, DDR3, USB, and power sections.
