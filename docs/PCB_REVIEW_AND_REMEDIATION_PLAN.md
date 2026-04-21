# PCB Review And Remediation Plan

## Purpose

This document is the authoritative review and remediation plan for the KiCad hardware design under:

- `pcb/actual pcb design/rustyjack-h616/`

This document covers **PCB-related project elements only**. It does not review software, firmware, installers, or runtime behavior.

The goal is not to produce a vague list of "best practices." The goal is to define:

- what is wrong today
- why it is wrong
- which files must change
- exactly how those files must change
- what proof is required before we call the item complete

If a future PCB change conflicts with this document, the burden is on the change author to prove the new approach is better and still compliant with the cited sources.

Implementation bridge: [PCB Implementation Delta And Checklist](PCB_IMPLEMENTATION_DELTA_AND_CHECKLIST.md).
Board-file layout follow-up: [PCB Layout Review Checklist](PCB_LAYOUT_REVIEW_CHECKLIST.md).

## Scope Reviewed

The following files were reviewed:

- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pro`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_dru`
- `pcb/actual pcb design/rustyjack-h616/dram.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/power.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/io1.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/io2.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/usb_uart.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/sheets/ethernet_lan8720.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/sheets/storage_emmc.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/sheets/wifi_aw859a.kicad_sch`

## Source Hierarchy

When this document says "must", that requirement comes from one of these categories:

1. Official KiCad documentation
2. Official silicon vendor datasheet, checklist, layout guide, or package/mechanical spec
3. Public mirror of vendor-authored documentation when the official host is not available
4. Direct evidence from the Rustyjack KiCad files
5. Project reference docs already checked into the repo

Primary sources used:

- KiCad schematic/netclass documentation: [KiCad 8 Schematic Editor](https://docs.kicad.org/8.0/en/eeschema/eeschema.html)
- KiCad custom rules documentation: [KiCad PCB advanced topics](https://docs.kicad.org/master/en/pcbnew/pcbnew_advanced.html)
- Microchip USB layout guidance: [USB3280 Hardware Design Checklist](https://ww1.microchip.com/downloads/aemDocuments/documents/UNG/ProductDocuments/DesignChecklist/USB3280-HW-Design-Checklist-00004460.pdf)
- Microchip LAN8720A checklist: [LAN8720A QFN Schematic Checklist](https://ww1.microchip.com/downloads/en/DeviceDoc/LAN8720A%20QFN%20Rev%20D%20Schematic%20Checklist.pdf)
- TI Ethernet PHY layout guidance: [AN-1469 PHYTER Design & Layout Guide](https://www.ti.com/lit/an/snla079d/snla079d.pdf)
- TI Ethernet PHY datasheet example guidance: [DP83848C datasheet](https://www.ti.com/lit/ds/symlink/dp83848c.pdf)
- TI eMMC layout guidance: [AM62Px eMMC Board Design and Simulation Guidelines](https://www.ti.com/lit/pdf/spradp5)
- Silicon Labs USB-UART bridge datasheet: [CP2102N Data Sheet](https://www.silabs.com/documents/public/data-sheets/cp2102n-datasheet.pdf)
- Public mirror of vendor-authored AW859A module specification: [AW859A SPEC V1.4](https://linux-sunxi.org/images/1/1f/AW859A_SPEC_V1.4.pdf)
- Project H616 references already checked into the repo: [Orange Pi Zero2 H616 reference extraction](../pcb/orangepi-zero2-h616-reference-extraction.md), [Orange Pi Zero2 H616 reference map](../pcb/orangepi-zero2-h616-reference-map.md), [KeyCAD / KiCad Architecture Document — H616 Rustyjack Prototype PCB (v0)](../pcb/rustyjack-h616-pcb-architecture-v0.md)

Important source note:

- The AW859A specification is the package and placement baseline for the Wi-Fi module footprint and keepout.
- Do not synthesize the RF footprint from a generic module guide or a third-party footprint library.
- If the official vendor-hosted PDF is unavailable, keep the public mirror in the trace chain but label it clearly as mirrored vendor-authored data, not a substitute for verification.

## Executive Conclusion

The current KiCad project is **not yet implementation-ready**.

What is true today:

- The laid-out PCB has a real 4-layer stackup and a non-trivial constraint setup.
- The implemented core board appears to contain the SoC, DDR, PMIC, microSD, USB-C/UART, crystal, passives, and test points.
- The root schematic also includes Ethernet, Wi-Fi, and eMMC storage sheets.
- Those additional subsystems are not fully reflected in the placed PCB.

That mismatch is the main structural problem.

In plain English: **the schematic scope, the layout scope, and the source traceability are out of sync**. Until the Wi-Fi footprint is grounded in the AW859A spec, the netclass rules are corrected, and the H616 reference docs are part of the review chain, this is not a reliable production PCB plan.

KiCad CLI validation, after restoring the default library tables, still reports 162 DRC violations with 41 errors and 785 ERC violations with 205 errors. The concrete blockers are the DDR clearance/skew issues, the Wi-Fi sheet's unconnected module pins, and the Ethernet sheet's remaining PMOD-style reference artifacts. See the layout checklist for the exact violations, plus the subsystem status matrix and design-correction register.

## Current-State Snapshot

### What The Root Schematic Claims Exists

The root schematic includes these sheets:

- `DRAM`
- `POWER`
- `IO1`
- `IO2`
- `USB-UART`
- `STORAGE`
- `WIFI`
- `ETHERNET`

### What The Physical Board Appears To Actually Implement

The board file shows instantiated references for at least:

- `U1` SoC
- `U2` DDR
- `U3` PMIC
- `U4` CP2102N
- `J1` microSD
- `J2` USB-C
- `J3` USB-C
- `D3` USB ESD
- `D4` Schottky
- `Y1` crystal

The board file does **not** show corresponding placed PCB footprints for:

- LAN8720A Ethernet PHY
- RJ45 connector / magnetics
- AW859A Wi-Fi module
- eMMC device from the storage sheet

That means the PCB is currently best understood as a **partial board implementation**, not a finished hardware platform matching the full project narrative.

## Non-Negotiable Rules Before Any PCB Changes

These rules are mandatory for future work:

1. Do not keep subsystems in the root schematic as `on_board yes` unless they are intentionally part of the product and either:
   - actually placed on the PCB, or
   - explicitly marked and documented as deferred/not fitted
2. Do not rely on fragile netclass pattern matching for high-speed or timing-sensitive nets.
3. Do not guess RF land patterns or antenna keepouts. Use the module vendor's package drawing or a public vendor-authored spec.
4. Do not treat imported reference material as production-ready just because it "works in another project."
5. Do not accept a high-speed interface as complete until net assignment, layout, and DRC/ERC evidence all agree.

## Issue 1: Schematic Scope And PCB Scope Are Not Synchronized

### Problem

The root schematic says the design includes `STORAGE`, `WIFI`, and `ETHERNET`, but the actual PCB does not show those subsystems placed and routed as finished hardware.

This is not just a cosmetic documentation problem. It causes real engineering ambiguity:

- reviewers cannot tell what the real hardware target is
- DRC/netclass rules may exist for nets that are not routed
- future contributors can easily break intent because the project scope is unclear
- BOM, assembly, and bring-up expectations become unreliable

### Why This Must Change

KiCad organizes PCB implementation around the relationship between the schematic, board, net names, footprints, and rules. If the schematic says a subsystem exists but the board does not implement it, the project stops being a trustworthy description of the product.

High-speed guidance from TI is explicit that routing guidance must be followed on the actual board implementation, not just held in theory. A not-yet-routed subsystem does not get credit for compliance.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`
- `pcb/actual pcb design/rustyjack-h616/sheets/storage_emmc.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/sheets/wifi_aw859a.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/sheets/ethernet_lan8720.kicad_sch`
- any footprint/library tables if new parts are added

### Exactly What Must Change

Choose one and only one of these paths for each deferred subsystem:

#### Path A: The Subsystem Is Real And Must Exist On The Board

If Ethernet, Wi-Fi, and/or eMMC are part of the real Rustyjack hardware target:

1. Keep the sheet in the root schematic.
2. Ensure every board-intended symbol has:
   - a real footprint
   - real power connections
   - real decoupling
   - real interface naming
3. Update the PCB from schematic.
4. Place and route the subsystem on the PCB.
5. Add or repair netclass assignments and layout rules for the actual routed nets.
6. Run ERC and DRC.

#### Path B: The Subsystem Is Not Yet In The Real Board

If the subsystem is not actually part of the current fabricated board:

1. Remove that sheet from the root production schematic, or move it to a clearly named non-production reference project.
2. Remove unused high-speed rule patterns associated only with the absent subsystem.
3. Update project documentation so the board description matches reality.

### Why Path B Is Sometimes Better

A smaller, truthful hardware project is better than a larger misleading one.

If the current board is intentionally a bring-up board, that is acceptable. What is not acceptable is a bring-up board presented as a completed full-platform PCB.

### What Correct Looks Like

This issue is complete only when **every subsystem in the root schematic is in one of these states**:

- present in schematic and physically implemented on the PCB
- intentionally removed from the production schematic
- clearly designated as reference-only and not part of the production hardware project

There must be no middle state where the root schematic implies production hardware that the board does not actually contain.

## Issue 2: The Wi-Fi Design Is Not Board-Ready

### Problem

The Wi-Fi sheet contains `U_WIFI1` with value `AW859A`, but its `Footprint` property is blank.

That means the Wi-Fi portion is not yet board-ready. A public mirror of the AW859A specification exists and should be treated as the source of truth for package geometry, pad spacing, antenna placement, and keepouts. Until that spec is used to define the footprint, there is no valid RF layout to review.

### Why This Must Change

RF modules are not generic logic ICs. The vendor's package drawing defines the only acceptable:

- land pattern
- courtyard
- keepout
- board-edge relationship
- antenna clearance
- copper exclusion under the antenna

Do not synthesize those rules from a generic RF-module guide or a third-party footprint library. Generic examples are useful only as a sanity check for the level of detail expected.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/sheets/wifi_aw859a.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`
- `pcb/actual pcb design/rustyjack-h616/fp-lib-table`
- the project footprint library if a custom footprint is required

### Exactly What Must Change

#### Step 1: Base The Footprint On The AW859A Specification

1. Use the AW859A SPEC V1.4 package/mechanical drawing as the footprint baseline.
2. Confirm all pad geometry, courtyard, and antenna clearance dimensions from that spec.
3. If the spec and any existing library footprint disagree, the spec wins.

#### Step 2: Create Or Import The Exact Footprint

1. Create a proper KiCad footprint in the project library if one is not already available.
2. Assign that footprint to `U_WIFI1`.
3. Verify every pad number exactly matches the symbol pinout.
4. Verify the footprint origin and orientation against the package drawing.

#### Step 3: Implement Placement And Keepouts From The Module Data

If the module uses an embedded antenna:

1. Place the module at the board edge unless the vendor says otherwise.
2. Create explicit keepout areas on the PCB for:
   - copper pour
   - traces
   - vias
   - components
3. Apply the keepout exactly to the dimensions required by the spec.

If the module uses an RF pin to an external antenna:

1. Route the RF feed as a controlled-impedance 50 ohm line.
2. Keep it short.
3. Avoid stubs and unnecessary vias.
4. Follow the vendor's matching network recommendation exactly.

#### Step 4: Implement The Digital Interface Sanely

For the Wi-Fi SDIO side:

1. Make net names explicit.
2. Assign a stable `SDIO` netclass.
3. Route the interface over a solid reference plane.
4. Avoid plane splits.
5. Keep return paths continuous.

These points are standard for SDIO-class interfaces and keep the routing discipline aligned with the rest of the board.

### What Must Change In The Rustyjack Project Specifically

At minimum:

1. Set a real footprint on `U_WIFI1`.
2. Add the footprint to the project library if needed.
3. Place the Wi-Fi module on `rustyjack-h616.kicad_pcb`.
4. Add vendor-correct keepout geometry to the PCB.
5. Verify the Wi-Fi SDIO nets exist on the board and are assigned to the intended netclass.

### What Correct Looks Like

The Wi-Fi item is complete only when all of the following are true:

- `U_WIFI1` has a footprint traced to the AW859A spec
- that footprint exists in the project or referenced library
- the footprint is instantiated on the PCB
- antenna keepout geometry is drawn on the board
- the keepout dimensions match the spec
- no copper, vias, traces, or components violate that keepout
- the SDIO interface is routed over a continuous reference plane

## Issue 3: The eMMC Storage Design Is Imported Placeholder Material, Not A Finished Rustyjack Storage Design

### Problem

The storage sheet is still visibly derived from a separate "Voltlog eMMC to microSD Adapter" design. It contains `Voltlog` naming and `emmc-adapter` rescue library references.

That is a warning sign, not because re-use is inherently bad, but because it strongly suggests the sheet was imported as reference material and not yet fully reworked into a production Rustyjack design.

The actual board also does not show a placed eMMC footprint matching that sheet.

### Why This Must Change

eMMC is not a low-risk interface. TI's eMMC guidance is explicit about:

- solid ground reference planes
- no plane cuts in the routing region
- short stubs
- impedance control
- extra spacing for clock and strobe nets
- local bypassing near the device and SoC

An imported sheet with unresolved third-party naming is not enough. Either eMMC is a real Rustyjack subsystem or it is not.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/sheets/storage_emmc.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`
- any library files used for the eMMC package

### Exactly What Must Change

#### Option 1: Rustyjack Will Support eMMC On This Board

If eMMC is truly required:

1. Replace residual third-party naming with Rustyjack-owned naming.
2. Confirm the exact eMMC part number that will be used in production.
3. Confirm its voltage rails, decoupling, boot strap implications, and package geometry from the vendor datasheet.
4. Verify the symbol pinout against the chosen part.
5. Verify the footprint against the chosen package.
6. Place the eMMC device on the board.
7. Route all eMMC signals adjacent to a solid ground plane.
8. Do not allow any reference plane cuts below the eMMC routing region.
9. Keep the clock and strobe nets isolated from aggressors.
10. Place required bypass capacitors as close as practical to the relevant power pins.

#### Option 2: Rustyjack Will Not Support eMMC On This Board

If eMMC is not part of this hardware revision:

1. Remove the storage sheet from the production schematic.
2. Remove unused `EMMC` netclass patterns and skew rules from the production project.
3. Update documentation to state that storage is microSD-only on this board revision.

### Why The Netclass Cleanup Matters

Unused constraint classes create a false sense of rigor. A project is not "better" because it has more rule names. A project is better when the rules correspond to real routed nets and are actually being enforced.

### What Correct Looks Like

The storage issue is complete only when one of these is true:

- the eMMC device is fully integrated in schematic and PCB with verified routing and power delivery, or
- the production design no longer claims to implement eMMC

There must be no remaining ambiguous "maybe later" eMMC production sheet in the root board project.

## Issue 4: The Netclass Assignment Strategy Is Brittle And At Least Partially Incorrect

### Problem

The project has the right idea: it defines netclasses for `DDR3_ADDR`, `DDR3_DATA_LB`, `DDR3_DATA_HB`, `DDR3_DIFF`, `EMMC`, `SDIO`, `RMII`, and `USB`, plus custom skew rules.

The problem is that at least one pattern is malformed and another does not match the actual board net names. On top of that, KiCad netclass assignment is order-sensitive: if multiple patterns match, the first match wins, and net names include the full sheet path. A broad early pattern can silently capture critical nets before a later explicit rule gets a chance.

Examples from the current project:

- `DDR3_DATA_HB` uses `"/DRAM/DQ[1]|[0-9]"`
- `RMII` uses `"^(RMII_|ETH_|MDC$|MDIO$).*"`

Current board net names include:

- `/IO1/MDC`
- `/IO1/MDIO`

That means the project is at risk of having rules that exist in files but are not applied to the intended nets.
The `DDR3_DATA_HB` pattern is especially risky because the alternation can match far more than the intended byte-lane subset, while the `RMII` expression does not account for the full sheet-path names used on this board.

### Why This Must Change

KiCad netclasses are useful only if the nets are actually assigned to them. KiCad's documentation is explicit that nets can be assigned to classes using pattern-based assignments, and that the effective class depends on the ordering and priority of the matching patterns. If the pattern does not match the full sheet-path name, or if a broad pattern appears too early, the rule does not help.

For high-speed or timing-sensitive interfaces, silent misassignment is unacceptable.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pro`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_dru`
- relevant schematic files where net names should be made explicit

### Exactly What Must Change

#### Rule 1: Put Exact Critical-Net Patterns Before Broader Patterns

For critical nets, explicit is better than clever. Put exact matches for `/IO1/MDC` and `/IO1/MDIO` ahead of any broader `RMII_*` or `ETH_*` patterns.

#### Rule 2: Use Stable, Intentional Net Names

Do not rely on auto-generated sheet-path naming for constrained interfaces if you can avoid it.

Instead, rename critical interfaces with stable, obvious labels. Recommended naming approach:

- Ethernet MAC management:
  - `ETH_MDC`
  - `ETH_MDIO`
- RMII data/control:
  - `RMII_TXD0`
  - `RMII_TXD1`
  - `RMII_RXD0`
  - `RMII_RXD1`
  - `RMII_TX_EN`
  - `RMII_CRS_DV`
  - `RMII_REF_CLK`
- eMMC:
  - `EMMC_CLK`
  - `EMMC_CMD`
  - `EMMC_DS`
  - `EMMC_DAT0` through `EMMC_DAT7`
- Wi-Fi SDIO:
  - `WIFI_SDIO_CLK`
  - `WIFI_SDIO_CMD`
  - `WIFI_SDIO_D0` through `WIFI_SDIO_D3`

This makes pattern assignment trivial and robust.

#### Rule 3: Replace Ambiguous Patterns With Explicit Ones

Recommended immediate fix for DDR high-byte matching:

- remove `"/DRAM/DQ[1]|[0-9]"`
- replace it with explicit entries:
  - `/DRAM/DQ8`
  - `/DRAM/DQ9`
  - `/DRAM/DQ10`
  - `/DRAM/DQ11`
  - `/DRAM/DQ12`
  - `/DRAM/DQ13`
  - `/DRAM/DQ14`
  - `/DRAM/DQ15`

Recommended immediate fix for RMII/MDIO/MDC matching if the old names are temporarily retained:

- add exact patterns for:
  - `/IO1/MDC`
  - `/IO1/MDIO`
- if you keep regex-based fallback rules, anchor them to the full sheet-path name, not just the short net label

Preferred long-term fix:

- rename nets to the stable names above
- then assign by simple prefix patterns such as:
  - `RMII_*`
  - `ETH_*`
  - `EMMC_*`
  - `WIFI_SDIO_*`

### How To Implement This Correctly In KiCad

1. Open the project in KiCad.
2. Update net labels in the schematic where needed.
3. Open schematic or board netclass setup.
4. Replace fragile patterns with explicit or prefix-based patterns.
5. Update the PCB from schematic.
6. Open the net inspector.
7. Verify every critical net is in the intended netclass.
8. Run DRC.

Do not treat the text file diff as proof. The proof is the **net inspector showing the right class on the right nets**.

### What Correct Looks Like

This issue is complete only when:

- every constrained interface net has an intentionally chosen name
- every constrained interface net appears in the correct KiCad netclass
- every custom skew rule refers to netclasses that actually have member nets
- DRC runs without netclass assignment surprises

## Issue 5: Ethernet Is Schematic-Only Today And Must Be Implemented To The Vendor Guidance If It Is Kept

### Problem

The Ethernet sheet is much more complete than the Wi-Fi sheet. It includes a LAN8720A PHY and an RJ45 footprint in the schematic. But that does not matter if the actual PCB does not contain the placed and routed Ethernet subsystem.

### Why This Must Change

The Ethernet sources are explicit enough that this subsystem should not be guessed at:

- Microchip's LAN8720A checklist defines the analog-side terminations, decoupling, and RJ45 treatment.
- TI's PHY layout guidance defines the physical routing practices for differential pairs and RMII/MII.

If Ethernet is going to remain in the production Rustyjack board design, the PCB must follow that guidance, not just the schematic.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/sheets/ethernet_lan8720.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pro`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_dru`

### Exactly What Must Change

#### Step 1: Schematic Must Match The Checklist Exactly

Audit the Ethernet schematic against the official LAN8720A checklist and confirm all of the following:

1. PHY twisted-pair side terminations use the specified 49.9 ohm, 1% pull-ups to VDDA where required.
2. Any optional EMC capacitors called out by the checklist are present as DNP placeholders if that flexibility is desired.
3. Analog supply pins are fed the way the checklist requires, including ferrite bead isolation and local bulk/high-frequency decoupling.
4. RJ45 unused pairs and Bob Smith termination are implemented correctly if the chosen connector/magnetics arrangement requires them.
5. RJ45 shield treatment matches the chosen grounding strategy and certification plan.

#### Step 2: The PHY Must Be Placed For The Routing, Not For Aesthetics

When placing the Ethernet section on the PCB:

1. Place the PHY so MDI traces to the magnetics/RJ45 are short and direct.
2. Place the 49.9 ohm resistors and local decoupling close to the PHY pins, not somewhere merely convenient.
3. Keep the MDI pairs short, parallel, and matched.
4. Avoid stubs.
5. Minimize vias.
6. Do not cross plane splits.
7. Route over a continuous reference plane.

TI's layout guidance explicitly calls for all of those behaviors.

#### Step 3: Implement The Ground Strategy Deliberately

Around the RJ45 and magnetics:

1. Decide whether chassis ground is present as a distinct concept on this board.
2. If yes, implement the chassis/system ground handling exactly and document it.
3. If no metal chassis exists, define how the shield and Bob Smith network are being terminated in a way that still matches the intended EMI behavior.

This cannot be left hand-wavy. Connector shield handling is one of the fastest ways to create a noisy or certification-hostile Ethernet design.

#### Step 4: Implement RMII Constraints Only On The Nets That Actually Exist

Once the PHY is real on the board:

1. ensure the RMII nets have stable names
2. assign them to the `RMII` netclass
3. verify the skew rule applies to real members
4. keep traces short
5. add any required series terminations per the chosen MAC/PHY interface design

### What Correct Looks Like

The Ethernet issue is complete only when:

- the LAN8720A and RJ45/magnetics are physically on the board
- MDI routing follows the vendor guidance
- RMII signals have deterministic netclass assignment
- the shield/chassis/Bob Smith strategy is explicit and implemented, not implied
- ERC and DRC pass on the actual instantiated Ethernet hardware

## Issue 6: USB Is In Better Shape Than The Other External Interfaces, But It Still Needs Verification Discipline

### Problem

The USB-UART section is the strongest implemented external interface in the current project. It includes:

- USB-C receptacles
- 5.1k CC resistors
- USB ESD protection
- a CP2102N UART bridge

That is good, but "looks reasonable" is not the same as "verified."

### Why This Matters

Silicon Labs' CP2102N documentation shows the device is a USB 2.0 full-speed bridge with an integrated transceiver, oscillator, regulator, and UART. That means the board-level review should focus on the physical USB path, connector protection, and footprint correctness rather than on any exotic device-side requirements.

Microchip's USB layout guidance calls for:

- proper differential impedance
- matched D+ and D- routing
- minimal vias
- continuous reference plane behavior
- attention to the differential pair as a real signal path, not just two adjacent traces

Because this is a full-speed bridge, the review should not overfit to high-speed USB rules. The current project should preserve the good USB design decisions it already has and then verify the layout discipline around them.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/usb_uart.kicad_sch`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pcb`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pro`

### Exactly What Must Change

1. Verify the USB differential pair nets are assigned to the `USB` netclass.
2. Verify the selected CP2102N footprint variant matches the symbol and board footprint exactly.
3. Verify the pair stays over a continuous reference plane.
4. Verify vias are minimized.
5. Verify the ESD device is physically placed close to the connector entry point.

### What Correct Looks Like

The USB item is complete when:

- the existing good schematic decisions remain intact
- the CP2102N footprint/pinout is verified
- the pair assignment is verified in KiCad
- the physical routing is checked against the official USB layout guidance
- no regression is introduced while adding the other subsystems

## Issue 7: Constraint Files Must Be Treated As Design Inputs, Not Decorative Metadata

### Problem

The project contains useful constraints in:

- `rustyjack-h616.kicad_pro`
- `rustyjack-h616.kicad_dru`

This is good. The problem is that the project is not yet in a state where those constraints can be trusted as complete and correctly applied across all claimed subsystems. In KiCad, class priority and pattern ordering matter, so constraint definitions are part of the design, not decoration.

### Why This Must Change

Constraints are part of the design. If a project claims to have skew budgets for DDR, eMMC, SDIO, and RMII, then the following must also be true:

- the nets exist
- the nets are classed correctly
- the board routes those nets
- the class ordering is verified in KiCad
- DRC checks those constraints against the real design

Otherwise the rule file is only decorative.

### Where To Implement The Fix

Files affected:

- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_pro`
- `pcb/actual pcb design/rustyjack-h616/rustyjack-h616.kicad_dru`

### Exactly What Must Change

1. Remove constraint classes that are only placeholders for hardware not in the production board.
2. Keep only classes that correspond to real routed interfaces, or clearly documented near-term hardware intentionally retained in the production project.
3. For each remaining class, verify:
   - member nets exist
   - those nets are routed
   - the class ordering and match priority are correct in KiCad
   - the skew budget is justified
4. For each added subsystem, re-check whether the skew budget is realistic for the chosen topology and layer transitions.

### What Correct Looks Like

The constraint issue is complete when:

- every netclass corresponds to real interface intent
- every pattern is in the correct order
- every custom rule has real targets
- there are no orphaned "future maybe" classes pretending to protect absent hardware

## Required Signoff Procedure Before Any PCB Revision Is Called Correct

This section is mandatory. It defines the minimum signoff evidence.

### Step 1: Schematic Truthfulness Check

Confirm that every sheet in the root schematic is either:

- implemented on the PCB, or
- intentionally excluded from the production design

### Step 2: Footprint Completeness Check

Confirm every `on_board yes` production symbol has:

- a real footprint
- a valid library reference
- a matching pad/pin map

### Step 3: Net Naming Check

Confirm all constrained interfaces use stable names that support unambiguous netclass assignment.

### Step 4: Netclass Membership Check

In KiCad net inspector, confirm every critical net is assigned to the intended class.

This must be done for:

- DDR
- USB
- Ethernet RMII/management if Ethernet remains
- eMMC if eMMC remains
- Wi-Fi SDIO if Wi-Fi remains

### Step 5: Netclass Order And Priority Check

Confirm the pattern ordering and class priority in KiCad match the intended hierarchy, especially for any broad `RMII_*`, `ETH_*`, or DDR patterns. Exact matches must win before broad fallbacks.

### Step 6: ERC And DRC Check

Run ERC and DRC after each major subsystem integration, not just at the end.

### Step 7: Layout Sanity Check Against Vendor Guidance

For every high-speed or RF subsystem, perform a visual review against the cited vendor guidance:

- no plane-split crossings
- no unnecessary vias
- no long stubs
- decoupling placed correctly
- antenna and shield regions respected

### Step 8: Commit Evidence

A PCB revision should not be merged without all relevant generated project files updated together:

- schematic files
- PCB file
- project file
- design rule file
- footprint or symbol library updates if applicable

## Execution Order

This is the recommended order for the actual remediation work.

1. Decide product truth:
   - Is this board a bring-up board, or the full Rustyjack hardware?
2. Remove or retain `STORAGE`, `WIFI`, and `ETHERNET` based on that decision.
3. Repair net naming and netclass assignment strategy.
4. Fix Wi-Fi footprint and keepout against the AW859A spec.
5. Fix or remove eMMC.
6. Implement or remove Ethernet.
7. Re-run full netclass verification and DRC/ERC.
8. Update the repo documentation so hardware claims match the KiCad project.

## Definition Of Done

This document is considered satisfied only when all of the following are true:

- the production schematic matches the production PCB
- every production symbol has a real footprint
- every constrained interface uses intentional naming
- every critical net is in the expected netclass
- netclass ordering has been validated in KiCad
- absent subsystems are removed or explicitly non-production
- Ethernet, Wi-Fi, and eMMC are either properly implemented or honestly excluded
- high-speed and RF layout decisions are backed by vendor guidance or public vendor-authored specs, not guesswork
- ERC and DRC have been reviewed on the real board design
- every electrical claim in the plan is traceable to official vendor documentation, a public vendor-authored mirror, or direct repo evidence

## Practical Summary

The most important correction is not a single resistor, trace, or keepout. It is the correction of the **design truth model**:

- the schematic must reflect the real board
- the board must reflect the intended product
- the constraints must reflect the real nets

Once that is fixed, the individual Ethernet, Wi-Fi, eMMC, and USB improvements become straightforward and auditable.
