# Detailed work analysis for the H616 Watchdog PCB architecture subsection on compute-core integration

## Executive summary

Section three of the KeyCAD/KiCad architecture document is explicitly a **subsystem-level “table of contents”** for what must be designed, captured in KiCad, laid out, validated, and handed off to a factory to get a first-spin board built. It is **implementation-free by intent**, and instead mandates a set of **follow-on low-level reference documents** (one per subsystem) that turn requirements into KiCad actions and manufacturable artefacts. fileciteturn1file0

The first subsystem in that section, **compute core: Allwinner H616 integration**, is the **foundation block** for everything else. The architecture document defines its minimum requirements as: (a) **perfect symbol↔footprint↔ball-map correctness**, (b) a working **24 MHz reference clock** with proper decoupling, and (c) **reset + boot straps (including FEL) accessible** via pads/headers/jumpers; and it requires an **always-accessible UART0 console** plus reset access and strap access specifically to make bring-up possible. fileciteturn1file0

This report turns that architectural intent into a **very low-level, KiCad‑v9.0.4‑targeted work package**: what to take from Orange Pi Zero2 (H616) as proven reference patterns, what to adapt for the Watchdog constraints (notably DDR3, 8 GB eMMC, microSD recovery, USB‑C 5 V sink, 2× USB‑A, 10/100 RMII Ethernet, external USB Wi‑Fi dongle, SPI TFT + 8 buttons), what the **inputs/outputs** are, where those outputs must land inside the repo structure in the ZIP, and how the resulting artefacts “plug into” the rest of section three’s subsystem plan. fileciteturn1file0turn1file8turn1file13

## What section three demands for the board to exist

### Subsystems and the “deliverables model” implied by section three

Section three enumerates the subsystems that must be defined and then expanded into implementation docs. Each subsection includes: purpose, top-level requirements, reference designs to clone, bring-up/debug affordances, and a **named low-level reference doc** that must be written next. fileciteturn1file0

The list below is not an additional interpretation; it is simply a “materialisation view” of what section three already commits you to building and delivering.

| Subsystem | What must exist for the PCB to be materialised | Architecture-required low-level doc |
|---|---|---|
| Compute core integration | H616 symbol+footprint+ball map correctness; 24 MHz clock; reset and boot straps accessible; UART0 header | `REF_SOC_H616.md` fileciteturn1file0 |
| DRAM | 512 MB DDR3/DDR3L topology choice; rail plan; routing constraints; debug testpoints | `REF_DDR3_DDR3L.md` fileciteturn1file0 |
| eMMC | SMHC2 wiring; bus width choice; short/stable routing; optional disable strap | `REF_EMMC.md` fileciteturn1file0 |
| microSD recovery | SMHC0 wiring; boot/recovery flow defined; socket placement | `REF_MICROSD_RECOVERY.md` fileciteturn1file0 |
| Ethernet 10/100 | EMAC0→RMII PHY→MagJack; EMI/ESD discipline; PHY reset/straps observable | `REF_ETHERNET_RMII.md` fileciteturn1file0 |
| USB (2× host) | 2× USB‑A; per-port ESD; controlled VBUS power; topology decision (direct vs hub) | `REF_USB_HOST.md` fileciteturn1file0 |
| Wi‑Fi | (Architecture doc allows integrated Wi‑Fi via SDIO module) but must reconcile with Scenario‑2 Watchdog scope | `REF_WIFI_SDIO.md` fileciteturn1file0 |
| UI | SPI TFT signals + DC/RST/BL; 8 GPIO buttons; software mapping contract | `REF_UI_SPI_GPIO.md` fileciteturn1file0turn1file4 |
| Debug/instrumentation | UART0 header; strap pads; rail testpoints; isolation 0Ω links | `REF_DEBUG_BRINGUP.md` fileciteturn1file0 |
| Manufacturing/DFM | “Scenario 2” build split (factory SMT/BGA vs hand-soldered connectors); stack-up choice; DNP strategy | `REF_DFM_ASSEMBLY.md` fileciteturn1file0turn1file8 |

### Critical scope reconciliation: integrated Wi‑Fi versus “external dongle only”

The architecture doc’s locked-specs section includes *basic integrated Wi‑Fi* and also 2× USB‑A “so a user can plug in an external dongle.” fileciteturn1file0  
However, the Scenario‑2 Watchdog breakdown (the current source-of-truth constraints for fabrication intent and risk reduction) explicitly chooses **a single “basic” Wi‑Fi interface via an external USB Wi‑Fi dongle** to keep on-board RF out of scope. fileciteturn1file8  
Your Orange Pi reference mapping doc already treats this divergence explicitly: for first spin, **treat the Scenario‑2 USB-dongle approach as controlling** unless you intentionally accept the RF scope expansion. fileciteturn1file13

This matters to subsection 3.1 because **pinmux planning for the compute core** must not “spend” SDIO-capable pins on an on-board Wi‑Fi module if your first-spin spec is dongle-only; instead, preserve those lanes for future expansion or ignore them entirely in rev‑A to reduce risk. fileciteturn1file0turn1file8turn1file13

## Compute core integration work package for KiCad v9.0.4

### What subsection 3.1 requires, precisely

Subsection 3.1 states, in plain terms:

- Your H616 **package/library mapping must be perfect** (symbol ↔ footprint ↔ ball map).  
- You must provide a **24 MHz reference clock** and required decoupling.  
- You must make **reset and boot strap signals accessible** (pads/header/jumpers).  
- For bring-up: an always-accessible **UART0 console** (3.3 V TTL), a reset button/pads, and **FEL/boot strap access** for recovery paths.  
- You must produce a follow-on low-level doc called `REF_SOC_H616.md` containing a pinmux plan, clocks, reset strategy, boot strap truth table, JTAG decision, and KiCad net naming conventions. fileciteturn1file0

Everything below is the detailed “how we actually do that in KiCad 9.0.4 and in this repo”.

### Inputs you must use to implement 3.1 correctly

The inputs are the documents and artefacts you must have in-hand before you start drawing the H616 sheet in KiCad (otherwise you end up redrawing and reassigning pins mid‑layout, which is where first spins go to die).

| Input | Why it is required | Where it comes from in this project |
|---|---|---|
| Section‑3/3.1 requirements | Defines minimum compute-core “definition of done” | Architecture doc fileciteturn1file0 |
| Watchdog Scenario‑2 constraints | Defines what peripherals must exist and what to avoid in rev‑A (e.g., no on-board RF) | Breakdown v2 fileciteturn1file8 |
| Orange Pi Zero2 H616 schematic pack v1.3 | Provides proven H616 integration patterns (SoC sheet, straps, UART, pin groupings), but must be treated carefully where it is inconsistent | Orange Pi schematic PDF fileciteturn1file11 |
| Orange Pi reference extraction + mapping docs | Identifies known schematic inconsistencies (DDR4 label vs DDR3 reality; Wi‑Fi naming drift) and gives a “clone vs change” mental model | Reference extraction + mapping fileciteturn1file12turn1file13 |
| H616-in-KiCad integration deep dive | Captures key pitfalls to avoid: ball-map correctness, constraint encoding, and “KiCad length tuner stops at branches” behaviour that affects how you draw nets | SoC integration doc fileciteturn1file2 |
| UI contract expectations | Ensures pinmux exposes SPI TFT + DC/RST/BL + 8 button inputs (numbers may change via DT, but signals must exist) | BOM/fab breakdown fileciteturn1file4 |

### Outputs that implementing 3.1 must produce

Subsection 3.1 implicitly creates both **documentation outputs** and **KiCad artefact outputs**. If you do not create both, you will fail either internal review (lack of clarity) or manufacturing (no usable CAD), or bring-up (no access to straps/UART).

| Output | What it contains | Where it must go in the repo |
|---|---|---|
| `REF_SOC_H616.md` | The “pin-perfect” truth source: pinmux plan, clock/reset design, boot-strap truth table, JTAG decision, net naming conventions, and bring-up access plan | `watchdog/pcb/refs/REF_SOC_H616.md` (recommended location); architecture doc mandates the name fileciteturn1file0 |
| Project-local H616 symbol library | Multi-unit symbol split by subsystem (power/DDR/eMMC/IO groups) to keep schematics readable; includes correct pin functions and electrical types | `watchdog/pcb/kicad/library/symbols/…` (align with KiCad project conventions in your KiCad v9.0.4 guide) fileciteturn1file14 |
| Project-local H616 footprint | Correct BGA pad geometry, pitch, courtyard; includes pin‑1/orientation marker consistent with datasheet | `watchdog/pcb/kicad/library/footprints/…` fileciteturn1file14turn1file0 |
| “Compute core” schematic sheet | H616 core interconnects: clocks, reset, straps access, UART0 header; exports hierarchical pins/buses to other subsystem sheets | `watchdog/pcb/kicad/sheets/20_soc_h616_core.kicad_sch` (recommended naming aligned to your v9.0.4 plan) fileciteturn1file14 |
| Pinmux allocation table | A human- and machine-readable spreadsheet/markdown table mapping each H616 function to nets and external parts | `watchdog/pcb/doc/pinmux.md` or embedded inside `REF_SOC_H616.md` fileciteturn1file0 |
| Bring-up access artefacts | UART header footprint; labelled test pads; strap jumpers/0Ω links; reset button pads | In schematic + PCB; required by architecture doc and debug philosophy fileciteturn1file0turn1file8 |

### The detailed work to do for 3.1

#### Create (and verify) the H616 symbol↔footprint↔ball-map chain

This is the single most “binary” requirement in the whole project: either it’s correct and the board can boot, or it’s wrong and you own an expensive coaster.

What to do, concretely:

Establish a single authoritative ball-map source for your design and enforce it.
- The architecture doc requires perfect symbol/footprint/ball mapping. fileciteturn1file0  
- The H616 integration deep dive explicitly flags **symbol/footprint correctness for BGA pin mapping as a top KiCad-specific pitfall**; treat that as a hard gate before any layout work starts. fileciteturn1file2

Implement the H616 symbol as a multi-unit device.
- Use a multi-unit split that matches how you will route and review the board: dedicated units for DDR, eMMC/SD, Ethernet MAC, USB, GPIO banks, and power/grounds. This keeps the schematic readable and makes pinmux review possible without “Where’s Waldo” scanning. This approach aligns with the “instrumented bring-up board” philosophy: clarity beats cleverness in rev‑A. fileciteturn1file0turn1file14

Cross-check your pin functional groups against the Orange Pi SoC sheet and assignment tables.
- Orange Pi’s schematic pack includes both a “GPIO assignment” overview and the SOC1 page showing PC/PF/PG mapping for key muxed functions. For example, it explicitly shows **the NAND/eMMC mux group on PC pins, including SDC2 signals** (used for eMMC in your architecture), and SD card muxing on PF pins. fileciteturn1file11

![Orange Pi Zero2: GPIO assignment page highlighting SD, SDIO, and NAND/eMMC mux groups](sandbox:/mnt/data/user-SUTpJAuJBTIbdk1CotO8q8Xq__c1df8433-8eab-4a22-8cd8-05f35cac6ac1/667400b63b85494e9ce5f13de54d580a/mnt/data/opi_gpio_assignment_p04.png) fileciteturn1file11

Guardrails to encode in KiCad 9.0.4:
- Put the symbol, footprint, and any ball-map CSV/text into the project repo and treat them as versioned artefacts. Your own KiCad v9.0.4 guide stresses that constraints and correctness must be encoded in-project (not tribal knowledge), and it assumes project-local libraries for high-risk parts. fileciteturn1file14

#### Implement the 24 MHz clock block as a “known-good pattern”

The architecture doc requires a 24 MHz reference clock (typically a crystal + load caps, or an oscillator) and the associated decoupling. fileciteturn1file0  
Orange Pi’s block diagram explicitly calls out a **24 MHz DCXO** feeding the H616, showing that a 24 MHz reference is not optional and is treated as a first-class integration element. fileciteturn1file11

Your work items:
- Choose crystal vs oscillator deliberately:
  - Crystal is cheaper but more layout-sensitive and relies on correct loading.
  - Oscillator is more tolerant but costs more and adds a digital clock source near sensitive analogue regions.
- Encode a strict local placement rule in KiCad (rule area) for “clock island”:
  - Keep the crystal/oscillator as close as physically possible to H616 clock pins.
  - Keep a solid reference ground and avoid high di/dt switching regulators under/near this loop.
- Add measurement affordances:
  - Add a small test pad (or probe-able series resistor footprint) so you can verify the clock is oscillating during bring-up without micro-soldering onto BGA pins.

Why this belongs in 3.1 and not “power”:
- Without the clock, you cannot meaningfully debug boot flow; this is compute-core bring-up essential. fileciteturn1file0

#### Design reset behaviour for “debuggability”, not minimal BOM

Subsection 3.1 explicitly demands reset access: a reset button (or pads) plus a clean reset supervisor strategy. fileciteturn1file0

Practical implementation plan:
- Include a manual reset button footprint (even if unpopulated in some assembly variants).
- Provide a reset net test pad.
- Decide whether to include a dedicated reset supervisor IC:
  - If you include it, make it defeatable (0Ω link / strap) so that early bring-up isn’t blocked by a misconfigured supervisor.

This is consistent with the broader “instrumented bring-up board” philosophy: include debug affordances now; delete later. fileciteturn1file0turn1file8

#### Make boot straps and FEL accessible, with a strap strategy that actually works

The architecture doc requires “reset and boot strap signals accessible”, explicitly mentioning **FEL** and “boot straps” access pads/jumpers to force recovery paths. fileciteturn1file0

What to take from Orange Pi (and how to interpret it safely):
- Orange Pi’s SOC1 page includes boot-select muxing on PC pins (e.g., PC3–PC6 include `BOOT_SEL1..4` in the pin function strings shown). fileciteturn1file11  
- Orange Pi also shows a dedicated “RECOVERY” signal in its GPIO assignment block, reinforcing that recovery behaviour is treated as a board-level concern, not “we’ll figure it out in software”. fileciteturn1file11

Low-level strap access plan for Watchdog:
- Provide a compact “strap pad field” with clearly labelled pads for:
  - `FEL`
  - boot-select pins used in your boot strategy
  - `RESET`
- Implement default straps so the board boots “normally” (typically eMMC first spin), but allow you to override to recovery paths without rework.
- Use a strap-resistor approach consistent with SoC internal pull strengths:
  - Your H616 integration deep-dive warns that internal pull resistors vary by port and that overly weak external straps may not override internal pulls reliably; this is a classic “it boots on some boards, not others” pitfall if you treat straps casually. fileciteturn1file2

How this ties into the Watchdog constraints:
- Your recovery strategy is explicitly **microSD recovery/provisioning** plus soldered eMMC primary. Subsection 3.4 mandates microSD for recovery, and the Scenario‑2 breakdown repeats microSD recovery as a non-negotiable. That means strap strategy must support “I can always get to a known-good SD boot” without desoldering storage. fileciteturn1file0turn1file8

#### Guarantee “UART0 always works” regardless of what else is broken

The architecture doc’s compute-core bring-up affordance list begins with: “Always-accessible UART0 console header (3.3 V TTL level).” fileciteturn1file0

Concrete design requirements:
- UART0 header must be physically accessible even when the board is in its prototype enclosure (or, at minimum, when all hand-soldered connectors are installed). This is in the spirit of the microSD placement requirement in 3.4 (physical access matters for recovery). fileciteturn1file0  
- Provide at least a 3-pin header (TX/RX/GND); a 4-pin with +3V3 reference is often helpful but ensure you don’t encourage powering the board through the UART header.
- Avoid pinmux collisions:
  - Do not place the debug UART on pins you need for boot-critical storage unless you are confident the pinmux default state won’t interfere.
  - Orange Pi’s schematic separates “UART0 debug” as a first-class block in the block diagram, emphasising it is always present alongside TF card and other peripherals. fileciteturn1file11

This is also the practical answer to “how have other people done this before?”: shipping H616 boards treat UART debug as non-optional for bring-up. fileciteturn1file0turn1file11

#### Produce the pinmux plan that makes the rest of section three possible

`REF_SOC_H616.md` is required to include a pinmux plan. fileciteturn1file0  
You cannot treat pinmux as an afterthought because it is the dependency edge for every other subsystem sheet in section three (DDR, eMMC, microSD, Ethernet, USB, UI, debug). fileciteturn1file0turn1file8

A practical pinmux planning approach (aligned to your constraints and Orange Pi’s proven grouping):
- Reserve SMHC2/SDC2-capable pins for **8-bit eMMC** (matches section 3.3, which recommends SMHC2 for eMMC). fileciteturn1file0turn1file11  
- Reserve SMHC0/SDC0 pins for **microSD recovery** (section 3.4 recommends SMHC0). fileciteturn1file0turn1file11  
- Allocate EMAC0 pins for RMII (section 3.5 requires EMAC0 → RMII PHY → MagJack). fileciteturn1file0turn1file2  
- Allocate USB host resources for either:
  - direct dual-host routing, or
  - one host to a hub that fans out to 2× USB‑A (section 3.6 calls out both options). fileciteturn1file0turn1file8  
- Allocate one SPI controller for TFT, plus three control GPIOs (DC/RST/BL) and eight GPIO inputs for buttons (section 3.8), explicitly remembering your current software contract expects those signals to exist even if line numbering changes. fileciteturn1file0turn1file4  
- If following Scenario‑2 Watchdog constraints (external Wi‑Fi dongle only), do not allocate SDIO/SDC1 for Wi‑Fi in rev‑A; leave it unused or as “expansion pads” only if it doesn’t add routing risk. fileciteturn1file8turn1file13

This pinmux plan must be written in a way that other subsystems can consume directly:
- every function has:
  - chosen H616 pins/balls
  - net names (KiCad naming conventions)
  - voltage domain requirement (so pull-ups align with bank supply)

Orange Pi’s SOC1 page includes an explicit warning that **SoC GPIO voltage must match external IO voltage and pull-up voltage must correspond to the GPIO power domain**, which is exactly why your pinmux plan must include voltage-domain awareness. fileciteturn1file11

![Orange Pi Zero2: SOC1 page note about IO voltage matching external voltage domains](sandbox:/mnt/data/user-SUTpJAuJBTIbdk1CotO8q8Xq__c1df8433-8eab-4a22-8cd8-05f35cac6ac1/667400b63b85494e9ce5f13de54d580a/mnt/data/opi_p05_soc1.png) fileciteturn1file11

### How to implement all of the above in KiCad 9.0.4 specifically

Your KiCad v9.0.4 guide (already produced in this project) establishes the overall approach: hierarchical sheets, a reproducible file tree, project-local libs, and encoding constraints/rules in-project rather than in human memory. fileciteturn1file14

For subsection 3.1, the KiCad‑9‑specific recommendations are:

Use project-local libraries for H616 (symbol + footprint).
- This is a high-risk part; you cannot rely on global libraries or “someone’s local copy”. Your v9.0.4 guide directly recommends project-local libraries for non-standard/high-risk parts like the H616 BGA footprint. fileciteturn1file14

Use hierarchical sheets and expose only clean buses/ports to other sheets.
- Subsection 3.1 is the “SoC core sheet”; other subsystem sheets (DDR, eMMC, etc.) should connect via named hierarchical pins/buses so the SoC sheet remains stable as the top-level anchor. This matches the architecture doc’s “subsystem doc per sheet” relationship. fileciteturn1file0turn1file14

Encode strap/testpad intent as explicit schematic elements.
- Treat strap resistors, 0Ω links, and test pads as real parts with designators and DNP options; this forces them into the BOM and assembly plan and avoids “we planned for pads but forgot them” failures. This matches the “instrumented bring-up board” requirement. fileciteturn1file0turn1file8

Be disciplined about topology (even inside the SoC sheet).
- Your H616 integration deep dive highlights the KiCad pitfall that length tuning is point-to-point and stops at branches; while this is most painful for DDR/eMMC, it starts with how you structure nets and avoid stubs early. fileciteturn1file2turn1file14

## What to take from Orange Pi Zero2 for compute-core integration

Subsection 3.1 tells you to clone Orange Pi Zero2 pages for SoC + debug block, and to use your internal H616 integration doc. fileciteturn1file0turn1file11turn1file2  
Here is the practical, “do this, don’t do that” extraction for compute core.

### Proven patterns worth reusing directly

Boot-strap and recovery exposure as a board-level design feature.
- Orange Pi’s block level and GPIO assignment sheets clearly reflect boot/recovery and debug as first-class design responsibilities (not afterthought headers). fileciteturn1file11

Conservative pin grouping for storage and muxed interfaces.
- The Orange Pi GPIO assignment page provides a concrete “what lives where” for SDC0 (TF card), SDC1 (SDIO), and SDC2 (NAND/eMMC mux group) across PF/PG/PC pins. This is extremely useful as a reference when writing your `REF_SOC_H616.md` pinmux plan. fileciteturn1file11

Voltage-domain awareness of GPIO banks.
- Orange Pi explicitly notes that GPIO voltage must match external IO voltage and that pull-ups must align to the GPIO power domain; treat that as a “reference design warning label” for your own pinmux document and strap pull-up voltages. fileciteturn1file11

### Patterns to treat as “reference only” (do not blindly clone)

Never copy Orange Pi labels where the pack is internally inconsistent.
- Your project explicitly documents that the Orange Pi schematic pack contains misalignments (e.g., the sheet index says “DDR4 16×2”, but the actual memory implementation is DDR3), and you have already decided this project will use DDR3. Treat the actual wiring as truth, not the mislabeled headings. fileciteturn1file13turn1file11

Similarly, Wi‑Fi naming in the Orange Pi pack drifts (“AP6256” appears in labels while the actual schematic page uses different module naming). Even though Wi‑Fi is out of scope for Watchdog rev‑A (dongle only), this is still a cautionary example: trust the circuit, not the title. fileciteturn1file13turn1file8

### How Orange Pi reuse fits into the KeyCAD/KiCad project flow

The correct usage model is:

- Use Orange Pi to derive:
  - “which pin families are commonly used for which major functions”
  - restore confidence in exact strap/debug concepts
  - find “gotchas” like voltage domain and pull-up alignment
- But implement Watchdog with your own constraints:
  - **10/100 RMII** (not Orange Pi gigabit)
  - **external Wi‑Fi dongle** (not on-board SDIO Wi‑Fi)
  - **two USB‑A** plus VBUS power control
  - **DDR3** chosen intentionally, even if DDR3L is discussed elsewhere fileciteturn1file8turn1file13turn1file0

## Pitfalls others hit with this hardware class and how to prevent them

This section addresses your “have people tried before?” question in the most actionable way: “what are the failure modes seen in H616-class bring-up and how do we design them out.”

### The catastrophic pitfall: wrong ball-map or wrong footprint orientation

This is explicitly called out as a top KiCad-specific pitfall in your H616 integration deep dive: symbol/footprint correctness for BGA pin mapping is non-negotiable. fileciteturn1file2turn1file0  
Prevention:
- Treat ball-map verification as a gated checklist item in `REF_SOC_H616.md` and require a second-person review before layout begins.
- Cross-check ball/pin functions against Orange Pi’s SoC pages as an external sanity check (not as the primary authority). fileciteturn1file11turn1file0

### Straps that “work on the bench” but fail in production because internal pulls were ignored

Your H616 integration doc explicitly warns that internal pull resistor strengths vary by port and that too-weak external straps may fail to override those pulls. This is exactly the type of pitfall that produces intermittent boot behaviour and difficult-to-reproduce bring-up failures. fileciteturn1file2  
Prevention:
- Choose strap resistor values based on internal pull strength, not habit.
- Put FEL/strap pads where you can probe them and confirm their logic level at reset.

### Confusing the Ethernet MAC story and routing the wrong thing

Your H616 integration doc explicitly notes that H616 has two EMACs, and that EMAC0 is the external one for RMII/RGMII, while EMAC1 includes an embedded 100M EPHY with no external pins; therefore, a cabled RJ45 interface must use EMAC0 + an external PHY. fileciteturn1file2turn1file0  
Prevention:
- In `REF_SOC_H616.md`, include a diagram: “EMAC0 → RMII PHY → MagJack” as the only supported rev‑A wired Ethernet path, matching section 3.5. fileciteturn1file0turn1file8

### Copying Orange Pi’s schematic pack inconsistencies into your board

This is a real “other people did it” class of error because the easiest way to build a custom board is to clone a public schematic pack; when that pack contains inconsistencies, inexperienced cloners replicate the typo.

Two specific inconsistencies are already documented in your own repo:
- “DDR4” labelling while the actual design is DDR3. fileciteturn1file13turn1file11  
- Wi‑Fi naming drift between labels and the actual Wi‑Fi page. fileciteturn1file13turn1file11  

Prevention:
- Always anchor decisions to “what is wired” rather than “what is titled” in the reference pack.
- In `REF_SOC_H616.md`, add a one-paragraph “reference-pack inconsistencies” section so reviewers are primed not to rely on labels.

### Bring-up blocked by lack of physical access

The architecture doc repeatedly emphasises physical access as a design responsibility (UART0 console always accessible; microSD socket placeable for physical use; pads/jumpers for FEL/boot straps). fileciteturn1file0  
Prevention:
- Add “access review” to your PCB review checklist: can you reach UART, reset, strap pads, and microSD with the board assembled and the chunky connectors installed?

## How 3.1 outputs connect to the rest of the project

### Where the outputs need to go inside the ZIP layout

Your project ZIP already contains `watchdog/pcb/` and places the architecture docs there, with older design docs under `watchdog/pcb/old/`. The cleanest integration is:

- Keep architecture/spec docs in `watchdog/pcb/`.
- Create:
  - a new `watchdog/pcb/refs/` for the `REF_*.md` documents demanded by section 3/5, and
  - a `watchdog/pcb/kicad/` directory for the KiCad project itself (as recommended in your KiCad v9.0.4 guide). fileciteturn1file0turn1file14

### How 3.1 relates to every other subsystem in section three

A useful mental model is: **3.1 defines the “pins, clocks, and recovery affordances” contract** that all other sheets consume.

- DDR3 (3.2): cannot be defined until you lock SoC footprint orientation and DDR pin groups and decide the DDR3 topology; that starts in 3.1’s symbol correctness and pin group planning. fileciteturn1file0turn1file13  
- eMMC (3.3) + microSD (3.4): your architecture already targets SMHC2 for eMMC and SMHC0 for microSD; those are pinmux allocations that must be declared in `REF_SOC_H616.md` first or you will thrash later. fileciteturn1file0turn1file11  
- Ethernet/USB/UI: each depends on “which pins are left” and “which IO bank voltages they require”; Orange Pi’s SOC notes about IO voltage matching external IO voltage show why this must be called out early. fileciteturn1file11turn1file0  
- Debug/instrumentation (3.9) is not separate from 3.1 in practice: the UART0 header, reset access, and strap pads are part of core SoC integration; 3.9 simply expands them into a complete bring-up plan. fileciteturn1file0

### Definition of done for implementing subsection 3.1

You can treat the list below as the acceptance criteria for “compute core integration is done enough to move on”.

The following artefacts exist and are reviewable:
- `REF_SOC_H616.md` exists with pinmux plan, clock/reset strategy, strap truth table, JTAG decision, and KiCad net naming conventions. fileciteturn1file0  
- H616 symbol + footprint exist in project-local libraries, and a “ball-map correctness review” has been completed. fileciteturn1file0turn1file2turn1file14  
- The schematic has an SoC core sheet with:
  - 24 MHz clock block,
  - reset network + reset button/pads,
  - UART0 header (3.3 V TTL),
  - FEL/boot strap pads/jumpers. fileciteturn1file0  
- “Bring-up access” is physically possible:
  - UART header is accessible,
  - strap pads are probe-able,
  - microSD location won’t be blocked by other connectors in the intended prototype layout. fileciteturn1file0turn1file8  
- The sheet exports clean hierarchical ports/buses for the rest of the subsystem sheets (DDR/eMMC/SD/Ethernet/USB/UI). fileciteturn1file14

Once those are true, the rest of section three can be implemented without constantly revisiting SoC fundamentals—and the board has a credible path to being manufactured and brought up on the bench without heroic rework. fileciteturn1file0turn1file8